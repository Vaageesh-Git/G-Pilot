from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

import chromadb
from chromadb.api.models.Collection import Collection
from sentence_transformers import SentenceTransformer

from vuln_swarm.core.config import Settings
from vuln_swarm.rag.documents import COLLECTIONS, KnowledgeChunk, chunk_file, discover_knowledge_files
from vuln_swarm.schemas import RagCitation


class ChromaKnowledgeBase:
    def __init__(self, settings: Settings, *, base_dir: Path | None = None):
        self.settings = settings
        self.base_dir = base_dir or Path(__file__).resolve().parents[3]
        self.client = chromadb.PersistentClient(path=str(settings.chroma_dir))
        self._model: SentenceTransformer | None = None
        self._collections: dict[str, Collection] = {}

    @property
    def model(self) -> SentenceTransformer:
        if self._model is None:
            self._model = SentenceTransformer(self.settings.embedding_model)
        return self._model

    def collection(self, name: str) -> Collection:
        if name not in COLLECTIONS:
            raise ValueError(f"Unknown collection: {name}")
        if name not in self._collections:
            self._collections[name] = self.client.get_or_create_collection(
                name=name,
                metadata={"hnsw:space": "cosine"},
            )
        return self._collections[name]

    def ingest(self, *, force: bool = False) -> dict[str, int]:
        if force:
            for name in COLLECTIONS:
                try:
                    self.client.delete_collection(name)
                except Exception:
                    pass
                self._collections.pop(name, None)

        files = discover_knowledge_files(self.settings.knowledge_paths, self.base_dir)
        chunks: list[KnowledgeChunk] = []
        for file_path in files:
            chunks.extend(chunk_file(file_path))

        grouped: dict[str, list[KnowledgeChunk]] = defaultdict(list)
        for chunk in chunks:
            grouped[chunk.collection].append(chunk)

        counts: dict[str, int] = {}
        for name in COLLECTIONS:
            collection = self.collection(name)
            items = grouped.get(name, [])
            if not items:
                counts[name] = collection.count()
                continue
            existing = collection.get(ids=[item.id for item in items])
            existing_ids = set(existing.get("ids", []))
            new_items = [item for item in items if item.id not in existing_ids]
            if new_items:
                embeddings = self.embed([item.text for item in new_items])
                collection.add(
                    ids=[item.id for item in new_items],
                    documents=[item.text for item in new_items],
                    metadatas=[item.metadata for item in new_items],
                    embeddings=embeddings,
                )
            counts[name] = collection.count()
        return counts

    def retrieve(self, collection_name: str, query: str, *, top_k: int | None = None) -> list[RagCitation]:
        collection = self.collection(collection_name)
        if collection.count() == 0:
            return []
        query_embedding = self.embed([query])[0]
        result = collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k or self.settings.retrieval_top_k,
            include=["documents", "metadatas", "distances"],
        )
        return self._to_citations(collection_name, result)

    def retrieve_bundle(self, query: str, *, top_k: int | None = None) -> list[RagCitation]:
        citations: list[RagCitation] = []
        for name in COLLECTIONS:
            citations.extend(self.retrieve(name, query, top_k=top_k))
        return sorted(citations, key=lambda citation: citation.score if citation.score is not None else 1.0)

    def stats(self) -> dict[str, int]:
        return {name: self.collection(name).count() for name in COLLECTIONS}

    def embed(self, texts: list[str]) -> list[list[float]]:
        return self.model.encode(texts, normalize_embeddings=True).tolist()

    def _to_citations(self, collection_name: str, result: dict[str, Any]) -> list[RagCitation]:
        citations: list[RagCitation] = []
        ids = result.get("ids", [[]])[0]
        documents = result.get("documents", [[]])[0]
        metadatas = result.get("metadatas", [[]])[0]
        distances = result.get("distances", [[]])[0]
        for doc_id, document, metadata, distance in zip(ids, documents, metadatas, distances, strict=False):
            citations.append(
                RagCitation(
                    collection=collection_name,  # type: ignore[arg-type]
                    document_id=doc_id,
                    source=str((metadata or {}).get("source", "unknown")),
                    score=float(distance) if distance is not None else None,
                    excerpt=(document or "")[:1200],
                )
            )
        return citations
