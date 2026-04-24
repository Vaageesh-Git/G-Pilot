from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from pypdf import PdfReader


COLLECTION_VULNERABILITIES = "vulnerabilities"
COLLECTION_EXPLOITS = "exploits"
COLLECTION_FIXES = "fixes"
COLLECTIONS = (COLLECTION_VULNERABILITIES, COLLECTION_EXPLOITS, COLLECTION_FIXES)


@dataclass(frozen=True)
class KnowledgeChunk:
    id: str
    collection: str
    source: str
    page: int | None
    text: str
    metadata: dict[str, str | int | None]


def discover_knowledge_files(paths: list[Path], base_dir: Path) -> list[Path]:
    files: list[Path] = []
    for configured in paths:
        candidate = configured
        if not candidate.is_absolute():
            candidate = (base_dir / candidate).resolve()
        if candidate.is_dir():
            files.extend(sorted(candidate.glob("*.pdf")))
            files.extend(sorted(candidate.glob("*.md")))
            files.extend(sorted(candidate.glob("*.txt")))
        elif candidate.exists():
            files.append(candidate)
    seen: set[Path] = set()
    unique: list[Path] = []
    for file_path in files:
        resolved = file_path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(resolved)
    return unique


def load_file_text(path: Path) -> list[tuple[int | None, str]]:
    if path.suffix.lower() == ".pdf":
        reader = PdfReader(str(path))
        pages: list[tuple[int | None, str]] = []
        for index, page in enumerate(reader.pages, start=1):
            pages.append((index, page.extract_text() or ""))
        return pages
    return [(None, path.read_text(encoding="utf-8", errors="ignore"))]


def chunk_file(path: Path, *, max_chars: int = 1800, overlap: int = 220) -> list[KnowledgeChunk]:
    pages = load_file_text(path)
    chunks: list[KnowledgeChunk] = []
    for page_number, text in pages:
        normalized = normalize_text(text)
        for index, chunk in enumerate(split_text(normalized, max_chars=max_chars, overlap=overlap)):
            collection = classify_chunk(path.name, chunk)
            digest = hashlib.sha256(f"{path}:{page_number}:{index}:{chunk}".encode()).hexdigest()[:24]
            chunks.append(
                KnowledgeChunk(
                    id=f"{collection}:{digest}",
                    collection=collection,
                    source=path.name,
                    page=page_number,
                    text=chunk,
                    metadata={
                        "source": path.name,
                        "page": page_number or 0,
                        "collection": collection,
                        "chunk_index": index,
                    },
                )
            )
    return chunks


def normalize_text(text: str) -> str:
    text = text.replace("\x00", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def split_text(text: str, *, max_chars: int, overlap: int) -> list[str]:
    if not text:
        return []
    sections = re.split(r"(?=\n?(?:Category|Part|Agent Query|[A-Z]\.\d|[0-9]\.\d)\b)", text)
    chunks: list[str] = []
    current = ""
    for section in sections:
        section = section.strip()
        if not section:
            continue
        if len(current) + len(section) + 2 <= max_chars:
            current = f"{current}\n\n{section}".strip()
            continue
        if current:
            chunks.extend(split_large_block(current, max_chars=max_chars, overlap=overlap))
        current = section
    if current:
        chunks.extend(split_large_block(current, max_chars=max_chars, overlap=overlap))
    return chunks


def split_large_block(text: str, *, max_chars: int, overlap: int) -> list[str]:
    if len(text) <= max_chars:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + max_chars, len(text))
        chunks.append(text[start:end].strip())
        if end >= len(text):
            break
        start = max(0, end - overlap)
    return [chunk for chunk in chunks if chunk]


def classify_chunk(filename: str, text: str) -> str:
    lowered_name = filename.lower()
    lowered = text.lower()
    if "solution" in lowered_name or "remediation" in lowered or "correct:" in lowered:
        return COLLECTION_FIXES
    if "exploit pattern" in lowered or "confirmed if" in lowered or "payload:" in lowered:
        return COLLECTION_EXPLOITS
    return COLLECTION_VULNERABILITIES
