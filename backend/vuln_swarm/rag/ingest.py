from __future__ import annotations

import argparse
import json
from pathlib import Path

from vuln_swarm.core.config import get_settings
from vuln_swarm.rag.vector_store import ChromaKnowledgeBase


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest Vuln-Swarm knowledge documents into ChromaDB.")
    parser.add_argument("--force", action="store_true", help="Rebuild collections from scratch.")
    args = parser.parse_args()

    settings = get_settings()
    kb = ChromaKnowledgeBase(settings, base_dir=Path(__file__).resolve().parents[3])
    counts = kb.ingest(force=args.force)
    print(json.dumps(counts, indent=2))


if __name__ == "__main__":
    main()
