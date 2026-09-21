"""
Build the MITRE ATT&CK FAISS index.

This script downloads the official STIX data (if not cached),
processes it into RAG documents, embeds them, and builds a
persistent FAISS index.

Usage:
    python -m mitre_rag.scripts.build_index [--force]

The --force flag re-downloads the STIX data even if cached.
"""

import argparse
import logging
import sys
import time

# Ensure the project root is importable
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from mitre_rag.ingestion.stix_loader import load_and_parse
from mitre_rag.processing.document_builder import build_documents, save_documents
from mitre_rag.embeddings.embedder import embed_texts
from mitre_rag.vectorstore.faiss_store import FaissStore


def main():
    parser = argparse.ArgumentParser(
        description="Build the MITRE ATT&CK FAISS index for RAG retrieval."
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-download of STIX data even if cached.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    logger = logging.getLogger(__name__)

    t0 = time.time()

    # 1. Download and parse STIX data
    logger.info("=" * 60)
    logger.info("PHASE 1: STIX Data Ingestion")
    logger.info("=" * 60)
    techniques = load_and_parse(force_download=args.force)
    logger.info("Parsed %d techniques.", len(techniques))

    # 2. Build documents
    logger.info("=" * 60)
    logger.info("PHASE 2: Document Processing")
    logger.info("=" * 60)
    documents = build_documents(techniques)
    save_documents(documents)
    logger.info("Built and saved %d documents.", len(documents))

    # 3. Embed documents
    logger.info("=" * 60)
    logger.info("PHASE 3: Embedding Generation")
    logger.info("=" * 60)
    texts = [doc["text"] for doc in documents]
    embeddings = embed_texts(texts)
    logger.info("Generated embeddings: shape %s", embeddings.shape)

    # 4. Build and save FAISS index
    logger.info("=" * 60)
    logger.info("PHASE 4: FAISS Index Construction")
    logger.info("=" * 60)
    metadata = [doc["metadata"] for doc in documents]
    store = FaissStore()
    store.build(embeddings, metadata)
    store.save()
    logger.info("FAISS index saved (%d vectors).", store.size)

    elapsed = time.time() - t0
    logger.info("=" * 60)
    logger.info("BUILD COMPLETE in %.1fs", elapsed)
    logger.info("  Techniques: %d", len(techniques))
    logger.info("  Documents:  %d", len(documents))
    logger.info("  Embeddings: %s", embeddings.shape)
    logger.info("  Index size: %d vectors", store.size)
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
