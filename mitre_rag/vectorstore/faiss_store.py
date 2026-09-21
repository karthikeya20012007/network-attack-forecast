"""
FAISS-based vector store for MITRE ATT&CK technique documents.

Supports:
- Building an index from document embeddings
- Saving / loading a persistent index
- Searching by query embedding (returns top-K candidates with scores)

The index uses Inner Product (IP) similarity on L2-normalised vectors,
which is equivalent to cosine similarity.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

from mitre_rag.config import (
    FAISS_INDEX_FILENAME,
    FAISS_METADATA_FILENAME,
    VECTORSTORE_DIR,
    EMBEDDING_DIMENSION,
    TOP_K_CANDIDATES,
)

logger = logging.getLogger(__name__)


class FaissStore:
    """Persistent FAISS index with associated document metadata."""

    def __init__(self):
        self._index = None
        self._metadata: List[Dict] = []
        self._is_loaded = False

    @property
    def is_loaded(self) -> bool:
        return self._is_loaded

    @property
    def size(self) -> int:
        if self._index is None:
            return 0
        return self._index.ntotal

    def build(self, embeddings: np.ndarray, metadata: List[Dict]) -> None:
        """Build a new FAISS index from embeddings and metadata.

        Args:
            embeddings: (N, dim) float32 array of document embeddings.
            metadata: List of N metadata dicts (one per document).
        """
        import faiss

        n, dim = embeddings.shape
        assert dim == EMBEDDING_DIMENSION, (
            f"Embedding dimension mismatch: got {dim}, expected {EMBEDDING_DIMENSION}"
        )
        assert len(metadata) == n, (
            f"Metadata count mismatch: {len(metadata)} metadata vs {n} embeddings"
        )

        # Inner Product index (equivalent to cosine sim on L2-normalised vectors)
        self._index = faiss.IndexFlatIP(dim)
        self._index.add(embeddings)
        self._metadata = metadata
        self._is_loaded = True

        logger.info("[RAG] Built FAISS index with %d vectors (dim=%d)", n, dim)

    def save(self, dest_dir: Path = VECTORSTORE_DIR) -> None:
        """Persist the index and metadata to disk.

        Args:
            dest_dir: Directory to save index and metadata files.
        """
        import faiss

        if self._index is None:
            raise RuntimeError("No index to save — call build() first.")

        dest_dir.mkdir(parents=True, exist_ok=True)
        index_path = dest_dir / FAISS_INDEX_FILENAME
        meta_path = dest_dir / FAISS_METADATA_FILENAME

        faiss.write_index(self._index, str(index_path))
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(self._metadata, f, ensure_ascii=False)

        logger.info("[RAG] Saved FAISS index (%d vectors) to %s",
                    self._index.ntotal, index_path)

    def load(self, src_dir: Path = VECTORSTORE_DIR) -> None:
        """Load a previously saved index and metadata from disk.

        Args:
            src_dir: Directory containing the index and metadata files.
        """
        import faiss

        index_path = src_dir / FAISS_INDEX_FILENAME
        meta_path = src_dir / FAISS_METADATA_FILENAME

        if not index_path.exists():
            raise FileNotFoundError(f"FAISS index not found at {index_path}")
        if not meta_path.exists():
            raise FileNotFoundError(f"Metadata file not found at {meta_path}")

        self._index = faiss.read_index(str(index_path))
        with open(meta_path, "r", encoding="utf-8") as f:
            self._metadata = json.load(f)

        self._is_loaded = True
        logger.info("[RAG] Loaded FAISS index with %d vectors from %s",
                    self._index.ntotal, index_path)

    def search(
        self,
        query_embedding: np.ndarray,
        top_k: int = TOP_K_CANDIDATES,
    ) -> List[Tuple[Dict, float]]:
        """Search for the top-K most similar documents.

        Args:
            query_embedding: (dim,) float32 query vector.
            top_k: Number of results to return.

        Returns:
            List of (metadata_dict, similarity_score) tuples,
            sorted by descending similarity.
        """
        if self._index is None:
            raise RuntimeError("Index not loaded — call load() or build() first.")

        # FAISS expects a 2D array
        query_2d = query_embedding.reshape(1, -1).astype(np.float32)
        scores, indices = self._index.search(query_2d, top_k)

        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < 0:
                continue  # FAISS returns -1 for missing results
            results.append((self._metadata[idx], float(score)))

        return results

    def index_exists(self, src_dir: Path = VECTORSTORE_DIR) -> bool:
        """Check whether a saved index exists at the given directory."""
        return (
            (src_dir / FAISS_INDEX_FILENAME).exists()
            and (src_dir / FAISS_METADATA_FILENAME).exists()
        )
