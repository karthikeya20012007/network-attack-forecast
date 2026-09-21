"""
Sentence-transformer embedding wrapper (singleton).

Loads the embedding model exactly once and reuses it for all
subsequent calls. Thread-safe via module-level singleton.
"""

import logging
from typing import List, Optional

import numpy as np

from mitre_rag.config import EMBEDDING_MODEL_NAME, EMBEDDING_DIMENSION

logger = logging.getLogger(__name__)

# Module-level singleton — model is loaded once per process.
_model = None


def _get_model():
    """Lazy-load the sentence-transformer model (singleton)."""
    global _model
    if _model is None:
        logger.info("[RAG] Loading embedding model '%s' ...", EMBEDDING_MODEL_NAME)
        from sentence_transformers import SentenceTransformer
        _model = SentenceTransformer(EMBEDDING_MODEL_NAME)
        logger.info("[RAG] Embedding model loaded (dim=%d).", EMBEDDING_DIMENSION)
    return _model


def embed_texts(texts: List[str], batch_size: int = 64) -> np.ndarray:
    """Embed a list of text strings into dense vectors.

    Args:
        texts: List of strings to embed.
        batch_size: Batch size for encoding.

    Returns:
        numpy array of shape (len(texts), EMBEDDING_DIMENSION).
    """
    model = _get_model()
    embeddings = model.encode(
        texts,
        batch_size=batch_size,
        show_progress_bar=False,
        normalize_embeddings=True,  # L2-normalise for cosine similarity via inner product
    )
    return np.asarray(embeddings, dtype=np.float32)


def embed_query(text: str) -> np.ndarray:
    """Embed a single query string.

    Args:
        text: Query string.

    Returns:
        numpy array of shape (EMBEDDING_DIMENSION,).
    """
    model = _get_model()
    embedding = model.encode(
        [text],
        show_progress_bar=False,
        normalize_embeddings=True,
    )
    return np.asarray(embedding[0], dtype=np.float32)


def get_dimension() -> int:
    """Return the embedding dimension of the loaded model."""
    return EMBEDDING_DIMENSION


def is_loaded() -> bool:
    """Check whether the embedding model has been loaded."""
    return _model is not None
