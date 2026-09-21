"""
Unit tests for embeddings wrapper module (mitre_rag.embeddings.embedder).
"""

from unittest.mock import patch, MagicMock
import numpy as np
import pytest

from mitre_rag.embeddings.embedder import (
    embed_texts,
    embed_query,
    get_dimension,
    is_loaded,
    _get_model,
)
from mitre_rag.config import EMBEDDING_DIMENSION


def test_get_dimension():
    assert get_dimension() == EMBEDDING_DIMENSION
    assert get_dimension() == 384


def test_embed_texts_mocked():
    mock_model = MagicMock()
    # Dummy normalized vectors for 2 texts
    dummy_vecs = np.random.randn(2, EMBEDDING_DIMENSION).astype(np.float32)
    norms = np.linalg.norm(dummy_vecs, axis=1, keepdims=True)
    dummy_vecs = dummy_vecs / norms
    mock_model.encode.return_value = dummy_vecs

    with patch("mitre_rag.embeddings.embedder._get_model", return_value=mock_model):
        texts = ["DoS flooding attack", "Lateral movement via SMB"]
        res = embed_texts(texts, batch_size=32)

        assert res.shape == (2, EMBEDDING_DIMENSION)
        mock_model.encode.assert_called_once_with(
            texts,
            batch_size=32,
            show_progress_bar=False,
            normalize_embeddings=True,
        )


def test_embed_query_mocked():
    mock_model = MagicMock()
    dummy_vec = np.random.randn(1, EMBEDDING_DIMENSION).astype(np.float32)
    dummy_vec = dummy_vec / np.linalg.norm(dummy_vec)
    mock_model.encode.return_value = dummy_vec

    with patch("mitre_rag.embeddings.embedder._get_model", return_value=mock_model):
        query = "high packet rate flooding"
        res = embed_query(query)

        assert res.shape == (EMBEDDING_DIMENSION,)
        mock_model.encode.assert_called_once_with(
            [query],
            show_progress_bar=False,
            normalize_embeddings=True,
        )


def test_is_loaded_flag():
    import mitre_rag.embeddings.embedder as emb
    # Test state reflection
    orig = emb._model
    try:
        emb._model = None
        assert is_loaded() is False
        emb._model = MagicMock()
        assert is_loaded() is True
    finally:
        emb._model = orig
