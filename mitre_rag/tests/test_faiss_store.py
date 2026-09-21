"""
Unit tests for FAISS vector store module (mitre_rag.vectorstore.faiss_store).
"""

import numpy as np
import pytest

from mitre_rag.config import EMBEDDING_DIMENSION
from mitre_rag.vectorstore.faiss_store import FaissStore


@pytest.fixture
def dummy_store():
    """Create a FaissStore with 3 dummy techniques and normalized vectors."""
    store = FaissStore()
    np.random.seed(42)

    # 3 embeddings
    raw_vecs = np.random.randn(3, EMBEDDING_DIMENSION).astype(np.float32)
    # L2 normalize
    embeddings = raw_vecs / np.linalg.norm(raw_vecs, axis=1, keepdims=True)

    metadata = [
        {"technique_id": "T1498", "name": "Network Denial of Service", "tactic": "impact"},
        {"technique_id": "T1046", "name": "Network Service Discovery", "tactic": "discovery"},
        {"technique_id": "T1110", "name": "Brute Force", "tactic": "credential-access"},
    ]

    store.build(embeddings, metadata)
    return store, embeddings, metadata


def test_build_and_properties(dummy_store):
    store, embeddings, metadata = dummy_store
    assert store.is_loaded is True
    assert store.size == 3


def test_build_dimension_mismatch():
    store = FaissStore()
    bad_embeddings = np.random.randn(2, EMBEDDING_DIMENSION + 10).astype(np.float32)
    metadata = [{"technique_id": "T1"}, {"technique_id": "T2"}]

    with pytest.raises(AssertionError, match="Embedding dimension mismatch"):
        store.build(bad_embeddings, metadata)


def test_build_metadata_count_mismatch():
    store = FaissStore()
    embeddings = np.random.randn(2, EMBEDDING_DIMENSION).astype(np.float32)
    metadata = [{"technique_id": "T1"}]

    with pytest.raises(AssertionError, match="Metadata count mismatch"):
        store.build(embeddings, metadata)


def test_search(dummy_store):
    store, embeddings, metadata = dummy_store

    # Query using the exact vector of T1046 (index 1)
    query_vec = embeddings[1].copy()
    results = store.search(query_vec, top_k=2)

    assert len(results) == 2
    # Top match should be T1046 with cosine sim ~ 1.0
    top_meta, top_score = results[0]
    assert top_meta["technique_id"] == "T1046"
    assert pytest.approx(top_score, rel=1e-3) == 1.0


def test_save_and_load(dummy_store, tmp_path):
    store, embeddings, metadata = dummy_store
    store.save(dest_dir=tmp_path)

    assert store.index_exists(src_dir=tmp_path) is True

    # Load into fresh store
    new_store = FaissStore()
    assert new_store.is_loaded is False
    new_store.load(src_dir=tmp_path)

    assert new_store.is_loaded is True
    assert new_store.size == 3

    # Search loaded store
    results = new_store.search(embeddings[0], top_k=1)
    assert len(results) == 1
    assert results[0][0]["technique_id"] == "T1498"


def test_search_unloaded_raises():
    store = FaissStore()
    query_vec = np.zeros(EMBEDDING_DIMENSION, dtype=np.float32)
    with pytest.raises(RuntimeError, match="Index not loaded"):
        store.search(query_vec)
