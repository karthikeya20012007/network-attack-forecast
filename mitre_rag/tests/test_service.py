"""
Unit tests for the high-level RAG service (mitre_rag.service).
"""

from unittest.mock import MagicMock, patch
import pytest

from mitre_rag.service import MitreRAGService
from mitre_rag.config import ATTACK_THRESHOLD


def test_service_benign_response():
    service = MitreRAGService()

    # Query with attack probability below threshold (e.g. 0.2 < 0.55)
    res = service.query(
        predicted_stage="Benign",
        attack_probability=0.2,
        important_features=[],
    )

    assert res["technique_id"] is None
    assert res["technique_name"] is None
    assert res["confidence"] == 0.0
    assert "No attack detected" in res["reason"]
    assert res["candidates"] == []


def test_service_unready_response():
    service = MitreRAGService()
    # Temporarily set ready to False
    orig_ready = service._ready
    try:
        service._ready = False
        res = service.query(
            predicted_stage="DoS Impact (TA0040)",
            attack_probability=0.85,
            important_features=[{"feature": "mean_Flow Pkts/s", "importance": 0.9}],
        )
        assert res["technique_id"] is None
        assert "not initialized" in res["reason"]
    finally:
        service._ready = orig_ready


def test_service_query_mocked_store():
    service = MitreRAGService()
    orig_ready = service._ready
    orig_store = service._store

    try:
        service._ready = True
        mock_store = MagicMock()
        mock_store.search.return_value = [
            (
                {
                    "technique_id": "T1498",
                    "name": "Network Denial of Service",
                    "tactics": ["impact"],
                    "tactic_ids": ["TA0040"],
                    "network_relevance": 0.9,
                    "description_snippet": "Volumetric network flooding",
                    "url": "https://attack.mitre.org/techniques/T1498",
                },
                0.88,
            )
        ]
        service._store = mock_store

        # Mock embedding
        with patch("mitre_rag.service.embed_query", return_value=MagicMock()):
            res = service.query(
                predicted_stage="DoS Impact (TA0040)",
                attack_probability=0.85,
                important_features=[{"feature": "mean_Flow Pkts/s", "importance": 0.9}],
                flow_count=300,
            )

            assert res["technique_id"] == "T1498"
            assert res["technique_name"] == "Network Denial of Service"
            assert res["tactic"] == "impact"
            assert res["confidence"] > 0.5
            assert "scores" in res
            assert "evidence" in res
            assert len(res["evidence"]) == 1
            assert res["evidence"][0]["feature"] == "mean_Flow Pkts/s"
            assert "reason" in res
            assert "limitations" in res
    finally:
        service._ready = orig_ready
        service._store = orig_store


def test_service_status():
    service = MitreRAGService()
    st = service.status()
    assert "ready" in st
    assert "index_size" in st
    assert "embedding_model_loaded" in st
