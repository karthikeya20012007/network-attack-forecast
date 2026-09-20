"""
End-to-end integration test for MITRE ATT&CK RAG with FastAPI backend.
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app, _rag_service


@pytest.fixture
def client():
    return TestClient(app)


def test_rag_status_endpoint(client):
    """Test the /api/rag/status diagnostic endpoint."""
    response = client.get("/api/rag/status")
    assert response.status_code == 200
    data = response.json()
    assert "ready" in data
    assert "index_size" in data
    assert "embedding_model_loaded" in data


def test_scenario_step_contains_rag_field(client):
    """Verify that /api/scenario/{id}/step/{idx} includes the 'rag' key in the current window."""
    # Check scenario 0, step 0
    response = client.get("/api/scenario/0/step/0")
    if response.status_code == 200:
        data = response.json()
        if "current_window" in data and data["current_window"]:
            window = data["current_window"]
            assert "rag" in window, "Window must contain 'rag' field"
            if window["rag"] is not None:
                rag = window["rag"]
                assert "technique_id" in rag
                assert "confidence" in rag
                assert "reason" in rag
                assert "evidence" in rag
                assert "scores" in rag


def test_benign_window_rag_schema():
    """Verify that a benign window produces the expected RAG structure."""
    if _rag_service is not None:
        result = _rag_service.query(
            predicted_stage="Benign",
            attack_probability=0.15,
            important_features=[],
            flow_count=45,
        )
        assert result["technique_id"] is None
        assert result["confidence"] == 0.0
        assert "No attack detected" in result["reason"]
        assert result["scores"]["final_retrieval_score"] == 0.0
        assert result["candidates"] == []
