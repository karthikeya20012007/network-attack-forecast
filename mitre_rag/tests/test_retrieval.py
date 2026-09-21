"""
Unit tests for the retrieval pipeline (mitre_rag.retrieval.retriever).
"""

import pytest

from mitre_rag.retrieval.retriever import (
    _strip_agg_prefix,
    build_query,
    compute_tactic_score,
    compute_evidence_score,
    rank_candidates,
    generate_reason,
    generate_limitations,
)


def test_strip_agg_prefix():
    assert _strip_agg_prefix("mean_Flow Pkts/s") == "Flow Pkts/s"
    assert _strip_agg_prefix("std_Dst Port") == "Dst Port"
    assert _strip_agg_prefix("min_Flow Duration") == "Flow Duration"
    assert _strip_agg_prefix("max_Init Fwd Win Byts") == "Init Fwd Win Byts"
    assert _strip_agg_prefix("meta_log_flow_count") == "meta_log_flow_count"


def test_build_query():
    # Attack stage with features
    query = build_query(
        predicted_stage="DoS Impact (TA0040)",
        attack_probability=0.92,
        important_features=[
            {"feature": "mean_Flow Pkts/s", "importance": 0.85},
            {"feature": "std_Flow Duration", "importance": 0.45},
        ],
        flow_count=250,
    )
    assert "DoS Impact (TA0040)" in query
    assert "Flow Pkts/s" in query
    assert "Flow Duration" in query
    assert "250 flows per minute" in query
    assert "Very high confidence" in query

    # Benign stage
    query_benign = build_query(
        predicted_stage="Benign",
        attack_probability=0.1,
        important_features=[],
    )
    assert "anomaly detected" in query_benign


def test_compute_tactic_score():
    # Class 2 = DoS Impact -> TA0040
    assert compute_tactic_score(["TA0040"], model_mitre_class=2) == 1.0
    # Class 2 does not match TA0006
    assert compute_tactic_score(["TA0006"], model_mitre_class=2) == 0.0
    # Class 0 = Benign -> 0.0
    assert compute_tactic_score(["TA0040"], model_mitre_class=0) == 0.0
    # Class 1 = Credential Access -> TA0006
    assert compute_tactic_score(["TA0006"], model_mitre_class=1) == 1.0


def test_compute_evidence_score():
    metadata = {
        "description_snippet": "Adversaries may perform volumetric flooding attacks with high packet rates",
        "tactics": ["impact"],
        "network_relevance": 0.9,
    }
    # Matching features
    features = [
        {"feature": "mean_Flow Pkts/s", "importance": 0.8},
    ]
    score = compute_evidence_score(metadata, features)
    assert score > 0.6

    # Empty features
    assert compute_evidence_score(metadata, []) == 0.0


def test_rank_candidates():
    candidates = [
        (
            {
                "technique_id": "T1498",
                "name": "Network Denial of Service",
                "tactics": ["impact"],
                "tactic_ids": ["TA0040"],
                "network_relevance": 0.9,
                "description_snippet": "Flooding network traffic with high packet rates",
                "url": "https://attack.mitre.org/techniques/T1498",
            },
            0.85,  # semantic score
        ),
        (
            {
                "technique_id": "T1110",
                "name": "Brute Force",
                "tactics": ["credential-access"],
                "tactic_ids": ["TA0006"],
                "network_relevance": 0.6,
                "description_snippet": "Repeated login attempts",
                "url": "https://attack.mitre.org/techniques/T1110",
            },
            0.70,  # semantic score
        ),
    ]

    # Model predicted DoS Impact (class 2 -> TA0040)
    ranked = rank_candidates(
        candidates=candidates,
        model_mitre_class=2,
        attack_probability=0.9,
        important_features=[{"feature": "mean_Flow Pkts/s", "importance": 0.8}],
    )

    assert len(ranked) == 2
    top = ranked[0]
    # T1498 should win due to matching tactic and evidence
    assert top["technique_id"] == "T1498"
    assert top["tactic_score"] == 1.0
    assert top["final_retrieval_score"] > ranked[1]["final_retrieval_score"]
    # Verify confidence is never identical to raw semantic score
    assert top["confidence"] != candidates[0][1]
    assert top["confidence"] <= 0.95


def test_generate_reason_and_limitations():
    top_result = {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "impact",
        "tactic_score": 1.0,
        "confidence": 0.82,
        "evidence_score": 0.75,
    }
    features = [{"feature": "mean_Flow Pkts/s", "importance": 0.9}]

    reason = generate_reason(top_result, "DoS Impact (TA0040)", features)
    assert "Network Denial of Service" in reason
    assert "Flow Pkts/s" in reason
    assert "matches this technique's tactic" in reason

    limitations = generate_limitations(top_result, features)
    assert "Network flow features alone cannot definitively confirm" in limitations
