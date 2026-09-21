"""
Retrieval evaluation suite for MITRE ATT&CK RAG.

Evaluates retrieval ranking, tactic alignment, evidence grounding,
and score decomposition across synthetic and deterministic threat scenarios.
"""

import pytest

from mitre_rag.config import (
    WEIGHT_SEMANTIC,
    WEIGHT_TACTIC,
    WEIGHT_EVIDENCE,
)
from mitre_rag.retrieval.retriever import (
    rank_candidates,
    compute_tactic_score,
    compute_evidence_score,
)


@pytest.fixture
def candidate_library():
    """A realistic pool of candidate techniques across diverse tactics."""
    return [
        (
            {
                "technique_id": "T1498",
                "name": "Network Denial of Service",
                "tactics": ["impact"],
                "tactic_ids": ["TA0040"],
                "network_relevance": 0.95,
                "description_snippet": "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or disrupt the availability of targeted systems through volumetric flooding.",
                "url": "https://attack.mitre.org/techniques/T1498",
            },
            0.82,  # semantic score for DoS query
        ),
        (
            {
                "technique_id": "T1110",
                "name": "Brute Force",
                "tactics": ["credential-access"],
                "tactic_ids": ["TA0006"],
                "network_relevance": 0.70,
                "description_snippet": "Adversaries may use brute force techniques to attempt authentication credentials over network protocols.",
                "url": "https://attack.mitre.org/techniques/T1110",
            },
            0.55,  # semantic score for DoS query
        ),
        (
            {
                "technique_id": "T1046",
                "name": "Network Service Discovery",
                "tactics": ["discovery"],
                "tactic_ids": ["TA0007"],
                "network_relevance": 0.85,
                "description_snippet": "Adversaries may attempt to get a listing of services running on remote hosts by port scanning and analyzing responses.",
                "url": "https://attack.mitre.org/techniques/T1046",
            },
            0.50,
        ),
        (
            {
                "technique_id": "T1021",
                "name": "Remote Services",
                "tactics": ["lateral-movement"],
                "tactic_ids": ["TA0008"],
                "network_relevance": 0.75,
                "description_snippet": "Adversaries may use valid accounts to log into remote services such as RDP, SSH, or SMB for lateral movement.",
                "url": "https://attack.mitre.org/techniques/T1021",
            },
            0.45,
        ),
    ]


def test_eval_dos_scenario(candidate_library):
    """Scenario: High volumetric traffic, model predicts DoS Impact (class 2 -> TA0040)."""
    important_features = [
        {"feature": "mean_Flow Pkts/s", "importance": 0.92},
        {"feature": "std_Flow Duration", "importance": 0.65},
    ]

    ranked = rank_candidates(
        candidates=candidate_library,
        model_mitre_class=2,  # DoS Impact
        attack_probability=0.94,
        important_features=important_features,
    )

    top = ranked[0]
    assert top["technique_id"] == "T1498", "Top candidate must be Network DoS (T1498)"
    assert top["tactic_score"] == 1.0, "Tactic score must be 1.0 for matching TA0040"
    assert top["confidence"] >= 0.70, f"Expected high confidence, got {top['confidence']}"
    assert top["evidence_score"] > 0.5, "Evidence score should reflect high packet rate"


def test_eval_credential_access_scenario(candidate_library):
    """Scenario: Credential access attempt, model predicts class 1 -> TA0006."""
    # Modify candidate semantic scores to favor brute force
    modified_candidates = [
        (candidate_library[0][0], 0.40),  # T1498
        (candidate_library[1][0], 0.88),  # T1110 Brute Force
        (candidate_library[2][0], 0.50),  # T1046
        (candidate_library[3][0], 0.45),  # T1021
    ]
    important_features = [
        {"feature": "mean_Dst Port", "importance": 0.80},
        {"feature": "std_Tot Fwd Pkts", "importance": 0.70},
    ]

    ranked = rank_candidates(
        candidates=modified_candidates,
        model_mitre_class=1,  # Credential Access
        attack_probability=0.88,
        important_features=important_features,
    )

    top = ranked[0]
    assert top["technique_id"] == "T1110", "Top candidate must be Brute Force (T1110)"
    assert top["tactic_score"] == 1.0, "Tactic score must be 1.0 for matching TA0006"


def test_eval_score_decomposition_exactness(candidate_library):
    """Verify that final_retrieval_score exactly respects the weighted formulation."""
    important_features = [{"feature": "mean_Flow Pkts/s", "importance": 0.9}]

    ranked = rank_candidates(
        candidates=candidate_library,
        model_mitre_class=2,
        attack_probability=0.9,
        important_features=important_features,
    )

    for item in ranked:
        expected_final = (
            WEIGHT_SEMANTIC * item["semantic_score"]
            + WEIGHT_TACTIC * item["tactic_score"]
            + WEIGHT_EVIDENCE * item["evidence_score"]
        )
        assert pytest.approx(item["final_retrieval_score"], abs=1e-3) == expected_final


def test_eval_confidence_discounting(candidate_library):
    """Verify confidence discounting when evidence is weak vs strong."""
    # Strong evidence
    ranked_strong = rank_candidates(
        candidates=candidate_library[:1],
        model_mitre_class=2,
        attack_probability=0.95,
        important_features=[{"feature": "mean_Flow Pkts/s", "importance": 0.95}],
    )

    # Weak evidence (empty features)
    ranked_weak = rank_candidates(
        candidates=candidate_library[:1],
        model_mitre_class=2,
        attack_probability=0.60,
        important_features=[],
    )

    assert ranked_strong[0]["confidence"] > ranked_weak[0]["confidence"]
    # Even with strong evidence, confidence must never exceed 0.95 cap
    assert ranked_strong[0]["confidence"] <= 0.95
