"""
Evidence-grounded MITRE ATT&CK retrieval pipeline.

Receives actual model/network evidence from the inference pipeline,
constructs a semantic query, retrieves candidates from FAISS,
applies tactic-compatibility and evidence-compatibility scoring,
and returns ranked results with decomposed confidence.

Scoring Method
--------------
Each candidate technique receives three independent scores:

1. semantic_score (0-1):
   Cosine similarity between the query embedding and the technique
   document embedding. Measures how well the technique's description
   matches the observed behavior description.

2. tactic_score (0-1):
   Binary compatibility between the model's predicted MITRE tactic class
   and the technique's listed tactics. 1.0 if the technique belongs to
   the predicted tactic, 0.0 otherwise. When the model predicts Benign
   (class 0), all techniques get tactic_score = 0.0.

3. evidence_score (0-1):
   Measures how much the available gradient-based feature attribution
   evidence supports the technique. Based on matching important features
   to network-observable indicators and the technique's network_relevance.

Final retrieval score:
   final_score = W_semantic * semantic + W_tactic * tactic + W_evidence * evidence

Confidence:
   Derived from the final_score, discounted by evidence quality.
   confidence = final_score * evidence_discount * attack_probability_factor
   - Never equals raw cosine similarity
   - Reflects genuine uncertainty when evidence is weak
"""

import logging
from typing import Dict, List, Optional, Tuple

import numpy as np

from mitre_rag.config import (
    MODEL_TACTIC_MAP,
    WEIGHT_SEMANTIC,
    WEIGHT_TACTIC,
    WEIGHT_EVIDENCE,
    TOP_K_RESULTS,
    ATTACK_THRESHOLD,
)

logger = logging.getLogger(__name__)

# Features that strongly indicate network-level behavior
# (mapped from the TGAT_WorldModel's aggregated feature names)
NETWORK_INDICATOR_FEATURES = {
    # Port/protocol features → lateral movement, C2, scanning
    "Dst Port": ["scan", "port", "lateral", "remote", "smb", "ssh", "rdp"],
    "Protocol": ["protocol", "tcp", "udp", "icmp", "tunnel"],
    # Volume features → DoS/DDoS
    "Flow Pkts/s": ["flood", "dos", "ddos", "volumetric", "saturation"],
    "Fwd Pkts/s": ["flood", "dos", "scan", "automated"],
    "Bwd Pkts/s": ["reflection", "dos", "amplification"],
    "Tot Fwd Pkts": ["brute", "scan", "exfiltration", "transfer"],
    "Tot Bwd Pkts": ["exfiltration", "reflection", "data"],
    # Timing features → beaconing, C2, slow attacks
    "Flow Duration": ["slow", "beacon", "persistent", "c2"],
    "Flow IAT Mean": ["beacon", "c2", "command", "control", "automated"],
    "Flow IAT Max": ["persistent", "session", "keep-alive"],
    "Fwd IAT Mean": ["automated", "script", "tool"],
    # Payload features → exploit, exfiltration
    "Fwd Pkt Len Max": ["exploit", "overflow", "injection", "payload"],
    "Bwd Pkt Len Max": ["exfiltration", "data", "dump"],
    "Pkt Len Mean": ["tunnel", "encapsulation", "abnormal"],
    "Pkt Len Var": ["exploit", "multi-stage", "irregular"],
    # TCP flags → scanning, DoS
    "SYN Flag Cnt": ["syn", "scan", "flood", "reconnaissance"],
    "ACK Flag Cnt": ["ack", "flood", "firewall"],
    "PSH Flag Cnt": ["interactive", "shell", "reverse"],
    "RST Flag Cnt": ["scan", "port", "dos", "termination"],
    # Window features → scanning, custom tools
    "Init Fwd Win Byts": ["scan", "stealth", "custom", "exploit"],
    "Init_Win_bytes_forward": ["scan", "stealth", "custom", "exploit"],
    # Meta features
    "meta_log_flow_count": ["ddos", "flood", "sweep", "distributed"],
    "meta_unique_protocols": ["reconnaissance", "mapping", "discovery"],
    "meta_high_port_ratio": ["botnet", "automated", "scripting"],
}


def _strip_agg_prefix(feature_name: str) -> str:
    """Remove aggregation prefix (mean_, std_, min_, max_) from feature name."""
    for prefix in ("mean_", "std_", "min_", "max_"):
        if feature_name.startswith(prefix):
            return feature_name[len(prefix):]
    return feature_name


def build_query(
    predicted_stage: str,
    attack_probability: float,
    important_features: List[Dict],
    flow_count: Optional[int] = None,
) -> str:
    """Construct a semantic search query from model evidence.

    Args:
        predicted_stage: MITRE tactic label from the model's mitre head
                        (e.g., "DoS Impact (TA0040)").
        attack_probability: P(attack) from the attack head.
        important_features: List of {"feature": str, "importance": float}.
        flow_count: Number of flows in the window (optional context).

    Returns:
        A natural-language query string optimised for semantic search.
    """
    parts = []

    # Start with the predicted tactic
    if predicted_stage and predicted_stage != "Benign":
        parts.append(f"Network attack consistent with {predicted_stage}.")
    else:
        parts.append("Network traffic anomaly detected.")

    # Add feature evidence
    if important_features:
        feature_descs = []
        for feat in important_features[:5]:  # top 5 max
            base_name = _strip_agg_prefix(feat["feature"])
            importance = feat.get("importance", 0)
            if importance > 0.5:
                feature_descs.append(f"high {base_name}")
            elif importance > 0.2:
                feature_descs.append(f"elevated {base_name}")
        if feature_descs:
            parts.append(
                f"Key indicators: {', '.join(feature_descs)}."
            )

    # Add flow volume context
    if flow_count is not None and flow_count > 100:
        parts.append(f"High traffic volume ({flow_count} flows per minute).")

    # Add probability context
    if attack_probability >= 0.8:
        parts.append("Very high confidence of malicious activity.")
    elif attack_probability >= 0.6:
        parts.append("Moderate-to-high confidence of attack behavior.")

    return " ".join(parts)


def compute_tactic_score(
    candidate_tactic_ids: List[str],
    model_mitre_class: int,
) -> float:
    """Score tactic compatibility between model prediction and technique.

    Args:
        candidate_tactic_ids: Tactic IDs listed for the technique.
        model_mitre_class: Integer class from the model's mitre head (0-6).

    Returns:
        1.0 if compatible, 0.0 if not.
    """
    predicted_tactic_ids = MODEL_TACTIC_MAP.get(model_mitre_class, [])
    if not predicted_tactic_ids:
        # Model predicts Benign — no tactic match possible
        return 0.0

    for tid in predicted_tactic_ids:
        if tid in candidate_tactic_ids:
            return 1.0
    return 0.0


def compute_evidence_score(
    candidate_metadata: Dict,
    important_features: List[Dict],
) -> float:
    """Score how well the evidence supports the candidate technique.

    Combines:
    - Feature-to-technique indicator matching
    - Network relevance of the technique
    - Strength of the evidence (importance scores)

    Args:
        candidate_metadata: Metadata dict from the FAISS store.
        important_features: Feature attribution results.

    Returns:
        Float in [0, 1].
    """
    if not important_features:
        return 0.0

    # 1. Network relevance of the technique itself
    net_rel = candidate_metadata.get("network_relevance", 0.0)

    # 2. Feature indicator matching
    technique_text = (
        candidate_metadata.get("description_snippet", "").lower()
        + " "
        + " ".join(candidate_metadata.get("tactics", []))
    )

    match_score = 0.0
    total_weight = 0.0

    for feat in important_features:
        base_name = _strip_agg_prefix(feat["feature"])
        importance = feat.get("importance", 0.0)
        total_weight += importance

        # Check if this feature's indicators appear in the technique text
        indicators = NETWORK_INDICATOR_FEATURES.get(base_name, [])
        for indicator in indicators:
            if indicator in technique_text:
                match_score += importance
                break  # one match per feature is enough

    if total_weight > 0:
        feature_match = match_score / total_weight
    else:
        feature_match = 0.0

    # Combine: 60% feature matching + 40% network relevance
    evidence = 0.6 * feature_match + 0.4 * net_rel
    return min(evidence, 1.0)


def rank_candidates(
    candidates: List[Tuple[Dict, float]],
    model_mitre_class: int,
    attack_probability: float,
    important_features: List[Dict],
) -> List[Dict]:
    """Re-rank FAISS candidates using tactic + evidence scoring.

    Args:
        candidates: List of (metadata, semantic_score) from FAISS search.
        model_mitre_class: Integer class from the model's mitre head.
        attack_probability: P(attack) from the attack head.
        important_features: Feature attribution results.

    Returns:
        List of ranked result dicts with decomposed scores.
    """
    scored = []

    for metadata, semantic_score in candidates:
        # Clamp semantic score to [0, 1]
        semantic_score = max(0.0, min(1.0, semantic_score))

        tactic_score = compute_tactic_score(
            metadata.get("tactic_ids", []),
            model_mitre_class,
        )

        evidence_score = compute_evidence_score(metadata, important_features)

        # Weighted combination
        final_score = (
            WEIGHT_SEMANTIC * semantic_score
            + WEIGHT_TACTIC * tactic_score
            + WEIGHT_EVIDENCE * evidence_score
        )

        # Confidence derivation — NOT just cosine similarity
        # Discount by evidence quality and attack probability
        evidence_discount = 0.5 + 0.5 * evidence_score  # range [0.5, 1.0]
        atk_factor = min(attack_probability / ATTACK_THRESHOLD, 1.0)
        confidence = final_score * evidence_discount * atk_factor

        # Cap confidence at 0.95 — we can never be certain from network flows alone
        confidence = min(confidence, 0.95)

        scored.append({
            "technique_id": metadata.get("technique_id"),
            "technique_name": metadata.get("name"),
            "tactic": ", ".join(metadata.get("tactics", [])),
            "tactic_ids": metadata.get("tactic_ids", []),
            "confidence": round(float(confidence), 4),
            "semantic_score": round(float(semantic_score), 4),
            "tactic_score": round(float(tactic_score), 4),
            "evidence_score": round(float(evidence_score), 4),
            "final_retrieval_score": round(float(final_score), 4),
            "url": metadata.get("url"),
            "description_snippet": metadata.get("description_snippet", ""),
            "network_relevance": metadata.get("network_relevance", 0.0),
        })

    # Sort by final_retrieval_score descending
    scored.sort(key=lambda x: x["final_retrieval_score"], reverse=True)
    return scored[:TOP_K_RESULTS]


def generate_reason(
    top_result: Dict,
    predicted_stage: str,
    important_features: List[Dict],
) -> str:
    """Generate a human-readable explanation for the top RAG result.

    Args:
        top_result: The highest-ranked candidate dict.
        predicted_stage: Model's predicted MITRE tactic label.
        important_features: Feature attribution results.

    Returns:
        A concise reason string.
    """
    parts = []

    technique_name = top_result.get("technique_name", "Unknown")
    tactic = top_result.get("tactic", "Unknown")

    parts.append(
        f"The observed network behavior is consistent with "
        f"{technique_name} ({tactic})."
    )

    # Add feature support
    if important_features:
        top_feat = important_features[0]
        base_name = _strip_agg_prefix(top_feat["feature"])
        parts.append(
            f"Primary indicator: {base_name} "
            f"(importance: {top_feat.get('importance', 0):.2f})."
        )

    # Tactic alignment note
    if top_result.get("tactic_score", 0) > 0:
        parts.append(
            f"Tactic alignment: model predicted {predicted_stage}, "
            f"which matches this technique's tactic."
        )
    else:
        parts.append(
            f"Note: model predicted {predicted_stage}, which does not "
            f"directly align with this technique's tactic."
        )

    return " ".join(parts)


def generate_limitations(
    top_result: Dict,
    important_features: List[Dict],
) -> str:
    """Generate an honest limitations statement.

    Args:
        top_result: The highest-ranked candidate dict.
        important_features: Feature attribution results.

    Returns:
        A limitations string.
    """
    limitations = []

    confidence = top_result.get("confidence", 0)

    limitations.append(
        "Network flow features alone cannot definitively confirm "
        "the specific MITRE ATT&CK technique."
    )

    if confidence < 0.4:
        limitations.append(
            "Confidence is low — the available evidence provides only "
            "weak support for this technique mapping."
        )

    evidence_score = top_result.get("evidence_score", 0)
    if evidence_score < 0.3:
        limitations.append(
            "Limited feature-to-technique indicator matching. "
            "Host-level telemetry would improve accuracy."
        )

    if top_result.get("tactic_score", 0) == 0:
        limitations.append(
            "The predicted tactic does not directly match this technique. "
            "Consider alternative tactic interpretations."
        )

    return " ".join(limitations)
