"""
High-level MITRE ATT&CK RAG service.

Provides a single entry point for the backend to:
1. Initialize once (load MITRE data, embedding model, FAISS index)
2. Query per-request (embed query, retrieve, rank, return result)

The service is designed as a singleton — initialize once at application
startup, then call query() for each inference window.

Lifecycle:
    startup:  MitreRAGService() → loads index + model
    request:  service.query(evidence) → structured RAG result
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional

from mitre_rag.config import (
    VECTORSTORE_DIR,
    PROCESSED_DATA_DIR,
    ATTACK_THRESHOLD,
    TOP_K_CANDIDATES,
)
from mitre_rag.embeddings.embedder import embed_query, is_loaded as embedder_loaded
from mitre_rag.vectorstore.faiss_store import FaissStore
from mitre_rag.retrieval.retriever import (
    build_query,
    rank_candidates,
    generate_reason,
    generate_limitations,
)

logger = logging.getLogger(__name__)


# ─── MITRE class mapping (matches backend/model.py MITRE_NAMES) ────────────
_MITRE_NAME_TO_CLASS = {
    "Benign": 0,
    "Credential Access (TA0006)": 1,
    "DoS Impact (TA0040)": 2,
    "DDoS Impact (TA0040)": 3,
    "Web Exploit (TA0001)": 4,
    "Lateral Movement (TA0008)": 5,
    "C2 / Botnet (TA0011)": 6,
}


class MitreRAGService:
    """Singleton-style MITRE ATT&CK RAG service.

    Usage:
        service = MitreRAGService()       # loads everything once
        result = service.query(evidence)  # fast per-request retrieval
    """

    def __init__(self, vectorstore_dir: Path = VECTORSTORE_DIR):
        """Initialize the RAG service.

        Loads:
        - FAISS index (from pre-built index files)
        - Embedding model (lazy-loaded on first embed_query call)

        Args:
            vectorstore_dir: Directory containing the FAISS index files.

        Raises:
            FileNotFoundError: If the FAISS index hasn't been built yet.
        """
        self._store = FaissStore()
        self._ready = False

        logger.info("[RAG] Initializing MITRE ATT&CK RAG service...")

        if not self._store.index_exists(vectorstore_dir):
            logger.warning(
                "[RAG] FAISS index not found at %s. "
                "Run 'python -m mitre_rag.scripts.build_index' first. "
                "RAG will return empty results until the index is built.",
                vectorstore_dir,
            )
            return

        self._store.load(vectorstore_dir)

        # Trigger embedding model load now (not on first request)
        logger.info("[RAG] Loading embedding model...")
        embed_query("warmup")
        logger.info("[RAG] Embedding model loaded.")

        self._ready = True
        logger.info("[RAG] MITRE ATT&CK RAG service initialized. "
                     "Index: %d techniques.", self._store.size)

    @property
    def is_ready(self) -> bool:
        return self._ready

    def query(
        self,
        predicted_stage: str,
        attack_probability: float,
        important_features: List[Dict],
        flow_count: Optional[int] = None,
    ) -> Dict:
        """Query the RAG for the best MITRE ATT&CK technique mapping.

        This is called once per inference window with the actual
        evidence from the LSTM/TGAT world model.

        Args:
            predicted_stage: Model's MITRE tactic label (e.g., "DoS Impact (TA0040)").
            attack_probability: P(attack) from the attack head (0.0 - 1.0).
            important_features: Top gradient-attribution features, each
                {"feature": str, "importance": float}.
            flow_count: Number of flows in the 1-min window (optional).

        Returns:
            Structured RAG result dict.
        """
        # If RAG isn't ready or attack probability is below threshold,
        # return a lightweight response
        if attack_probability < ATTACK_THRESHOLD:
            return self._benign_result(attack_probability)

        if not self._ready:
            return self._empty_result(
                "RAG service not initialized (FAISS index not built)."
            )

        # 1. Build semantic query from evidence
        query_text = build_query(
            predicted_stage=predicted_stage,
            attack_probability=attack_probability,
            important_features=important_features,
            flow_count=flow_count,
        )

        # 2. Embed the query
        query_embedding = embed_query(query_text)

        # 3. Retrieve candidates from FAISS
        candidates = self._store.search(query_embedding, top_k=TOP_K_CANDIDATES)

        if not candidates:
            return self._empty_result("No candidates found in FAISS index.")

        # 4. Determine model MITRE class
        model_class = _MITRE_NAME_TO_CLASS.get(predicted_stage, 0)

        # 5. Re-rank with tactic + evidence scoring
        ranked = rank_candidates(
            candidates=candidates,
            model_mitre_class=model_class,
            attack_probability=attack_probability,
            important_features=important_features,
        )

        if not ranked:
            return self._empty_result("No candidates survived re-ranking.")

        # 6. Build structured response
        top = ranked[0]

        result = {
            "technique_id": top["technique_id"],
            "technique_name": top["technique_name"],
            "tactic": top["tactic"],
            "confidence": top["confidence"],
            "reason": generate_reason(top, predicted_stage, important_features),
            "evidence": [
                {
                    "feature": feat["feature"],
                    "importance": round(feat.get("importance", 0), 4),
                }
                for feat in important_features[:5]
            ],
            "mitre_url": top.get("url"),
            "mitre_description": top.get("description_snippet", ""),
            "limitations": generate_limitations(top, important_features),
            "scores": {
                "semantic_score": top["semantic_score"],
                "tactic_score": top["tactic_score"],
                "evidence_score": top["evidence_score"],
                "final_retrieval_score": top["final_retrieval_score"],
            },
            "candidates": [
                {
                    "technique_id": c["technique_id"],
                    "technique_name": c["technique_name"],
                    "tactic": c["tactic"],
                    "confidence": c["confidence"],
                    "final_retrieval_score": c["final_retrieval_score"],
                }
                for c in ranked[1:]  # exclude top (already shown)
            ],
        }

        return result

    def _benign_result(self, attack_probability: float) -> Dict:
        """Return a lightweight result when no attack is detected."""
        return {
            "technique_id": None,
            "technique_name": None,
            "tactic": None,
            "confidence": 0.0,
            "reason": (
                f"No attack detected (P(attack) = {attack_probability:.4f}, "
                f"below threshold {ATTACK_THRESHOLD}). "
                "MITRE ATT&CK mapping not applicable for benign traffic."
            ),
            "evidence": [],
            "mitre_url": None,
            "mitre_description": None,
            "limitations": "RAG analysis is only performed when the model detects an attack.",
            "scores": {
                "semantic_score": 0.0,
                "tactic_score": 0.0,
                "evidence_score": 0.0,
                "final_retrieval_score": 0.0,
            },
            "candidates": [],
        }

    def _empty_result(self, reason: str) -> Dict:
        """Return an empty result with an explanation."""
        return {
            "technique_id": None,
            "technique_name": None,
            "tactic": None,
            "confidence": 0.0,
            "reason": reason,
            "evidence": [],
            "mitre_url": None,
            "mitre_description": None,
            "limitations": reason,
            "scores": {
                "semantic_score": 0.0,
                "tactic_score": 0.0,
                "evidence_score": 0.0,
                "final_retrieval_score": 0.0,
            },
            "candidates": [],
        }

    def status(self) -> Dict:
        """Return diagnostic status for the RAG service."""
        return {
            "ready": self._ready,
            "index_size": self._store.size if self._ready else 0,
            "embedding_model_loaded": embedder_loaded(),
        }
