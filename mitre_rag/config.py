"""
RAG configuration — paths, model names, and retrieval parameters.

All paths use pathlib for cross-platform compatibility.
"""

from pathlib import Path

# ─── Paths ──────────────────────────────────────────────────────────────────
RAG_ROOT = Path(__file__).resolve().parent
DATA_DIR = RAG_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
VECTORSTORE_DIR = RAG_ROOT / "vectorstore"

# ─── MITRE ATT&CK STIX source ──────────────────────────────────────────────
STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
STIX_FILENAME = "enterprise-attack.json"

# ─── Embedding model ───────────────────────────────────────────────────────
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"
EMBEDDING_DIMENSION = 384  # output dim of all-MiniLM-L6-v2

# ─── FAISS index ────────────────────────────────────────────────────────────
FAISS_INDEX_FILENAME = "mitre_techniques.index"
FAISS_METADATA_FILENAME = "mitre_techniques_meta.json"

# ─── Retrieval parameters ──────────────────────────────────────────────────
TOP_K_CANDIDATES = 10          # candidates retrieved from FAISS
TOP_K_RESULTS = 5              # final results returned after re-ranking
ATTACK_THRESHOLD = 0.55        # matches backend _best_threshold

# ─── Scoring weights ───────────────────────────────────────────────────────
WEIGHT_SEMANTIC = 0.40
WEIGHT_TACTIC = 0.35
WEIGHT_EVIDENCE = 0.25

# ─── Tactic mapping (model class → MITRE tactic IDs) ───────────────────────
# Maps the 7-class MITRE head outputs from TGAT_WorldModel to official
# MITRE ATT&CK tactic identifiers for tactic-compatibility scoring.
MODEL_TACTIC_MAP = {
    0: [],                                        # Benign — no tactics
    1: ["TA0006"],                                # Credential Access
    2: ["TA0040"],                                # DoS Impact
    3: ["TA0040"],                                # DDoS Impact
    4: ["TA0001"],                                # Web Exploit / Initial Access
    5: ["TA0008"],                                # Lateral Movement
    6: ["TA0011"],                                # C2 / Botnet
}
