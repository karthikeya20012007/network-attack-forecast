"""
Document builder for the MITRE RAG vector store.

Converts parsed technique dictionaries into rich text documents
suitable for semantic embedding and retrieval.

Each document combines the technique's name, tactics, description,
detection guidance, and network-observable indicators into a single
text passage optimised for cosine-similarity search.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List

from mitre_rag.config import PROCESSED_DATA_DIR

logger = logging.getLogger(__name__)

# Network-relevant keywords used to identify techniques that are
# observable at the network flow level (CICFlowMeter / Zeek features).
NETWORK_KEYWORDS = [
    "network", "traffic", "packet", "port", "protocol", "tcp", "udp",
    "icmp", "http", "https", "dns", "smb", "ssh", "rdp", "ftp",
    "scan", "flood", "dos", "ddos", "brute", "lateral", "beacon",
    "c2", "command and control", "exfiltration", "tunnel", "proxy",
    "remote", "connection", "session", "flow", "bandwidth", "firewall",
    "socket", "syn", "ack", "rst", "payload",
]


def build_document_text(technique: Dict) -> str:
    """Build a single searchable text passage from a technique dict.

    The text is structured to maximise semantic overlap with the
    kind of queries the retriever will construct from model evidence
    (e.g., "high packet rate DoS flooding attack").

    Args:
        technique: Parsed technique dict from stix_loader.

    Returns:
        A multi-line plain-text document.
    """
    parts = []

    # Header
    parts.append(
        f"MITRE ATT&CK Technique {technique['technique_id']}: "
        f"{technique['name']}"
    )

    # Tactics
    if technique["tactics"]:
        tactic_str = ", ".join(technique["tactics"])
        parts.append(f"Tactics: {tactic_str}")

    if technique["tactic_ids"]:
        parts.append(f"Tactic IDs: {', '.join(technique['tactic_ids'])}")

    # Platforms
    if technique["platforms"]:
        parts.append(f"Platforms: {', '.join(technique['platforms'])}")

    # Description (core content for semantic matching)
    desc = technique.get("description", "").strip()
    if desc:
        # Truncate very long descriptions to keep embeddings focused
        if len(desc) > 2000:
            desc = desc[:2000] + "..."
        parts.append(f"Description: {desc}")

    # Detection guidance (very valuable for matching against flow features)
    detection = technique.get("detection", "").strip()
    if detection:
        if len(detection) > 1000:
            detection = detection[:1000] + "..."
        parts.append(f"Detection: {detection}")

    return "\n".join(parts)


def compute_network_relevance(technique: Dict) -> float:
    """Score how relevant a technique is to network-flow observability.

    Techniques that are primarily host-based (e.g., registry modification)
    will score lower, while techniques involving network traffic patterns
    will score higher. This score is used during retrieval to boost
    network-observable techniques.

    Args:
        technique: Parsed technique dict.

    Returns:
        Float in [0, 1] indicating network relevance.
    """
    text = (
        technique.get("description", "").lower()
        + " "
        + technique.get("detection", "").lower()
        + " "
        + technique.get("name", "").lower()
    )

    hits = sum(1 for kw in NETWORK_KEYWORDS if kw in text)
    # Normalise: cap at 8 keyword hits → score 1.0
    return min(hits / 8.0, 1.0)


def build_documents(techniques: List[Dict]) -> List[Dict]:
    """Convert parsed techniques into RAG documents.

    Each document contains:
    - text: searchable passage (for embedding)
    - metadata: technique_id, name, tactics, tactic_ids, platforms,
                is_subtechnique, parent_id, url, network_relevance

    Args:
        techniques: List of technique dicts from stix_loader.

    Returns:
        List of document dicts.
    """
    documents = []

    for tech in techniques:
        text = build_document_text(tech)
        net_rel = compute_network_relevance(tech)

        doc = {
            "text": text,
            "metadata": {
                "technique_id": tech["technique_id"],
                "name": tech["name"],
                "tactics": tech["tactics"],
                "tactic_ids": tech["tactic_ids"],
                "platforms": tech["platforms"],
                "is_subtechnique": tech["is_subtechnique"],
                "parent_id": tech["parent_id"],
                "url": tech.get("url"),
                "network_relevance": round(net_rel, 4),
                "description_snippet": (tech.get("description", "")[:300]
                                        if tech.get("description") else ""),
            },
        }
        documents.append(doc)

    logger.info("[RAG] Built %d documents from techniques", len(documents))
    return documents


def save_documents(documents: List[Dict], dest_dir: Path = PROCESSED_DATA_DIR) -> Path:
    """Persist processed documents to JSON for reproducibility.

    Args:
        documents: List of document dicts.
        dest_dir: Directory to save to.

    Returns:
        Path to the saved JSON file.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    out_path = dest_dir / "mitre_documents.json"

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(documents, f, indent=2, ensure_ascii=False)

    logger.info("[RAG] Saved %d documents to %s", len(documents), out_path)
    return out_path


def load_documents(path: Path = PROCESSED_DATA_DIR / "mitre_documents.json") -> List[Dict]:
    """Load previously processed documents from JSON.

    Args:
        path: Path to the documents JSON file.

    Returns:
        List of document dicts.
    """
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
