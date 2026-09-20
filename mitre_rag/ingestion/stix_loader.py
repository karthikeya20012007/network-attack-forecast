"""
MITRE ATT&CK STIX data loader.

Downloads the official MITRE ATT&CK Enterprise STIX bundle from GitHub
and parses it into a list of technique dictionaries.

The raw JSON is cached locally so it only needs to be downloaded once.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional
from urllib.request import urlretrieve

from mitre_rag.config import RAW_DATA_DIR, STIX_URL, STIX_FILENAME

logger = logging.getLogger(__name__)


def download_stix_bundle(
    url: str = STIX_URL,
    dest_dir: Path = RAW_DATA_DIR,
    filename: str = STIX_FILENAME,
    force: bool = False,
) -> Path:
    """Download the MITRE ATT&CK Enterprise STIX bundle if not already cached.

    Args:
        url: URL of the STIX JSON bundle.
        dest_dir: Directory to save the downloaded file.
        filename: Name for the saved file.
        force: Re-download even if the file already exists.

    Returns:
        Path to the downloaded JSON file.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / filename

    if dest_path.exists() and not force:
        logger.info("[RAG] STIX bundle already cached at %s", dest_path)
        return dest_path

    logger.info("[RAG] Downloading MITRE ATT&CK STIX bundle from %s ...", url)
    urlretrieve(url, dest_path)
    logger.info("[RAG] Saved STIX bundle to %s (%.1f MB)",
                dest_path, dest_path.stat().st_size / 1_048_576)
    return dest_path


def load_stix_bundle(path: Path) -> dict:
    """Load a STIX bundle JSON file.

    Args:
        path: Path to the STIX JSON file.

    Returns:
        Parsed STIX bundle as a dictionary.
    """
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _extract_tactic_names(kill_chain_phases: list) -> List[str]:
    """Extract MITRE ATT&CK tactic short-names from kill_chain_phases."""
    return [
        phase["phase_name"]
        for phase in kill_chain_phases
        if phase.get("kill_chain_name") == "mitre-attack"
    ]


def _extract_tactic_ids(kill_chain_phases: list) -> List[str]:
    """Map tactic short-names to tactic IDs using the standard mapping."""
    tactic_name_to_id = {
        "reconnaissance": "TA0043",
        "resource-development": "TA0042",
        "initial-access": "TA0001",
        "execution": "TA0002",
        "persistence": "TA0003",
        "privilege-escalation": "TA0004",
        "defense-evasion": "TA0005",
        "credential-access": "TA0006",
        "discovery": "TA0007",
        "lateral-movement": "TA0008",
        "collection": "TA0009",
        "command-and-control": "TA0011",
        "exfiltration": "TA0010",
        "impact": "TA0040",
    }
    names = _extract_tactic_names(kill_chain_phases)
    return [tactic_name_to_id[n] for n in names if n in tactic_name_to_id]


def _get_external_id(external_references: list) -> Optional[str]:
    """Extract the technique ID (e.g., T1021.002) from external references."""
    for ref in external_references:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _get_url(external_references: list) -> Optional[str]:
    """Extract the MITRE ATT&CK URL from external references."""
    for ref in external_references:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")
    return None


def parse_techniques(bundle: dict) -> List[Dict]:
    """Parse STIX bundle into a flat list of technique dictionaries.

    Filters out:
    - Non-attack-pattern objects
    - Revoked techniques (x_mitre_is_revoked = True)
    - Deprecated techniques (x_mitre_deprecated = True)

    Returns:
        List of dicts with keys: technique_id, name, description, tactics,
        tactic_ids, platforms, detection, url, is_subtechnique, parent_id.
    """
    techniques = []

    for obj in bundle.get("objects", []):
        # Only process attack-pattern objects
        if obj.get("type") != "attack-pattern":
            continue

        # Skip revoked techniques
        if obj.get("x_mitre_is_revoked", False):
            continue

        # Skip deprecated techniques
        if obj.get("x_mitre_deprecated", False):
            continue

        ext_refs = obj.get("external_references", [])
        technique_id = _get_external_id(ext_refs)
        if not technique_id:
            continue

        kill_chain = obj.get("kill_chain_phases", [])
        tactic_names = _extract_tactic_names(kill_chain)
        tactic_ids = _extract_tactic_ids(kill_chain)

        # Determine if this is a sub-technique
        is_sub = obj.get("x_mitre_is_subtechnique", False)
        parent_id = None
        if is_sub and "." in technique_id:
            parent_id = technique_id.split(".")[0]

        techniques.append({
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactics": tactic_names,
            "tactic_ids": tactic_ids,
            "platforms": obj.get("x_mitre_platforms", []),
            "detection": obj.get("x_mitre_detection", ""),
            "url": _get_url(ext_refs),
            "is_subtechnique": is_sub,
            "parent_id": parent_id,
        })

    logger.info("[RAG] Parsed %d active techniques (excluded revoked/deprecated)",
                len(techniques))
    return techniques


def load_and_parse(
    url: str = STIX_URL,
    dest_dir: Path = RAW_DATA_DIR,
    force_download: bool = False,
) -> List[Dict]:
    """End-to-end: download (if needed), load, and parse STIX data.

    Args:
        url: STIX bundle URL.
        dest_dir: Directory for cached downloads.
        force_download: Re-download even if cached.

    Returns:
        List of parsed technique dictionaries.
    """
    path = download_stix_bundle(url, dest_dir, force=force_download)
    bundle = load_stix_bundle(path)
    return parse_techniques(bundle)
