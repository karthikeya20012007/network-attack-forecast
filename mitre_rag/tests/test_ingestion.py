"""
Unit tests for STIX data ingestion module (mitre_rag.ingestion.stix_loader).
"""

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from mitre_rag.ingestion.stix_loader import (
    _extract_tactic_names,
    _extract_tactic_ids,
    _get_external_id,
    _get_url,
    parse_techniques,
    download_stix_bundle,
    load_stix_bundle,
)


@pytest.fixture
def sample_stix_bundle():
    """Create a minimal STIX bundle with valid, revoked, and deprecated techniques."""
    return {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            # 1. Valid technique
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Network Denial of Service",
                "description": "Adversaries may perform Network Denial of Service (DoS) attacks...",
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "impact"}
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1498",
                        "url": "https://attack.mitre.org/techniques/T1498",
                    }
                ],
                "x_mitre_platforms": ["Network"],
                "x_mitre_detection": "Monitor network traffic for anomalous volumetric spikes.",
                "x_mitre_is_subtechnique": False,
            },
            # 2. Valid sub-technique
            {
                "type": "attack-pattern",
                "id": "attack-pattern--2",
                "name": "Direct Network Flood",
                "description": "Adversaries may use direct volumetric floods...",
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "impact"}
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1498.001",
                        "url": "https://attack.mitre.org/techniques/T1498/001",
                    }
                ],
                "x_mitre_platforms": ["Network"],
                "x_mitre_detection": "Detect high packet rates.",
                "x_mitre_is_subtechnique": True,
            },
            # 3. Revoked technique (should be skipped)
            {
                "type": "attack-pattern",
                "id": "attack-pattern--3",
                "name": "Old Revoked Technique",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T9999"}
                ],
                "x_mitre_is_revoked": True,
            },
            # 4. Deprecated technique (should be skipped)
            {
                "type": "attack-pattern",
                "id": "attack-pattern--4",
                "name": "Old Deprecated Technique",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T9998"}
                ],
                "x_mitre_deprecated": True,
            },
            # 5. Non-attack-pattern object (malware, should be skipped)
            {
                "type": "malware",
                "id": "malware--1",
                "name": "TestMalware",
            },
        ],
    }


def test_extract_tactic_names():
    phases = [
        {"kill_chain_name": "mitre-attack", "phase_name": "impact"},
        {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"},
        {"kill_chain_name": "other-chain", "phase_name": "reconnaissance"},
    ]
    names = _extract_tactic_names(phases)
    assert names == ["impact", "initial-access"]


def test_extract_tactic_ids():
    phases = [
        {"kill_chain_name": "mitre-attack", "phase_name": "impact"},
        {"kill_chain_name": "mitre-attack", "phase_name": "lateral-movement"},
        {"kill_chain_name": "mitre-attack", "phase_name": "unknown-phase"},
    ]
    ids = _extract_tactic_ids(phases)
    assert ids == ["TA0040", "TA0008"]


def test_get_external_id():
    refs = [
        {"source_name": "cve", "external_id": "CVE-2021-1234"},
        {"source_name": "mitre-attack", "external_id": "T1046"},
    ]
    assert _get_external_id(refs) == "T1046"
    assert _get_external_id([]) is None


def test_get_url():
    refs = [
        {"source_name": "mitre-attack", "url": "https://attack.mitre.org/techniques/T1046"}
    ]
    assert _get_url(refs) == "https://attack.mitre.org/techniques/T1046"
    assert _get_url([]) is None


def test_parse_techniques(sample_stix_bundle):
    techniques = parse_techniques(sample_stix_bundle)

    # Should only contain the 2 valid techniques
    assert len(techniques) == 2

    # Check primary technique
    t1 = techniques[0]
    assert t1["technique_id"] == "T1498"
    assert t1["name"] == "Network Denial of Service"
    assert t1["tactics"] == ["impact"]
    assert t1["tactic_ids"] == ["TA0040"]
    assert t1["is_subtechnique"] is False
    assert t1["parent_id"] is None
    assert t1["url"] == "https://attack.mitre.org/techniques/T1498"

    # Check sub-technique
    t2 = techniques[1]
    assert t2["technique_id"] == "T1498.001"
    assert t2["is_subtechnique"] is True
    assert t2["parent_id"] == "T1498"


def test_download_stix_bundle_cached(tmp_path):
    cached_file = tmp_path / "enterprise-attack.json"
    cached_file.write_text('{"type": "bundle"}', encoding="utf-8")

    with patch("mitre_rag.ingestion.stix_loader.urlretrieve") as mock_urlretrieve:
        result_path = download_stix_bundle(
            url="http://fake.url/bundle.json",
            dest_dir=tmp_path,
            filename="enterprise-attack.json",
            force=False,
        )
        assert result_path == cached_file
        mock_urlretrieve.assert_not_called()


def test_load_stix_bundle(tmp_path):
    bundle_data = {"type": "bundle", "id": "test"}
    file_path = tmp_path / "test_bundle.json"
    file_path.write_text(json.dumps(bundle_data), encoding="utf-8")

    loaded = load_stix_bundle(file_path)
    assert loaded == bundle_data
