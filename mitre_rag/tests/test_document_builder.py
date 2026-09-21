"""
Unit tests for document builder module (mitre_rag.processing.document_builder).
"""

import json
from pathlib import Path
import pytest

from mitre_rag.processing.document_builder import (
    build_document_text,
    compute_network_relevance,
    build_documents,
    save_documents,
    load_documents,
)


@pytest.fixture
def sample_techniques():
    return [
        {
            "technique_id": "T1498",
            "name": "Network Denial of Service",
            "description": "Adversaries may perform Network Denial of Service (DoS) attacks by flooding targets with network traffic and packets to consume bandwidth.",
            "tactics": ["impact"],
            "tactic_ids": ["TA0040"],
            "platforms": ["Network"],
            "detection": "Monitor network traffic for sudden spikes in packet rates and flow volumes.",
            "url": "https://attack.mitre.org/techniques/T1498",
            "is_subtechnique": False,
            "parent_id": None,
        },
        {
            "technique_id": "T1112",
            "name": "Modify Registry",
            "description": "Adversaries may interact with the Windows registry to hide configuration data or evade detection.",
            "tactics": ["defense-evasion"],
            "tactic_ids": ["TA0005"],
            "platforms": ["Windows"],
            "detection": "Monitor Windows Registry for changes to keys and values.",
            "url": "https://attack.mitre.org/techniques/T1112",
            "is_subtechnique": False,
            "parent_id": None,
        },
    ]


def test_build_document_text(sample_techniques):
    tech = sample_techniques[0]
    text = build_document_text(tech)

    assert "MITRE ATT&CK Technique T1498: Network Denial of Service" in text
    assert "Tactics: impact" in text
    assert "Tactic IDs: TA0040" in text
    assert "Platforms: Network" in text
    assert "Description:" in text
    assert "flooding targets with network traffic" in text
    assert "Detection:" in text


def test_build_document_text_truncation():
    tech = {
        "technique_id": "T9999",
        "name": "Long Technique",
        "description": "A" * 3000,
        "tactics": [],
        "tactic_ids": [],
        "platforms": [],
        "detection": "B" * 2000,
        "url": None,
        "is_subtechnique": False,
        "parent_id": None,
    }
    text = build_document_text(tech)
    assert len(text) < 4000
    assert "..." in text


def test_compute_network_relevance(sample_techniques):
    dos_tech = sample_techniques[0]
    registry_tech = sample_techniques[1]

    dos_rel = compute_network_relevance(dos_tech)
    reg_rel = compute_network_relevance(registry_tech)

    # DoS mentions network, traffic, packet, flood, dos, bandwidth, flow
    assert dos_rel > 0.5
    # Registry has no network keywords
    assert reg_rel < 0.2
    assert dos_rel > reg_rel


def test_build_documents(sample_techniques):
    docs = build_documents(sample_techniques)
    assert len(docs) == 2

    d0 = docs[0]
    assert "text" in d0
    assert "metadata" in d0
    meta = d0["metadata"]
    assert meta["technique_id"] == "T1498"
    assert meta["name"] == "Network Denial of Service"
    assert meta["network_relevance"] > 0.5
    assert meta["description_snippet"].startswith("Adversaries may perform")


def test_save_and_load_documents(sample_techniques, tmp_path):
    docs = build_documents(sample_techniques)
    out_file = save_documents(docs, dest_dir=tmp_path)

    assert out_file.exists()
    loaded = load_documents(out_file)
    assert len(loaded) == 2
    assert loaded[0]["metadata"]["technique_id"] == "T1498"
    assert loaded[1]["metadata"]["technique_id"] == "T1112"
