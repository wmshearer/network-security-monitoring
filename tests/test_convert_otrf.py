"""Tests for src/convert_otrf.py's ATT&CK ground-truth extraction.

Covers `technique_from_metadata` (the function responsible for turning an
OTRF metadata YAML's `attack_mappings` block into the technique_id string
every detection is scored against) -- a bug here would silently corrupt
ground truth for every downstream score, so it is tested directly against
both a sub-technique and a no-sub-technique shape (both occur in the real
metadata: T1547.001 has a sub-technique, T1123 does not -- see
data/raw/otrf/metadata/*.yaml).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from convert_otrf import technique_from_metadata  # noqa: E402


def test_technique_with_subtechnique_joins_with_a_dot():
    meta = {
        "id": "SDWIN-190319023812",
        "attack_mappings": [
            {"technique": "T1547", "sub-technique": "001", "tactics": ["TA0003"]}
        ],
    }
    technique_id, technique_base, tactics = technique_from_metadata(meta)
    assert technique_id == "T1547.001"
    assert technique_base == "T1547"
    assert tactics == ["TA0003"]


def test_technique_without_subtechnique_has_no_trailing_dot():
    """T1123 (msf_record_mic) has sub-technique: (empty) in the real YAML --
    the resulting technique_id must be the bare technique, not "T1123." with
    a dangling separator."""
    meta = {
        "id": "SDWIN-200609225055",
        "attack_mappings": [{"technique": "T1123", "sub-technique": None, "tactics": ["TA0009"]}],
    }
    technique_id, technique_base, tactics = technique_from_metadata(meta)
    assert technique_id == "T1123"
    assert technique_base == "T1123"


def test_missing_attack_mappings_raises_rather_than_fabricating_ground_truth():
    """No attack_mappings at all must be a loud error -- silently proceeding
    with an empty/guessed technique_id would be exactly the kind of
    fabricated ground truth the task's constraints forbid."""
    with pytest.raises(ValueError, match="no attack_mappings"):
        technique_from_metadata({"id": "SDWIN-000000000000", "attack_mappings": []})


def test_uses_first_mapping_when_multiple_present():
    meta = {
        "id": "SDWIN-XXXX",
        "attack_mappings": [
            {"technique": "T1087", "sub-technique": "001", "tactics": ["TA0007"]},
            {"technique": "T1069", "sub-technique": "001", "tactics": ["TA0007"]},
        ],
    }
    technique_id, technique_base, tactics = technique_from_metadata(meta)
    assert technique_id == "T1087.001"
