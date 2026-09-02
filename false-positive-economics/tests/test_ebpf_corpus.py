"""Tests for the second-corpus figures pulled from ebpf-container-detection.

SKIP (never FAIL) when that project's evidence/analysis.json is absent.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from common import EBPF_ANALYSIS_JSON, load_ebpf_analysis  # noqa: E402

pytestmark = pytest.mark.skipif(
    not EBPF_ANALYSIS_JSON.exists(),
    reason=f"source project file not found: {EBPF_ANALYSIS_JSON} (ebpf-container-detection absent)",
)


def test_capability_probe_false_positive_totals():
    d = load_ebpf_analysis()
    fp = d["false_positive_measurement"]
    assert fp["benign_capability_total_events"] == 12841
    assert fp["benign_capability_from_cpptools_or_gdb"] == 1393
    assert fp["benign_capability_from_other_processes"] == 11448


def test_cpptools_gdb_plus_other_equals_total():
    d = load_ebpf_analysis()
    fp = d["false_positive_measurement"]
    assert fp["benign_capability_from_cpptools_or_gdb"] + fp["benign_capability_from_other_processes"] == (
        fp["benign_capability_total_events"]
    )


def test_other_four_probes_produced_zero_false_positives():
    d = load_ebpf_analysis()
    fp = d["false_positive_measurement"]
    assert fp["benign_namespace_events"] == 0
    assert fp["benign_mount_events"] == 0
    assert fp["benign_ptrace_events"] == 0
    assert fp["benign_sensitive_write_events"] == 0
