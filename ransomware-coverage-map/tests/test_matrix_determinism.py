"""Pins the detection-brittleness lesson: the matrix builder must SUM/derive
deterministically from its inputs, never silently ASSIGN in a way that
depends on iteration order or filesystem glob order between runs.

Rebuilds the full pipeline (stages 1, 3, 4) twice from scratch and asserts
the resulting matrix JSON is byte-identical. SKIPped, not failed, if the
source corpora this project reads are not present on this machine (see
conftest-style guard at the top of each test), per the brief's requirement
that an absent corpus produces a SKIP, never a default-to-pass or a
misleading FAIL.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORPUS_ROOT = Path("/home/kali/director/projects/_corpora/attack_data/datasets/malware")
SECURITY_CONTENT_ROOT = Path("/home/kali/director/projects/_corpora/security_content/detections/endpoint")
PY = str(ROOT / ".venv" / "bin" / "python3")

CORPUS_AVAILABLE = CORPUS_ROOT.is_dir() and SECURITY_CONTENT_ROOT.is_dir()
skip_if_no_corpus = pytest.mark.skipif(
    not CORPUS_AVAILABLE,
    reason=f"corpus not found at {CORPUS_ROOT} or {SECURITY_CONTENT_ROOT}; SKIP not FAIL per project rules",
)


def _run_pipeline() -> dict:
    for script in ("01_build_capture_evidence.py", "02_index_detections.py", "03_score_detection_logic.py", "04_build_matrix.py"):
        proc = subprocess.run([PY, str(ROOT / "scripts" / script)], cwd=ROOT, capture_output=True, text=True, timeout=120)
        assert proc.returncode == 0, f"{script} failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    return json.loads((ROOT / "matrix" / "coverage_matrix.json").read_text())


@skip_if_no_corpus
def test_matrix_is_deterministic_across_two_full_rebuilds():
    run_a = _run_pipeline()
    run_b = _run_pipeline()
    assert run_a == run_b, "matrix changed between two identical pipeline runs; a step is non-deterministic (assign-vs-sum bug class)"


@skip_if_no_corpus
def test_state_counts_match_actual_cell_tally():
    """The reported state_counts must be a real tally of the cells dict, not
    a separately-maintained counter that could drift from it."""
    matrix = json.loads((ROOT / "matrix" / "coverage_matrix.json").read_text())
    recomputed = {"GREEN": 0, "RED-LOGIC": 0, "RED-TELEMETRY": 0, "GREY": 0}
    for cell in matrix["cells"].values():
        recomputed[cell["state"]] += 1
    assert recomputed == matrix["state_counts"]
    assert sum(recomputed.values()) == matrix["total_cells"]


@skip_if_no_corpus
def test_every_cell_has_exactly_one_of_the_four_states():
    matrix = json.loads((ROOT / "matrix" / "coverage_matrix.json").read_text())
    allowed = {"GREEN", "RED-LOGIC", "RED-TELEMETRY", "GREY"}
    for key, cell in matrix["cells"].items():
        assert cell["state"] in allowed, f"cell {key} has invalid state {cell['state']!r}"


@skip_if_no_corpus
def test_grey_cells_are_exactly_the_not_present_cells():
    """GREY must mean, and only mean, 'behaviour not observed in this
    capture' -- never a stand-in for an undetermined detection verdict."""
    matrix = json.loads((ROOT / "matrix" / "coverage_matrix.json").read_text())
    for key, cell in matrix["cells"].items():
        if cell["state"] == "GREY":
            assert cell["present_in_capture"] is False, f"{key} is GREY but present_in_capture={cell['present_in_capture']}"
        else:
            assert cell["present_in_capture"] is True, f"{key} is {cell['state']} but present_in_capture={cell['present_in_capture']}"
