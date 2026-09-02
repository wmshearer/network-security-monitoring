"""
Verify the rubric CSV is internally consistent, and that this project's own
numbered scripts reproduce the same counts when run.
"""
import csv
import json
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CALLS = PROJECT_ROOT / "rubric" / "calls.csv"
SECURITY_CONTENT = Path("/home/kali/director/projects/_corpora/security_content")

VALID_CLASSES = {"incident-bound", "behavioral", "mixed"}


def test_calls_csv_exists_and_has_29_rows():
    if not CALLS.exists():
        pytest.skip("rubric/calls.csv not found")
    rows = list(csv.DictReader(open(CALLS)))
    assert len(rows) == 29


def test_every_row_has_a_valid_class_and_nonempty_reason():
    if not CALLS.exists():
        pytest.skip("rubric/calls.csv not found")
    rows = list(csv.DictReader(open(CALLS)))
    for r in rows:
        assert r["class"] in VALID_CLASSES, f"{r['file']} has invalid class {r['class']!r}"
        assert r["reason"].strip(), f"{r['file']} has an empty reason"
        assert r["search_fragment_basis"].strip(), f"{r['file']} cites no search fragment"


@pytest.mark.skipif(not SECURITY_CONTENT.exists(), reason="security_content corpus not present")
def test_every_row_references_a_real_file_in_the_corpus():
    if not CALLS.exists():
        pytest.skip("rubric/calls.csv not found")
    rows = list(csv.DictReader(open(CALLS)))
    for r in rows:
        full = SECURITY_CONTENT / r["file"]
        assert full.exists(), f"rubric references missing file: {r['file']}"


@pytest.mark.skipif(not SECURITY_CONTENT.exists(), reason="security_content corpus not present")
def test_script_01_reproduces_29_detections():
    script = PROJECT_ROOT / "scripts" / "01_collect_t1195_detections.py"
    if not script.exists():
        pytest.skip("script not found")
    subprocess.run([sys.executable, str(script)], check=True, cwd=PROJECT_ROOT)
    out = PROJECT_ROOT / "evidence" / "01_t1195_detections.json"
    data = json.loads(out.read_text())
    assert len(data) == 29


@pytest.mark.skipif(not SECURITY_CONTENT.exists(), reason="security_content corpus not present")
def test_script_02_confirms_zero_xz_and_codecov_hits():
    script = PROJECT_ROOT / "scripts" / "02_verify_absences_and_licenses.py"
    if not script.exists():
        pytest.skip("script not found")
    subprocess.run([sys.executable, str(script)], check=True, cwd=PROJECT_ROOT)
    out = PROJECT_ROOT / "evidence" / "02_absences_and_licenses.json"
    data = json.loads(out.read_text())
    assert data["security_content_xz_hits"] == []
    assert data["security_content_codecov_hits"] == []
    assert data["security_content_license"]["is_apache2"] is True


def test_script_03_tally_matches_rubric():
    script = PROJECT_ROOT / "scripts" / "03_tally_classification.py"
    if not script.exists() or not CALLS.exists():
        pytest.skip("script or rubric not found")
    subprocess.run([sys.executable, str(script)], check=True, cwd=PROJECT_ROOT)
    out = PROJECT_ROOT / "evidence" / "03_classification_tally.json"
    data = json.loads(out.read_text())
    rows = list(csv.DictReader(open(CALLS)))
    from collections import Counter
    expected = Counter(r["class"] for r in rows)
    assert data["incident_bound"] == expected.get("incident-bound", 0)
    assert data["behavioral"] == expected.get("behavioral", 0)
    assert data["total_detections"] == len(rows)


@pytest.mark.skipif(not Path("/home/kali/director/projects/_corpora/attack_data").exists(),
                     reason="attack_data corpus not present")
def test_script_04_replay_shows_cross_incident_zero_match():
    script = PROJECT_ROOT / "scripts" / "04_replay_detections_against_telemetry.py"
    if not script.exists():
        pytest.skip("script not found")
    subprocess.run([sys.executable, str(script)], check=True, cwd=PROJECT_ROOT,
                    capture_output=True)
    out = PROJECT_ROOT / "evidence" / "04_replay_results.json"
    data = json.loads(out.read_text())
    by_dataset = {(r["dataset"], r["detection"]): r for r in data if not r.get("skipped")}
    # Shai-Hulud detection fires on its own incident, not on 3CX's.
    own = [r for r in data if r.get("dataset", "").startswith("npm (Shai-Hulud")]
    other = [r for r in data if r.get("dataset", "").startswith("3CX (a different")]
    assert own and own[0]["fires"] is True
    assert other and other[0]["fires"] is False
