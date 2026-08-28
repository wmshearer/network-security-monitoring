"""Tests for the scoring pipeline (scripts/06_score_alerts.py) and its inputs.

SKIP (not FAIL) when a scan output file is absent, since these tests exercise
committed evidence rather than a live container.
"""
import csv
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ZAP_UNAUTH = ROOT / "evidence" / "zap-unauth" / "zap-unauth-alerts-api.json"
ZAP_AUTH = ROOT / "evidence" / "zap-auth" / "zap-auth-alerts-api.json"
NUCLEI = ROOT / "evidence" / "nuclei" / "nuclei-results.jsonl"
COVERAGE_CSV = ROOT / "evidence" / "scoring" / "coverage_by_category.csv"
MAPPING_CSV = ROOT / "evidence" / "scoring" / "alert_mapping.csv"


def _skip_if_missing(path: Path):
    if not path.exists():
        pytest.skip(f"{path} not present (scan was not run in this environment)")


def test_zap_unauth_evidence_present_or_skip():
    _skip_if_missing(ZAP_UNAUTH)
    d = json.loads(ZAP_UNAUTH.read_text())
    assert "alerts" in d
    assert len(d["alerts"]) > 0


def test_zap_auth_evidence_present_or_skip():
    _skip_if_missing(ZAP_AUTH)
    d = json.loads(ZAP_AUTH.read_text())
    assert "alerts" in d


def test_zap_auth_and_unauth_same_alert_types():
    _skip_if_missing(ZAP_UNAUTH)
    _skip_if_missing(ZAP_AUTH)
    unauth = json.loads(ZAP_UNAUTH.read_text())
    auth = json.loads(ZAP_AUTH.read_text())
    unauth_names = sorted(set(a["alert"] for a in unauth["alerts"]))
    auth_names = sorted(set(a["alert"] for a in auth["alerts"]))
    # This is the actual measured result, not an assumption: recorded here so
    # a future scan run that finds something new is caught, not silently lost.
    assert unauth_names == auth_names, (
        f"expected identical alert types (measured result), got unauth={unauth_names} auth={auth_names}"
    )


def test_nuclei_evidence_present_or_skip():
    _skip_if_missing(NUCLEI)
    lines = NUCLEI.read_text().strip().splitlines()
    assert len(lines) > 0


def test_scoring_script_runs():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "06_score_alerts.py")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert COVERAGE_CSV.exists()
    assert MAPPING_CSV.exists()


def test_coverage_totals_match_manifest():
    _skip_if_missing(COVERAGE_CSV)
    manifest_csv = ROOT / "evidence" / "manifest" / "challenges_table.csv"
    _skip_if_missing(manifest_csv)
    with open(manifest_csv) as f:
        manifest_total = len(list(csv.DictReader(f)))
    with open(COVERAGE_CSV) as f:
        rows = list(csv.DictReader(f))
    coverage_total = sum(int(r["total_challenges"]) for r in rows)
    assert coverage_total == manifest_total


def test_every_mapped_key_exists_in_manifest():
    _skip_if_missing(MAPPING_CSV)
    manifest_csv = ROOT / "evidence" / "manifest" / "challenges_table.csv"
    _skip_if_missing(manifest_csv)
    with open(manifest_csv) as f:
        valid_keys = {row["key"] for row in csv.DictReader(f)}
    with open(MAPPING_CSV) as f:
        for row in csv.DictReader(f):
            if row["mapped_challenge_key"]:
                assert row["mapped_challenge_key"] in valid_keys, (
                    f"{row['mapped_challenge_key']} is not a real challenge key"
                )
