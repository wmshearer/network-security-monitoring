"""Tests for the manifest parser (scripts/01_parse_manifest.py)."""
import csv
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "data" / "challenges.yml"
CHALLENGES_CSV = ROOT / "evidence" / "manifest" / "challenges_table.csv"
CATEGORY_CSV = ROOT / "evidence" / "manifest" / "category_counts.csv"


def test_manifest_file_present():
    assert MANIFEST.exists(), "data/challenges.yml must be staged before any scoring can run"


def test_parser_runs_and_produces_output():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "01_parse_manifest.py")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert CHALLENGES_CSV.exists()
    assert CATEGORY_CSV.exists()


def test_sixteen_categories():
    with open(CATEGORY_CSV) as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 16, f"expected 16 categories, got {len(rows)}"


def test_top_category_counts_match_ground_truth():
    # These counts were independently verified before any scanning began
    # (see the task brief). If challenges.yml changes upstream, this test
    # should be revisited rather than silently updated.
    expected = {
        "Sensitive Data Exposure": 17,
        "Injection": 14,
        "Improper Input Validation": 12,
        "Broken Access Control": 12,
        "XSS": 9,
        "Vulnerable Components": 9,
    }
    with open(CATEGORY_CSV) as f:
        counts = {row["category"]: int(row["count"]) for row in csv.DictReader(f)}
    for category, count in expected.items():
        assert counts.get(category) == count, f"{category}: expected {count}, got {counts.get(category)}"


def test_every_challenge_has_required_fields():
    with open(CHALLENGES_CSV) as f:
        rows = list(csv.DictReader(f))
    assert len(rows) > 0
    for row in rows:
        assert row["name"], "every challenge must have a name"
        assert row["category"], "every challenge must have a category"
        assert row["key"], "every challenge must have a key"
