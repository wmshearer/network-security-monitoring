"""Tests for src/score_robustness.py's STP score table and CSV output."""

from __future__ import annotations

import csv
import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from score_robustness import ROBUSTNESS_SCORES, build_rows  # noqa: E402

EXPECTED_HEADER = [
    "Name",
    "Analytic Robustness Score",
    "Event Robustness Score",
    "Filter Score",
    "Final Score",
    "Notes",
    "Permalink",
]

REPO_ROOT = Path(__file__).parent.parent


def test_all_six_detections_are_scored():
    names = {d["name"] for d in ROBUSTNESS_SCORES}
    assert names == {
        "D1_registry_run_key_setvalue",
        "D2_schtasks_encoded_powershell",
        "D3_net_localgroup_administrators",
        "D4_net_user_enumeration",
        "D5_process_access_audiodg",
        "D6_powershell_spawns_recon_tool",
    }


def test_every_score_is_in_the_valid_stp_range():
    """STP's Analytic Robustness Score is defined 1-5. A score outside that
    range is a data-entry error, not a judgment call, and must fail."""
    for d in ROBUSTNESS_SCORES:
        assert 1 <= d["analytic_robustness_score"] <= 5, d["name"]


def test_every_event_robustness_score_is_a_valid_kua_letter():
    """All 6 detections read Sysmon (user-mode), so all 6 must be 'U' --
    none of them is K (kernel) or A (application)."""
    for d in ROBUSTNESS_SCORES:
        assert d["event_robustness_score"] in {"K", "U", "A"}, d["name"]
        assert d["event_robustness_score"] == "U", (
            f"{d['name']}: expected U (all 6 detections read Sysmon, "
            "user-mode telemetry), got {d['event_robustness_score']}"
        )


def test_d2_d3_d4_score_lower_than_d1():
    """The literal-string detections (D2-D4) must score below D1 (the
    registry-API-level detection) -- this is the core claim of the whole
    project and must hold numerically, not just in prose."""
    scores = {d["name"]: d["analytic_robustness_score"] for d in ROBUSTNESS_SCORES}
    d1 = scores["D1_registry_run_key_setvalue"]
    for brittle in (
        "D2_schtasks_encoded_powershell",
        "D3_net_localgroup_administrators",
        "D4_net_user_enumeration",
    ):
        assert scores[brittle] < d1, f"{brittle} ({scores[brittle]}) should score below D1 ({d1})"


def test_d2_notes_reference_the_evasion_evidence_file():
    d2 = next(d for d in ROBUSTNESS_SCORES if d["name"] == "D2_schtasks_encoded_powershell")
    assert "evasion_results.json" in d2["notes"]


def test_build_rows_matches_published_stp_csv_header():
    rows = build_rows()
    assert list(rows[0].keys()) == EXPECTED_HEADER


def test_build_rows_permalink_embeds_the_real_spl_text():
    rows = build_rows()
    d2_row = next(r for r in rows if r["Name"] == "D2_schtasks_encoded_powershell")
    spl_path = REPO_ROOT / "evidence/detection_dev/d2_schtasks_encoded_powershell.spl"
    real_spl = spl_path.read_text().strip()
    assert real_spl in d2_row["Permalink"]


def test_csv_writer_round_trips_all_six_rows():
    rows = build_rows()
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=EXPECTED_HEADER)
    writer.writeheader()
    writer.writerows(rows)
    buf.seek(0)
    reader = list(csv.DictReader(buf))
    assert len(reader) == 6
    assert {r["Name"] for r in reader} == {d["name"] for d in ROBUSTNESS_SCORES}
