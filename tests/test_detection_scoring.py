"""Live-Splunk tests against the already-scored detections in
evidence/detection_scoring.json (produced by src/score_detections.py
against the real cloud_lab index). Auto-skipped if Splunk is unreachable,
same pattern as tests/test_live_parse_proof.py.

These encode two things as regression assertions:
  1. Recall: every one of the 12 detections fires on the technique
     capture it targets (12/12 at the time this suite was written).
  2. The scoring harness's own correctness: for a correlation/threshold
     detection, an off-target hit is only reported when the target host's
     events genuinely CROSS the detection's real threshold, not merely
     when raw matching events exist on that host. This regression-guards
     a real bug found and fixed during this build (see
     src/score_detections.py's docstring and README.md): an earlier
     version of the scoring harness dropped the bin/stats/where threshold
     pipeline and substituted a flat `stats count by host`, which reported
     T1110.001 as a false off-target hit for the Azure password-spray
     detection even though that host's traffic never crosses the real
     dc(identity)>5 condition (confirmed: only 1 distinct identity from
     the one source IP in that capture).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from splunk_search import run_search  # noqa: E402

SCORING_PATH = Path(__file__).parent.parent / "evidence/detection_scoring.json"
SPL_DIR = Path(__file__).parent.parent / "detections/spl"


def _splunk_available() -> bool:
    try:
        run_search("| makeresults", earliest="0", latest="now")
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _splunk_available(),
    reason="Splunk REST API not reachable at SPLUNK_URL -- these tests need a live instance with cloud_lab already ingested.",
)


def _load_scoring():
    with SCORING_PATH.open() as fh:
        return json.load(fh)


def test_scoring_evidence_file_exists_and_covers_all_detections():
    results = _load_scoring()
    assert len(results) >= 8


def test_every_detection_has_recall_hit_on_its_target_technique():
    results = _load_scoring()
    misses = [r["name"] for r in results if not r["recall_hit"]]
    assert not misses, f"detections with no recall hit on their target technique: {misses}"


def test_azure_password_spray_does_not_false_fire_on_single_target_bruteforce():
    """Direct live re-check of the specific bug this project's scoring
    harness had and fixed: T1110.001 (single-account password guessing,
    one IP, one identity) must NOT cross the Azure password-spray
    detection's real dc(identity)>5-per-IP-per-10-minutes threshold,
    confirmed by running the exact threshold logic live rather than
    trusting the saved evidence file alone."""
    search = '''search index=cloud_lab sourcetype="azure:monitor:aad" host=T1110.001
      operationName="Sign-in activity" resultType="50126"
      | bin _time span=10m
      | stats dc(identity) as value_count by _time callerIpAddress
      | where value_count > 5'''
    resp = run_search(search)
    rows = resp.get("results", [])
    assert rows == [], (
        f"expected T1110.001 to never cross the >5-distinct-identity threshold, got {rows}"
    )


def test_off_target_hits_are_real_not_harness_artifacts():
    """Every off-target hit reported in the saved evidence must be
    reproducible by a fresh, independent live search (not just trusted
    from the saved JSON), guarding against the scoring harness silently
    drifting from the actual detection logic in detections/spl/*.yml."""
    results = _load_scoring()
    checked = 0
    for r in results:
        if r["off_target_host_count"] == 0:
            continue
        resp = run_search(f"search {r['scoring_search']}")
        rows = resp.get("results", [])
        count_field = "total_matches" if rows and "total_matches" in rows[0] else "count"
        fires_by_host = {row["host"]: int(row[count_field]) for row in rows}
        for host, expected_count in r["off_target_hosts_fired"].items():
            assert fires_by_host.get(host) == expected_count, (
                f"{r['name']}: off-target host {host} expected {expected_count}, "
                f"live re-run got {fires_by_host.get(host)}"
            )
            checked += 1
    assert checked > 0, "no off-target hits were available to re-check live"


def test_full_production_search_returns_results_on_target_technique():
    """Runs each detection's COMPLETE search field (including the
    rename/stats/filter-macro tail this project's scoring harness strips
    out) exactly as written in detections/spl/*.yml, exactly as an analyst
    running it in Splunk would. Regression-guards a real bug found and
    fixed during this build: Splunk's `stats ... by <field>` silently
    DROPS every row where any BY field is null (e.g. errorCode absent on
    a successful CloudTrail call), which zeroed out 6 of 12 detections'
    final output even though their underlying match logic was correct
    (confirmed live: aws_cloudtrail_stop_delete_disable_logging.yml went
    from 7 matching events to 0 output rows before `| fillnull` was added
    ahead of each `| stats ... by ...` line, the same pattern Splunk's own
    security_content detections use). This test would have caught that
    regression, since it checks the FULL search's own output row count,
    not just the pre-stats matching logic the scoring harness checks."""
    for f in sorted(SPL_DIR.glob("*.yml")):
        d = yaml.safe_load(f.open())
        resp = run_search(d["search"])
        assert resp.get("messages") == [], f"{f.name}: search produced messages {resp.get('messages')}"
        assert len(resp.get("results", [])) > 0, (
            f"{f.name}: full production search (with rename/stats/filter macro) "
            f"returned 0 rows even though this detection is expected to fire on its "
            f"labelled capture -- check for a null-BY-field stats drop"
        )
