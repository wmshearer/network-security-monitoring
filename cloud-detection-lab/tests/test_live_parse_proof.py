"""Tests against the LIVE Splunk instance and the already-ingested cloud_lab
index. Unlike test_select_cloud_files.py, these need a running Splunk with
the data already loaded (src/select_cloud_files.py then src/ingest_cloud_lab.py
already run) -- skipped automatically if Splunk is unreachable, so the suite
does not hard-fail in an environment where Splunk is not running, but DOES
fail loudly if Splunk is up and the parse is actually wrong.

These encode the exact real numbers this project measured and saved to
evidence/*.json (see README.md's parse-proof section) as regression
assertions: if a future config change breaks the timestamp parsing or the
CIM field aliases, these tests catch it rather than requiring a human to
notice a wrong number in a search result.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from splunk_search import run_search  # noqa: E402


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


def _stat_count(result: dict, field: str) -> int:
    rows = result.get("results", [])
    if not rows:
        return 0
    return int(rows[0].get(field, 0))


def test_cloud_lab_index_has_events_for_all_three_sourcetypes():
    result = run_search('index=cloud_lab | stats count by sourcetype')
    sourcetypes = {row["sourcetype"] for row in result.get("results", [])}
    assert sourcetypes == {"aws:cloudtrail", "azure:monitor:aad", "o365:management:activity"}


def test_cloudtrail_timestamp_matches_event_field_for_every_event():
    """The CloudTrail TIME_FORMAT (%Z against a literal "Z") must parse
    every single event's eventTime into _time with zero drift -- this is
    the exact check that proved %Z works on this Splunk build, contradicting
    the research brief's caution that it might not."""
    result = run_search(
        'index=cloud_lab sourcetype="aws:cloudtrail" '
        '| eval et=mvindex(eventTime,0) '
        '| eval event_epoch=strptime(et."+0000","%Y-%m-%dT%H:%M:%SZ%z") '
        '| eval diff_seconds=_time-event_epoch '
        '| stats count by diff_seconds'
    )
    rows = result.get("results", [])
    assert len(rows) == 1, f"expected every event to have the same (zero) diff_seconds, got {rows}"
    assert float(rows[0]["diff_seconds"]) == 0.0


def test_azure_seven_digit_fractional_timestamp_parses_correctly():
    """This is the specific claim the research brief flagged as NOT yet
    empirically confirmed: does %7Q actually parse a 7-digit fractional
    second on this Splunk build. Confirmed: 719 of 724 ingested Azure events
    match exactly; the other 5 come from 2 files using a genuinely different
    non-ISO timestamp shape (documented in props.conf and README.md), not a
    %7Q parsing failure."""
    result = run_search(
        'index=cloud_lab sourcetype="azure:monitor:aad" '
        '| eval t=mvindex(time,0) '
        '| eval event_epoch=strptime(t,"%Y-%m-%dT%H:%M:%S.%7QZ") '
        '| eval matched=if(round(_time-event_epoch,3)=0, 1, 0) '
        '| stats count as total, sum(matched) as matched_count'
    )
    total = _stat_count(result, "total")
    matched = _stat_count(result, "matched_count")
    assert total > 0
    # At least 99% should match the 7-digit fractional format; the known
    # 5-event exception (2 files with a "M/D/YYYY h:mm:ss AM/PM" shape) is
    # documented, not silently tolerated without a floor.
    assert matched / total >= 0.99, f"only {matched}/{total} Azure events matched the 7-digit fractional TIME_FORMAT"


def test_eventtype_collision_is_real_and_extracted_eventtype_is_the_working_substitute():
    """Proves the documented eventType/eventtype collision directly against
    live data: eventType (the field INDEXED_EXTRACTIONS should have produced)
    is unpopulated for every event, while extracted_eventType (search-time
    JSON auto-extraction of the same raw key) is populated for every event."""
    result = run_search(
        'index=cloud_lab sourcetype="aws:cloudtrail" '
        '| stats count as total, count(eventType) as eventType_populated, '
        'count(extracted_eventType) as extracted_eventType_populated'
    )
    total = _stat_count(result, "total")
    event_type_populated = _stat_count(result, "eventType_populated")
    extracted_populated = _stat_count(result, "extracted_eventType_populated")
    assert total > 0
    assert event_type_populated == 0, "eventType is populated -- the collision this project documented may no longer be real, update README.md"
    assert extracted_populated == total, "extracted_eventType is not populated for every event -- the documented substitute is not actually working"


def test_cloudtrail_cim_user_field_is_populated_for_most_events():
    """FIELDALIAS-cim_change_user (userIdentity.arn AS user) must actually
    fire. This is the test that would have caught the app-scoped knowledge
    object bug found during this project's own build (FIELDALIAS silently
    did not apply until metadata/local.meta set export=system)."""
    result = run_search(
        'index=cloud_lab sourcetype="aws:cloudtrail" '
        '| stats count as total, count(user) as user_populated'
    )
    total = _stat_count(result, "total")
    populated = _stat_count(result, "user_populated")
    assert total > 0
    assert populated / total > 0.99, f"only {populated}/{total} CloudTrail events have a populated CIM user field"
