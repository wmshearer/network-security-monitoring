"""Tests against the real ir_activemq_lockbit Splunk index. These are live
integration tests, not mocks: they require splunkd running on this host with
the ir_activemq_lockbit index already populated (see src/ingest.sh).

Each assertion here was proven able to fail before being left in this state:
see README.md "Tests" section for the break/observe-fail/fix/observe-pass log
for each one (summarized inline in the docstrings below too).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from splunk_search import result_count  # noqa: E402

INDEX = "index=ir_activemq_lockbit"


def test_total_event_count_matches_known_ingest():
    """Proven able to fail: asserting == 999999 instead of 73512 failed as
    expected (AssertionError: 73512 != 999999) before being corrected to the
    real, measured total."""
    assert result_count(INDEX) == 73512


def test_sysmon_count_matches_raw_file_event_count():
    """Sysmon source count must equal the raw file's <Event count (13462),
    confirmed by grep -c "<Event " on the source file. Proven able to fail:
    temporarily asserting 13000 failed before being corrected."""
    n = result_count(f'{INDEX} source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"')
    assert n == 13462


def test_security_count_matches_raw_file_event_count():
    n = result_count(f'{INDEX} source="XmlWinEventLog:Security"')
    assert n == 16946


def test_powershell_count_is_one_short_of_raw_file_event_count():
    """43105 <Event records exist in the raw source file; 43104 were
    indexed. This is a real, small (1-event, 0.002%), unexplained gap
    documented in README.md "What this cannot claim" -- not fabricated as a
    clean number. The test pins the actual observed value so a future
    re-ingest that silently drops MORE events is caught."""
    n = result_count(f'{INDEX} source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"')
    assert n == 43104


def test_sysmon_eventid_1_process_create_count():
    """Cross-checked against the research brief's independently-verified
    count for this exact dataset (4,044). Proven able to fail: asserting
    4000 failed before correction."""
    n = result_count(
        f'{INDEX} source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1'
    )
    assert n == 4044


def test_no_eventid_10_process_access_in_this_capture():
    """Sysmon ProcessAccess (EventID 10) never occurs in this dataset. This
    is a real, load-bearing negative result: it is why D5 from
    splunk-detection-lab (AUDIODG process-access) and any LSASS-access
    detection both return zero here, documented in README.md and
    evidence/08. Proven able to fail: asserting > 0 failed as expected
    before being corrected to == 0."""
    n = result_count(
        f'{INDEX} source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=10'
    )
    assert n == 0
