"""Tests for src/reconcile_counts.py's pure Reconciliation arithmetic.

Deliberately does NOT hit the live Splunk REST API -- these tests exercise
the reconciliation math (does the naive sourcetype's low event count fully
explain itself via merged lines, with zero left unaccounted for) against
hand-built counts, independent of whether a Splunk instance happens to be
running. Same pattern as splunk-detection-lab/tests/test_scoring.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from reconcile_counts import Reconciliation  # noqa: E402


def test_good_sourcetype_matches_source_lines_exactly():
    r = Reconciliation(
        source_lines=22085,
        good_events=22085,
        naive_events=345,
        naive_total_newlines_within_events=21740,
    )
    assert r.good_events_match_source_lines is True


def test_good_sourcetype_flags_mismatch():
    r = Reconciliation(
        source_lines=22085,
        good_events=22080,  # 5 events short -- would indicate a real problem
        naive_events=345,
        naive_total_newlines_within_events=21740,
    )
    assert r.good_events_match_source_lines is False


def test_naive_reconciles_exactly_this_projects_actual_measured_numbers():
    """These are the real numbers measured in evidence/event_counts_good_vs_naive.json
    and evidence/naive_merged_lines_sample.json -- not invented. 345 final
    events + 21740 merged-in newlines == 22085 source lines exactly."""
    r = Reconciliation(
        source_lines=22085,
        good_events=22085,
        naive_events=345,
        naive_total_newlines_within_events=21740,
    )
    assert r.naive_lines_accounted_for == 22085
    assert r.naive_unaccounted_lines == 0
    assert r.naive_reconciles_exactly is True


def test_naive_reconciliation_catches_true_data_loss():
    """If some source lines were neither indexed as their own event NOR
    merged into a surviving one -- real data loss, not just merging --
    naive_unaccounted_lines must be non-zero so a future re-run that hits
    this is caught rather than silently reported as a clean match."""
    r = Reconciliation(
        source_lines=22085,
        good_events=22085,
        naive_events=300,
        naive_total_newlines_within_events=21740,  # short of 22085 - 300
    )
    assert r.naive_unaccounted_lines == 45
    assert r.naive_reconciles_exactly is False


def test_zero_naive_events_is_not_falsely_reconciled():
    r = Reconciliation(
        source_lines=100,
        good_events=100,
        naive_events=0,
        naive_total_newlines_within_events=0,
    )
    assert r.naive_reconciles_exactly is False
    assert r.naive_unaccounted_lines == 100
