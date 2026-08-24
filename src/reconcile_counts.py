#!/usr/bin/env python3
"""Reconciles the Phase 2 good-vs-naive sourcetype comparison numbers.

The core claim this project makes is precise, not just directional: the
naive sourcetype's low event count is fully explained by line-merging, with
no unaccounted-for event loss. This script does that arithmetic and is the
thing tests/test_reconcile_counts.py actually exercises -- everything else
in this project is Splunk conf files and SPL, which pytest cannot run
against a live server as a unit test.

Usage (requires a running Splunk reachable via splunk_search.run_search,
see that module's env vars):
    python3 src/reconcile_counts.py
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from splunk_search import run_search


@dataclass
class Reconciliation:
    source_lines: int
    good_events: int
    naive_events: int
    naive_total_newlines_within_events: int

    @property
    def good_events_match_source_lines(self) -> bool:
        return self.good_events == self.source_lines

    @property
    def naive_lines_accounted_for(self) -> int:
        """Every naive "event" is 1 source line plus however many extra
        source lines got merged into it. naive_events (the final count)
        plus the newlines counted *within* those merged events should sum
        back to source_lines exactly, with zero left unexplained."""
        return self.naive_events + self.naive_total_newlines_within_events

    @property
    def naive_reconciles_exactly(self) -> bool:
        return self.naive_lines_accounted_for == self.source_lines

    @property
    def naive_unaccounted_lines(self) -> int:
        """Non-zero here would mean some source lines were neither indexed
        as their own event NOR merged into one that was -- true data loss,
        not just merging. This project's actual measured result is 0; the
        field exists so a future re-run that finds otherwise is caught
        rather than silently reported as a clean match."""
        return self.source_lines - self.naive_lines_accounted_for


def get_reconciliation(source_lines: int = 22085) -> Reconciliation:
    good = run_search(
        'index=ingest_lab sourcetype="ingest_lab:security:json" | stats count'
    )
    naive = run_search(
        'index=ingest_lab_naive sourcetype="ingest_lab:security:json_naive" | stats count'
    )
    naive_newlines = run_search(
        'index=ingest_lab_naive | eval n=mvcount(split(_raw,"\n"))-1 | stats sum(n) as total'
    )

    def _count(result: dict, field: str) -> int:
        rows = result.get("results", [])
        if not rows:
            return 0
        return int(rows[0].get(field, 0))

    return Reconciliation(
        source_lines=source_lines,
        good_events=_count(good, "count"),
        naive_events=_count(naive, "count"),
        naive_total_newlines_within_events=_count(naive_newlines, "total"),
    )


def main() -> int:
    r = get_reconciliation()
    print(f"source lines:              {r.source_lines}")
    print(f"good sourcetype events:    {r.good_events} (matches source lines: {r.good_events_match_source_lines})")
    print(f"naive sourcetype events:   {r.naive_events}")
    print(f"newlines merged in:        {r.naive_total_newlines_within_events}")
    print(f"naive lines accounted for: {r.naive_lines_accounted_for}")
    print(f"unaccounted (should be 0): {r.naive_unaccounted_lines}")
    print(f"naive reconciles exactly:  {r.naive_reconciles_exactly}")
    return 0 if r.good_events_match_source_lines and r.naive_reconciles_exactly else 1


if __name__ == "__main__":
    raise SystemExit(main())
