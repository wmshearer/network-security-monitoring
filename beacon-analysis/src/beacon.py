"""Detect command-and-control beaconing from connection metadata.

A beacon is malware calling home on a schedule. The detection signal is not
content, which is usually encrypted, but TIMING: a machine talking to the same
destination at suspiciously regular intervals.

The method here follows the published approach used by RITA (Active
Countermeasures, GPL-3.0) and described in Chris Sanders' network security
monitoring work: score each source/destination pair on how machine-like its
timing looks, then require a human to rule out benign explanations.

Implemented directly from the methodology rather than by calling a tool, because
the interesting part is the reasoning, and because Zeek is not installable on
this host (Kali ships 5.1.1, which requires libc6 < 2.38 against an installed
2.42). tshark produces the same connection metadata.

WHAT THIS DOES NOT DO
-------------------------------------------------------------------------------
It does not decide that something is malicious. Regular timing is a property of
enormous amounts of benign software: NTP, telemetry, update checks, keepalives,
monitoring agents. The output is a RANKING of what to look at, and Sanders'
differential-diagnosis point is the whole discipline here: a novice sees a
regular interval and calls it C2, while the actual work is enumerating the
benign explanations and ruling them out one at a time.
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict
from dataclasses import dataclass


@dataclass(frozen=True)
class Connection:
    """One observed connection event, reduced to what timing analysis needs."""

    timestamp: float
    src: str
    dst: str
    dport: int
    bytes_out: int = 0
    bytes_in: int = 0


@dataclass(frozen=True)
class BeaconScore:
    """Timing analysis for one source/destination pair."""

    src: str
    dst: str
    dport: int
    connections: int
    median_interval: float
    interval_mad: float          # median absolute deviation, robust to outliers
    jitter_ratio: float          # MAD / median: 0.0 = perfectly regular
    interval_score: float        # 0..1, higher = more machine-like
    duration_hours: float
    bytes_out_total: int
    bytes_in_total: int

    @property
    def out_in_ratio(self) -> float | None:
        """Bytes sent divided by bytes received.

        A high ratio on a long-lived regular connection is worth a look, since
        exfiltration sends more than it receives. Returns None rather than
        infinity when nothing came back, so callers must handle the case instead
        of silently sorting on a sentinel.
        """
        if self.bytes_in_total == 0:
            return None
        return self.bytes_out_total / self.bytes_in_total

    def as_row(self) -> dict:
        return {
            "src": self.src,
            "dst": self.dst,
            "dport": self.dport,
            "connections": self.connections,
            "median_interval_s": round(self.median_interval, 2),
            "interval_mad_s": round(self.interval_mad, 2),
            "jitter_ratio": round(self.jitter_ratio, 4),
            "interval_score": round(self.interval_score, 4),
            "duration_hours": round(self.duration_hours, 2),
            "bytes_out": self.bytes_out_total,
            "bytes_in": self.bytes_in_total,
        }


def _median_absolute_deviation(values: list[float], median: float) -> float:
    """MAD, not standard deviation.

    Standard deviation is dominated by outliers, and beacon traffic routinely
    has them: the host sleeps, the laptop closes, the network drops. One
    six-hour gap in an otherwise perfect 60-second beacon would wreck a
    stdev-based score while barely moving the MAD.
    """
    if not values:
        return 0.0
    return statistics.median([abs(v - median) for v in values])


def score_pair(conns: list[Connection], min_connections: int = 8) -> BeaconScore | None:
    """Score one src/dst/port group. Returns None if there is too little data.

    `min_connections` exists because three evenly spaced connections is not
    evidence of anything. Any pair of points is perfectly regular by
    definition, and three is barely better. The threshold is stated rather than
    hidden so it can be argued with.
    """
    if len(conns) < min_connections:
        return None

    ordered = sorted(conns, key=lambda c: c.timestamp)
    times = [c.timestamp for c in ordered]
    intervals = [b - a for a, b in zip(times, times[1:])]
    if not intervals:
        return None

    median = statistics.median(intervals)
    if median <= 0:
        return None

    mad = _median_absolute_deviation(intervals, median)
    jitter_ratio = mad / median

    # Map jitter to 0..1 where 1.0 is perfectly regular. exp(-x) rather than a
    # linear scale because the interesting distinction is between "very regular"
    # and "somewhat regular"; everything past roughly 100% jitter is equally
    # uninteresting and should not spread out across the top of the ranking.
    interval_score = math.exp(-jitter_ratio)

    return BeaconScore(
        src=ordered[0].src,
        dst=ordered[0].dst,
        dport=ordered[0].dport,
        connections=len(ordered),
        median_interval=median,
        interval_mad=mad,
        jitter_ratio=jitter_ratio,
        interval_score=interval_score,
        duration_hours=(times[-1] - times[0]) / 3600.0,
        bytes_out_total=sum(c.bytes_out for c in ordered),
        bytes_in_total=sum(c.bytes_in for c in ordered),
    )


def analyze(
    connections: list[Connection],
    min_connections: int = 8,
    group_by_port: bool = True,
) -> list[BeaconScore]:
    """Group connections into pairs and score each one.

    `group_by_port=True` treats the same host pair on different ports as
    separate candidates, since a beacon on 443 and unrelated chatter on 53 are
    different behaviours that should not be averaged into one timing series.
    """
    groups: dict[tuple, list[Connection]] = defaultdict(list)
    for c in connections:
        key = (c.src, c.dst, c.dport) if group_by_port else (c.src, c.dst, 0)
        groups[key].append(c)

    scored = [s for s in (score_pair(g, min_connections) for g in groups.values()) if s]
    # Rank by regularity, then by how long the behaviour persisted. A beacon
    # that ran for eight hours is a stronger candidate than one that ran for
    # eight minutes at the same regularity.
    scored.sort(key=lambda s: (-s.interval_score, -s.duration_hours))
    return scored
