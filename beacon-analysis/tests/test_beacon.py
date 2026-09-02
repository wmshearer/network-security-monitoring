"""Tests for beacon timing analysis.

Every test here guards a property that would produce a plausible-but-wrong
ranking if it broke. A beacon detector that silently mis-scores does not crash,
it just puts the wrong thing at the top of the list, and a human then spends
their day on it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.beacon import Connection, analyze, score_pair  # noqa: E402


def series(intervals, src="10.0.0.5", dst="203.0.113.9", dport=443, start=1000.0,
           bytes_out=100, bytes_in=100):
    """Build connections spaced by the given intervals."""
    conns, t = [], start
    for gap in intervals:
        t += gap
        conns.append(Connection(timestamp=t, src=src, dst=dst, dport=dport,
                                bytes_out=bytes_out, bytes_in=bytes_in))
    return conns


def test_perfect_beacon_scores_near_one():
    """Identical intervals means zero jitter means the maximum score."""
    s = score_pair(series([60] * 20))
    assert s is not None
    assert s.jitter_ratio == pytest.approx(0.0)
    assert s.interval_score == pytest.approx(1.0)
    assert s.median_interval == pytest.approx(60.0)


def test_irregular_traffic_scores_lower_than_a_beacon():
    """The ordering is the product. Human browsing must not outrank a beacon."""
    beacon = score_pair(series([60, 61, 59, 60, 62, 58, 60, 61, 60, 59]))
    human = score_pair(series([3, 47, 2, 190, 8, 640, 15, 4, 320, 61]))
    assert beacon.interval_score > human.interval_score


def test_one_long_gap_does_not_destroy_the_score():
    """The reason MAD is used instead of standard deviation.

    A beacon that ran every 60s, went quiet for six hours (host asleep), then
    resumed is still a beacon. Standard deviation would be wrecked by that one
    outlier.

    MAD is robust enough that the gap is INVISIBLE here: with 19 of 20 intervals
    identical, the median deviation stays exactly 0. That is a deliberate
    property and a documented limitation, not an accident. Robustness to
    outliers and sensitivity to them are the same dial. This detector is tuned
    to keep finding a beacon through interruptions, which means it will not
    flag "regular except for one strange gap" as unusual. A different question
    would need a different statistic.
    """
    clean = score_pair(series([60] * 20))
    gapped = score_pair(series([60] * 10 + [21600] + [60] * 10))
    assert clean.interval_score == pytest.approx(1.0)
    assert gapped.interval_score == pytest.approx(1.0)
    # The gap IS still visible in duration, which is why duration is reported
    # alongside the score rather than folded into it.
    assert gapped.duration_hours > clean.duration_hours


def test_sustained_irregularity_is_penalized_even_though_one_outlier_is_not():
    """The counterpart to the test above: MAD ignores one outlier, not many.

    Without this, "robust to outliers" would be indistinguishable from "ignores
    everything", and the score would be meaningless.
    """
    clean = score_pair(series([60] * 20))
    messy = score_pair(series([60, 300, 45, 900, 30, 600, 90, 15, 450, 75,
                               120, 800, 20, 350, 65, 700, 40, 250, 85, 500]))
    assert messy.interval_score < 0.6
    assert messy.interval_score < clean.interval_score


def test_too_few_connections_returns_none():
    """Three evenly spaced points is not evidence.

    Any two points are perfectly regular by definition. Scoring tiny samples
    would fill the top of the ranking with noise.
    """
    assert score_pair(series([60, 60, 60])) is None
    assert score_pair(series([60] * 7), min_connections=8) is None
    assert score_pair(series([60] * 8), min_connections=8) is not None


def test_pairs_are_grouped_by_port_so_behaviours_do_not_merge():
    """Same hosts on different ports are different behaviours.

    Averaging a 443 beacon together with unrelated DNS chatter would smear both
    timing series into one meaningless interval.
    """
    conns = series([60] * 10, dport=443) + series([7, 300, 12, 90, 4, 200, 33, 8, 150, 61], dport=53)
    scores = analyze(conns, min_connections=8)
    assert len(scores) == 2
    assert {s.dport for s in scores} == {443, 53}
    assert scores[0].dport == 443  # the regular one ranks first


def test_ranking_prefers_longer_running_behaviour_at_equal_regularity():
    long_run = series([60] * 40, dst="203.0.113.1")
    short_run = series([60] * 10, dst="203.0.113.2")
    scores = analyze(long_run + short_run, min_connections=8)
    assert scores[0].dst == "203.0.113.1"
    assert scores[0].duration_hours > scores[1].duration_hours


def test_out_in_ratio_is_none_when_nothing_came_back():
    """Must not be infinity or a sentinel.

    A caller sorting on this field would put every one-way flow at the top if
    it silently returned a large number.
    """
    s = score_pair(series([60] * 10, bytes_out=500, bytes_in=0))
    assert s.out_in_ratio is None


def test_out_in_ratio_computes_when_traffic_is_bidirectional():
    s = score_pair(series([60] * 10, bytes_out=1000, bytes_in=100))
    assert s.out_in_ratio == pytest.approx(10.0)


def test_zero_or_negative_median_interval_is_rejected():
    """Simultaneous timestamps must not divide by zero."""
    conns = [Connection(timestamp=1000.0, src="a", dst="b", dport=443) for _ in range(10)]
    assert score_pair(conns) is None


def test_duration_is_reported_in_hours():
    """N connections span N-1 intervals, so 10 hourly connections cover 9 hours.

    The helper advances the clock before appending, so the first connection sits
    one interval in. Duration is last-minus-first, which is the correct span of
    OBSERVED behaviour rather than the number of gaps.
    """
    s = score_pair(series([3600] * 10))
    assert s.duration_hours == pytest.approx(9.0)


def test_jitter_ratio_is_relative_not_absolute():
    """A 5s wobble on a 60s beacon is noisy; on an hourly one it is nothing.

    Scoring absolute deviation would rank all slow beacons above all fast ones
    regardless of how regular either actually is.
    """
    fast = score_pair(series([60, 65, 55, 60, 65, 55, 60, 65, 55, 60]))
    slow = score_pair(series([3600, 3605, 3595, 3600, 3605, 3595, 3600, 3605, 3595, 3600]))
    assert slow.interval_score > fast.interval_score
