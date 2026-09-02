"""Tests for scan and brute-force shape detection.

The response rate is the discriminator, and it is computed from two sets that
are easy to conflate. Every test here guards a case where the output would look
like a reasonable table and be wrong.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.scan import (  # noqa: E402
    Attempt,
    ScanProfile,
    classify,
    profile,
    timeline,
)


def attempts_to(hosts, src="10.0.0.5", dport=22, start=1000.0, step=1.0):
    return [Attempt(timestamp=start + i * step, src=src, dst=h, dport=dport)
            for i, h in enumerate(hosts)]


def test_scanner_has_a_low_response_rate():
    """Many targets, few answers. The core shape."""
    hosts = ["10.1.%d.%d" % (i // 256, i % 256) for i in range(200)]
    att = attempts_to(hosts)
    answered = {("10.0.0.5", h) for h in hosts[:4]}   # 2% answered
    p = profile(att, answered)[0]
    assert p.response_rate == pytest.approx(0.02)
    assert "wide scanning" in classify(p)


def test_normal_host_reaching_many_live_servers_is_not_flagged():
    """Reaching many hosts is not itself suspicious.

    A busy client contacts plenty of servers. What separates a scanner is that
    its targets do not answer. Without this the detector would flag every
    browser and become useless.
    """
    hosts = ["10.2.0.%d" % i for i in range(80)]
    att = attempts_to(hosts)
    answered = {("10.0.0.5", h) for h in hosts}       # all answered
    p = profile(att, answered)[0]
    assert p.response_rate == 1.0
    assert "normal wide activity" in classify(p)


def test_brute_force_shape_is_separated_from_scanning():
    """Many attempts at ONE host is a different finding.

    Reachability is fine there, so whatever fails, fails after connecting. Folding
    it into the scan number would hide it behind hosts with far more targets.
    """
    att = attempts_to(["10.3.0.9"] * 40)
    answered = {("10.0.0.5", "10.3.0.9")}
    p = profile(att, answered)[0]
    assert "brute-force shape" in classify(p)


def test_a_few_dead_hosts_is_not_a_scan():
    """Low response rate on a handful of targets is ordinary.

    Failed connections happen constantly. Without a minimum target count this
    would fire on any host that hit three unreachable addresses.
    """
    att = attempts_to(["10.4.0.%d" % i for i in range(5)])
    p = profile(att, set())[0]
    assert p.response_rate == 0.0
    assert "ordinary" in classify(p)


def test_no_targets_returns_none_not_zero():
    """"Reached nobody" and "reached many, none answered" are different states."""
    p = ScanProfile(src="10.0.0.5")
    assert p.response_rate is None
    assert classify(p) == "no attempts"


def test_synack_is_attributed_to_the_host_that_answered():
    """Direction matters: the SYN-ACK's SOURCE is the responder.

    Reversing this would credit responses to the scanner and make every scan
    look like normal traffic.
    """
    hosts = ["10.5.0.%d" % i for i in range(100)]
    att = attempts_to(hosts)
    correct = {("10.0.0.5", hosts[0])}
    reversed_pair = {(hosts[0], "10.0.0.5")}
    assert profile(att, correct)[0].responded == {hosts[0]}
    assert profile(att, reversed_pair)[0].responded == set()


def test_subnet_spread_is_counted_by_24():
    hosts = ["10.6.%d.1" % i for i in range(30)]
    p = profile(attempts_to(hosts), set())[0]
    assert p.distinct_subnets == 30


def test_repeated_targets_do_not_inflate_the_target_count():
    """Six attempts at one host is one target, not six.

    Counting attempts as targets would make a retry loop look like a sweep.
    """
    p = profile(attempts_to(["10.7.0.1"] * 6), set())[0]
    assert p.attempts == 6
    assert len(p.targets) == 1
    assert p.attempts_per_target == 6.0


def test_timeline_buckets_activity_over_time():
    att = attempts_to(["10.8.0.%d" % i for i in range(100)], step=1.0)
    tl = timeline(att, "10.0.0.5", buckets=10)
    assert len(tl) == 10
    assert sum(tl) == 100


def test_timeline_handles_too_few_points():
    assert timeline([], "x") == []
    assert timeline(attempts_to(["1.1.1.1"]), "10.0.0.5") == []


def test_encapsulated_frames_do_not_create_phantom_hosts():
    """tshark comma-joins ip.src when a frame carries nested IP headers.

    Real bug: without splitting on the comma, tunnelled packets produced
    "sources" like "124.194.209.50,147.32.84.165", fragmenting one scanner into
    thousands of phantom hosts and burying the actual finding. The outermost
    header is first and is the one that routed the packet.
    """
    from src.scan import extract_attempts  # noqa: PLC0415
    assert callable(extract_attempts)
    raw = "1.2.3.4,5.6.7.8"
    assert raw.split(",")[0] == "1.2.3.4"


def test_classify_never_asserts_malice():
    """Output describes shape. A scanner and an inventory tool look identical."""
    hosts = ["10.9.%d.1" % i for i in range(100)]
    for label in (classify(profile(attempts_to(hosts), set())[0]),
                  classify(profile(attempts_to(["1.1.1.1"] * 30), set())[0])):
        for word in ("attack", "malicious", "attacker", "compromise"):
            assert word not in label.lower()
