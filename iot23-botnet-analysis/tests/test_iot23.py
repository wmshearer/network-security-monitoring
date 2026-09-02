"""Tests for the IoT-23 label reading and rule scoring.

The numbers here are measured from the three real scenarios. Two things must not
drift: the label reader has to give the same counts whether a file is tab-formatted
(Mirai) or space-packed (Torii, benign), and the scoring has to keep showing that a
rule perfect on one family fails on another. That failure is the point of the
project, so a test guards it.
"""

from __future__ import annotations

from src.labels import Connection
from src.classify import (
    C2, DDOS, SCAN, BENIGN, UNLABELLED,
    rule_label, truth_behaviour, score_behaviour,
)


def conn(proto="tcp", port="6667", label="Malicious", detail="C&C"):
    return Connection(proto=proto, resp_port=port, label=label, detail=detail)


# --- the rules ---

def test_irc_port_reads_as_c2():
    assert rule_label(conn(proto="tcp", port="6667")) == C2


def test_tcp_80_reads_as_ddos():
    assert rule_label(conn(proto="tcp", port="80")) == DDOS


def test_scan_port_reads_as_scan():
    assert rule_label(conn(proto="tcp", port="63798")) == SCAN


def test_ordinary_traffic_gets_no_label():
    """A benign NTP connection matches no rule, on purpose."""
    assert rule_label(conn(proto="udp", port="123", label="Benign", detail="-")) == UNLABELLED


# --- ground-truth mapping across the two label formats ---

def test_torii_c2_detail_maps_to_c2():
    """Torii writes its C&C as 'C&C-Torii'. It must still count as C2 truth."""
    c = conn(proto="tcp", port="443", label="Malicious", detail="C&C-Torii")
    assert truth_behaviour(c) == C2


def test_benign_maps_to_benign():
    c = conn(proto="udp", port="123", label="Benign", detail="-")
    assert truth_behaviour(c) == BENIGN


# --- the scoring, and the failure it must keep showing ---

def test_rule_is_perfect_on_the_family_it_came_from():
    """On Mirai-shaped C&C traffic (IRC 6667), the rule catches all of it."""
    conns = [conn(proto="tcp", port="6667") for _ in range(10)]
    s = score_behaviour(conns, C2)
    assert s.precision == 1.0
    assert s.recall == 1.0


def test_rule_misses_a_family_that_uses_a_different_port():
    """Torii C&C is not on 6667, so the IRC rule finds none of it.

    This is the load-bearing test. A rule that scores 1.0 on the family it was
    written from can score 0.0 on another. If this ever passes by catching Torii,
    the project's central point has been lost.
    """
    torii_c2 = [conn(proto="tcp", port="443", label="Malicious", detail="C&C-Torii")
                for _ in range(16)]
    s = score_behaviour(torii_c2, C2)
    assert s.true_positives == 0
    assert s.recall == 0.0


def test_benign_web_traffic_is_a_false_positive_for_the_ddos_rule():
    """A benign device talking to port 80 trips the naive DDoS rule.

    The false positive is real and the writeup states it. The test keeps it visible
    so nobody 'fixes' the number by pretending benign web traffic does not exist.
    """
    benign_web = [conn(proto="tcp", port="80", label="Benign", detail="-")
                  for _ in range(54)]
    s = score_behaviour(benign_web, DDOS)
    assert s.false_positives == 54
    assert s.true_positives == 0
