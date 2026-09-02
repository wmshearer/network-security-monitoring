"""Tests for the beacon threshold study.

These cover the two places this analysis actually went wrong, plus the arithmetic
the findings rest on. The row-matching tests are the important ones: both bugs
they guard against produced plausible numbers rather than errors, which is why
they went unnoticed until the counts were checked against the raw logs.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import analyze  # noqa: E402


# --- row matching ---------------------------------------------------------
# RITA reports a destination either as an address in "Destination IP" or, for
# rows it tied to a hostname, as "::" there with the real value in "FQDN".

def test_matches_beacon_reported_by_ip():
    rows = [{"Source IP": "192.168.2.77", "Destination IP": "143.198.3.13", "FQDN": ""}]
    assert len(analyze.find_beacon_rows(rows)) == 1


def test_matches_beacon_reported_by_hostname():
    """The first bug: this row was invisible to a Destination IP match."""
    rows = [{"Source IP": "192.168.2.77", "Destination IP": "::", "FQDN": "143.198.3.13"}]
    assert len(analyze.find_beacon_rows(rows)) == 1


def test_matches_redirector_hostnames():
    """The second bug: redirector legs are reported under cover names."""
    rows = [
        {"Source IP": "192.168.2.77", "Destination IP": "::", "FQDN": "timeserversync.com"},
        {"Source IP": "192.168.2.77", "Destination IP": "::", "FQDN": "weathersync.cloud"},
    ]
    assert len(analyze.find_beacon_rows(rows)) == 2


def test_ignores_other_traffic_from_the_beacon_host():
    """The failure mode that made wrong numbers look right.

    When the matcher missed the beacon it fell through to whatever else that
    host was talking to and reported those scores as the beacon's.
    """
    rows = [
        {"Source IP": "192.168.2.77", "Destination IP": "::", "FQDN": "edge.microsoft.com"},
        {"Source IP": "192.168.2.77", "Destination IP": "52.226.139.180", "FQDN": ""},
    ]
    assert analyze.find_beacon_rows(rows) == []


def test_ignores_other_hosts():
    rows = [{"Source IP": "192.168.2.19", "Destination IP": "::", "FQDN": "143.198.3.13"}]
    assert analyze.find_beacon_rows(rows) == []


def test_returns_empty_rather_than_substituting_a_top_row():
    """A missed detection has to report as a miss, not as the next best row."""
    rows = [
        {"Source IP": "192.168.2.19", "Destination IP": "::", "FQDN": "connectivity-check.ubuntu.com"},
    ]
    assert analyze.find_beacon_rows(rows) == []


# --- helpers --------------------------------------------------------------

@pytest.mark.parametrize("ip", ["192.168.2.77", "10.0.0.1", "172.16.5.5", "172.31.0.1"])
def test_internal_addresses(ip):
    assert analyze.is_internal(ip)


@pytest.mark.parametrize("ip", ["143.198.3.13", "8.8.8.8", "172.32.0.1", "172.15.0.1"])
def test_external_addresses(ip):
    assert not analyze.is_internal(ip)


@pytest.mark.parametrize("ip", ["224.0.0.251", "239.255.255.250", "255.255.255.255"])
def test_multicast_is_not_a_c2_candidate(ip):
    """The beacon host also emits SSDP and mDNS. Neither is a destination."""
    assert not analyze.is_routable_external(ip)


def test_config_parsing():
    assert analyze.parse_config("jit_var_d30_j99_24H") == (30, 99, "24H", "direct")
    assert analyze.parse_config("delay_var_d300_j25_1H") == (300, 25, "1H", "direct")
    assert analyze.parse_config("round_rob_d30_j25_24H")[3] == "round-robin redirector"
    assert analyze.parse_config("random_d30_j0_1H")[3] == "random redirector"


def test_config_parsing_rejects_unparseable_names():
    with pytest.raises(ValueError):
        analyze.parse_config("not-a-capture-name")


def test_to_float_survives_missing_values():
    assert analyze.to_float("") == 0.0
    assert analyze.to_float(None) == 0.0
    assert analyze.to_float("0.496") == pytest.approx(0.496)


# --- the findings ---------------------------------------------------------

WARMUP = ROOT / "data" / "warmup.json"


@pytest.fixture(scope="module")
def warmup():
    if not WARMUP.is_file():
        pytest.skip("warmup.json not generated; run scripts/warmup.py")
    return json.loads(WARMUP.read_text())


def test_composite_is_the_mean_of_four_subscores(warmup):
    """RITA's documented formula, checked against its own stored output.

    This is what rules out the score being adjusted by threat-intel or
    prevalence modifiers, which was the leading alternative explanation for
    the numbers below.
    """
    for name, ds in warmup.items():
        for hour in ds["hours"]:
            expected = (hour["ts"] + hour["ds"] + hour["dur"] + hour["hist"]) / 4
            assert hour["score"] == pytest.approx(expected, abs=0.001), name


def test_perfect_timing_does_not_produce_a_perfect_score(warmup):
    """The finding. Flawless timing, lowest composite score in the grid."""
    hour1 = warmup["jit_d30_j0_24h"]["hours"][0]
    assert hour1["ts"] == 1.0
    assert hour1["score"] == pytest.approx(0.5, abs=0.001)
    assert hour1["dur"] == 0.0
    assert hour1["hist"] == 0.0


def test_regular_beacon_needs_hours_to_reach_the_alerting_band(warmup):
    ds = warmup["jit_d30_j0_24h"]
    assert ds["first_hour_low"] == 5
    assert ds["first_hour_medium"] == 6


def test_jittered_beacons_alert_immediately(warmup):
    """The comparison that makes the result counterintuitive."""
    for name in ("jit_d30_j10_24h", "delay_d30_j25_24h"):
        assert warmup[name]["first_hour_medium"] == 1, name


def test_every_configuration_is_eventually_detected(warmup):
    """The negative result: no jitter level defeats the detector outright."""
    for name, ds in warmup.items():
        assert ds["first_hour_low"] is not None, name
        best = max(h["score"] for h in ds["hours"])
        assert best * 100 >= 70, name
