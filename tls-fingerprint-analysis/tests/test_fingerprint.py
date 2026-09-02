"""Tests for TLS fingerprint parsing and profiling.

The risk here is quiet wrongness. A fingerprint parsed slightly wrong still
looks like a fingerprint, still groups, still produces a plausible table. Every
test below guards a case where the output would look fine and be wrong.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.fingerprint import (  # noqa: E402
    ClientProfile,
    Hello,
    find_sni_mismatches,
    group_by_destination,
    profile_clients,
)

# Real shapes: 'd' = SNI sent, 'i' = no SNI.
BROWSER = "t13d1516h2_8daaf6152771_b186095e22b6"
NO_SNI = "t10i110100_3609b414f052_bc98f8e001b5"


def hello(ja4=BROWSER, src="10.0.0.5", dst="93.184.216.34", sni="example.com",
          ts=1000.0, dport=443):
    return Hello(timestamp=ts, src=src, dst=dst, dport=dport,
                 ja4=ja4, ja3="abc123", sni=sni)


def test_tls_version_is_decoded_from_the_fingerprint():
    assert ClientProfile(ja4=BROWSER).tls_version == "TLS 1.3"
    assert ClientProfile(ja4=NO_SNI).tls_version == "TLS 1.0"


def test_unknown_version_code_does_not_crash():
    """An unparseable fingerprint must degrade, not raise.

    Captures contain malformed and truncated handshakes. One bad record should
    not take down analysis of the other thousands.
    """
    assert ClientProfile(ja4="xx").tls_version in ("", "unknown", "x")
    assert ClientProfile(ja4="").tls_version == "unknown"


def test_sni_presence_is_read_from_the_fingerprint_not_the_field():
    """The 'd'/'i' marker is the fingerprint's own claim about SNI."""
    assert ClientProfile(ja4=BROWSER).sends_sni is True
    assert ClientProfile(ja4=NO_SNI).sends_sni is False


def test_mismatch_between_fingerprint_and_sni_field_is_surfaced():
    """If the two disagree, the parse is unsafe and must be reported.

    Silently trusting either field would mean publishing a conclusion drawn
    from data the parser itself could not agree on.
    """
    consistent = [hello(ja4=BROWSER, sni="example.com"),
                  hello(ja4=NO_SNI, sni="")]
    assert find_sni_mismatches(consistent) == []

    inconsistent = [hello(ja4=NO_SNI, sni="example.com")]
    assert len(find_sni_mismatches(inconsistent)) == 1


def test_profiles_aggregate_counts_and_endpoints():
    hellos = [
        hello(dst="1.1.1.1", sni="a.com"),
        hello(dst="2.2.2.2", sni="b.com"),
        hello(dst="1.1.1.1", sni="a.com"),
    ]
    profiles = profile_clients(hellos)
    assert len(profiles) == 1
    p = profiles[0]
    assert p.count == 3
    assert p.fanout == 2
    assert p.server_names["a.com"] == 2


def test_profiles_are_sorted_by_frequency():
    hellos = [hello(ja4=BROWSER)] * 5 + [hello(ja4=NO_SNI, sni="")] * 2
    profiles = profile_clients(hellos)
    assert profiles[0].ja4 == BROWSER
    assert profiles[0].count == 5


def test_distinct_fingerprints_do_not_merge():
    """Two different clients must stay separate.

    Merging them would erase the entire signal: the point is that different
    software negotiates differently.
    """
    profiles = profile_clients([hello(ja4=BROWSER), hello(ja4=NO_SNI, sni="")])
    assert len(profiles) == 2


def test_fanout_counts_distinct_destinations_not_connections():
    """Ten connections to one host is fanout 1, not 10.

    Fanout is meant to separate a browser (many servers) from a client with one
    job (one server, repeatedly). Counting connections would collapse that.
    """
    hellos = [hello(dst="1.1.1.1") for _ in range(10)]
    assert profile_clients(hellos)[0].fanout == 1


def test_group_by_destination_maps_servers_to_clients():
    hellos = [
        hello(ja4=BROWSER, dst="1.1.1.1"),
        hello(ja4=NO_SNI, dst="1.1.1.1", sni=""),
        hello(ja4=BROWSER, dst="2.2.2.2"),
    ]
    g = group_by_destination(hellos)
    assert g["1.1.1.1"] == {BROWSER, NO_SNI}
    assert g["2.2.2.2"] == {BROWSER}


def test_hello_has_sni_is_false_for_empty_string():
    assert hello(sni="").has_sni is False
    assert hello(sni="example.com").has_sni is True


def test_ports_are_tracked_per_profile():
    """TLS on a non-443 port is worth seeing in the output."""
    hellos = [hello(dport=443), hello(dport=443), hello(dport=8443)]
    p = profile_clients(hellos)[0]
    assert p.ports[443] == 2
    assert p.ports[8443] == 1
