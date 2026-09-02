"""Tests for src/leak_audit.py.

Two layers: synthetic-frame tests for the overlap logic itself (always
run), and real-data tests that measure the actual dataset's client-IP
disjointness (skipped if the CSVs haven't been downloaded, since they're
~800MB and gitignored, see data/README.md).
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from src.leak_audit import KNOWN_DOH_RESOLVERS, client_ips, ip_overlap_report

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _frame(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(rows)


# --- synthetic logic tests, always run -----------------------------------


def test_client_ips_excludes_known_resolvers():
    frame = _frame(
        [
            {"SourceIP": "192.168.1.5", "DestinationIP": "1.1.1.1"},
            {"SourceIP": "8.8.8.8", "DestinationIP": "192.168.1.5"},
        ]
    )
    assert client_ips(frame) == {"192.168.1.5"}


def test_client_ips_keeps_unknown_public_ip():
    frame = _frame([{"SourceIP": "203.0.113.9", "DestinationIP": "1.1.1.1"}])
    assert client_ips(frame) == {"203.0.113.9"}


def test_ip_overlap_report_finds_no_overlap_for_disjoint_groups():
    frame = _frame(
        [
            {"SourceIP": "192.168.1.5", "DestinationIP": "1.1.1.1", "Label": "Benign"},
            {"SourceIP": "192.168.2.9", "DestinationIP": "1.1.1.1", "Label": "Malicious"},
        ]
    )
    report = ip_overlap_report(frame, "Label")
    assert report["overlaps"] == []


def test_ip_overlap_report_finds_overlap_when_present():
    frame = _frame(
        [
            {"SourceIP": "192.168.1.5", "DestinationIP": "1.1.1.1", "Label": "Benign"},
            {"SourceIP": "192.168.1.5", "DestinationIP": "1.1.1.1", "Label": "Malicious"},
        ]
    )
    report = ip_overlap_report(frame, "Label")
    assert len(report["overlaps"]) == 1
    group_a, group_b, shared = report["overlaps"][0]
    assert {group_a, group_b} == {"Benign", "Malicious"}
    assert shared == ["192.168.1.5"]


def test_known_doh_resolvers_are_all_valid_looking_ipv4():
    for ip in KNOWN_DOH_RESOLVERS:
        parts = ip.split(".")
        assert len(parts) == 4
        assert all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


# --- real-data tests, skipped if the CSVs aren't present -------------------


def _load_l2() -> pd.DataFrame:
    path = DATA_DIR / "l2-total-add.csv"
    if not path.exists():
        pytest.skip(f"{path} not present; see data/README.md to fetch the dataset")
    df = pd.read_csv(path)
    df.columns = [c.strip().lstrip("﻿") for c in df.columns]
    return df


def test_real_dataset_client_ips_are_disjoint_between_benign_and_malicious():
    """The empirical basis for this whole project's methodology: benign and
    malicious DoH flows must come from non-overlapping client IP ranges, or
    the identity-feature leak this project is built around doesn't exist.
    """
    l2 = _load_l2()
    report = ip_overlap_report(l2, "Label")
    assert report["overlaps"] == [], (
        f"expected disjoint client IPs between Benign and Malicious, found overlap: "
        f"{report['overlaps']}"
    )


def test_real_dataset_resolver_ips_do_appear_on_both_sides():
    """Sanity check on KNOWN_DOH_RESOLVERS itself: if this ever fails, the
    resolver list is stale (or wrong) and the disjoint-IP test above would
    be passing for the wrong reason (excluding an IP that isn't actually a
    shared resolver).
    """
    l2 = _load_l2()
    benign_ips = set(l2[l2["Label"] == "Benign"]["SourceIP"]) | set(
        l2[l2["Label"] == "Benign"]["DestinationIP"]
    )
    malicious_ips = set(l2[l2["Label"] == "Malicious"]["SourceIP"]) | set(
        l2[l2["Label"] == "Malicious"]["DestinationIP"]
    )
    raw_overlap = benign_ips & malicious_ips
    assert raw_overlap, "expected some raw IP overlap from shared public resolvers"
    assert raw_overlap <= KNOWN_DOH_RESOLVERS, (
        f"raw IP overlap includes addresses not in KNOWN_DOH_RESOLVERS: "
        f"{raw_overlap - KNOWN_DOH_RESOLVERS}"
    )
