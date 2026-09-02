"""
Pytest suite pinning the measured numbers from data/summary.json.

These tests run against the committed summary, not the pcaps
themselves (pcaps are gitignored and regenerable with
scripts/capture.sh + scripts/summarize.py). That means the suite
passes from a fresh clone without root, without a live capture, and
without needing tshark at test time.

If a capture is re-run and a number changes, that's a real result and
these tests are meant to fail loudly so the change gets looked at
before docs/FINDING.md is trusted again.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from compare import diff  # noqa: E402
from grease import is_grease, GREASE_VALUES  # noqa: E402

SUMMARY_PATH = ROOT / "data" / "summary.json"


@pytest.fixture(scope="module")
def summary():
    assert SUMMARY_PATH.exists(), (
        "data/summary.json is missing. Run scripts/summarize.py after "
        "a capture, or check it into the repo as a committed artifact."
    )
    return json.loads(SUMMARY_PATH.read_text())


def ja4_of(summary, label):
    hellos = summary[label]["clienthellos"]
    assert hellos, f"no ClientHello captured for {label}"
    ja4s = {c["ja4"] for c in hellos}
    assert len(ja4s) == 1, f"{label} produced inconsistent JA4 across connections: {ja4s}"
    return next(iter(ja4s))


def ja4_r_of(summary, label):
    hellos = summary[label]["clienthellos"]
    ja4rs = {c["ja4_r"] for c in hellos}
    assert len(ja4rs) == 1
    return next(iter(ja4rs))


def ja3_of(summary, label):
    hellos = summary[label]["clienthellos"]
    return [c["ja3"] for c in hellos]


# ---------------------------------------------------------------------
# Integrity locks: catch a broken query silently returning nothing,
# which would look identical to "no GREASE found" or "clients match".
# ---------------------------------------------------------------------

def test_summary_has_all_expected_clients(summary):
    expected = {
        "firefox", "chromium", "curl", "curl_cffi",
        "python_requests", "python_urllib", "python_ssl_custom",
        "order_a", "order_b",
    }
    missing = expected - set(summary.keys())
    assert not missing, f"missing captures: {missing}"


def test_every_client_has_at_least_one_clienthello(summary):
    # Negative-control style check: an empty capture and a broken
    # tshark filter both produce zero rows. If this ever trips, the
    # capture pipeline is broken, not "GREASE is absent."
    for label, data in summary.items():
        assert len(data["clienthellos"]) >= 1, f"{label}: zero ClientHellos captured"


def test_negative_control_grease_detector_flags_known_grease_value():
    # 0x0a0a is GREASE by RFC 8701. If this fails the detector itself
    # is broken, independent of anything about a captured client.
    assert is_grease(0x0A0A) is True
    assert is_grease(0xFAFA) is True
    assert len(GREASE_VALUES) == 16


def test_negative_control_grease_detector_rejects_real_cipher():
    # 0x1301 is TLS_AES_128_GCM_SHA256, a real TLS 1.3 cipher, not GREASE.
    assert is_grease(0x1301) is False
    assert is_grease(0xC02B) is False


# ---------------------------------------------------------------------
# GREASE hypothesis: does it actually appear in browser captures and
# not in stock Python ones?
# ---------------------------------------------------------------------

def test_chromium_sends_grease(summary):
    assert summary["chromium"]["grease"]["any_grease"] is True


def test_firefox_does_not_send_grease(summary):
    # Measured result, not assumed: Firefox 140.13.0esr on this box did
    # not send GREASE in cipher, extension, or supported-group lists.
    # GREASE is a Chromium-family behavior, not a universal browser one.
    assert summary["firefox"]["grease"]["any_grease"] is False


def test_stock_python_clients_do_not_send_grease(summary):
    for label in ("python_requests", "python_urllib", "python_ssl_custom"):
        assert summary[label]["grease"]["any_grease"] is False, (
            f"{label} unexpectedly sent GREASE"
        )


def test_curl_cffi_impersonation_sends_grease(summary):
    # curl_cffi's chrome impersonation profile should replicate GREASE,
    # since that is part of what a real Chrome ClientHello looks like.
    assert summary["curl_cffi"]["grease"]["any_grease"] is True


# ---------------------------------------------------------------------
# Sorting claim: same cipher SET, different wire order -> identical
# JA4, different JA3.
# ---------------------------------------------------------------------

def test_same_set_different_order_gives_identical_ja4(summary):
    assert ja4_of(summary, "order_a") == ja4_of(summary, "order_b")
    assert ja4_r_of(summary, "order_a") == ja4_r_of(summary, "order_b")


def test_same_set_different_order_gives_different_ja3(summary):
    ja3_a = ja3_of(summary, "order_a")[0]
    ja3_b = ja3_of(summary, "order_b")[0]
    assert ja3_a != ja3_b


# ---------------------------------------------------------------------
# Browser-vs-browser and browser-vs-script comparisons
# ---------------------------------------------------------------------

def test_firefox_and_chromium_produce_different_ja4(summary):
    assert ja4_of(summary, "firefox") != ja4_of(summary, "chromium")


def test_firefox_and_chromium_diff_is_explainable(summary):
    d = diff(ja4_r_of(summary, "firefox"), ja4_r_of(summary, "chromium"))
    assert d, "expected at least one differing component between firefox and chromium"


def test_stock_requests_ja4_could_not_pass_for_a_browser(summary):
    # requests' JA4 must differ from both real browsers captured here.
    req_ja4 = ja4_of(summary, "python_requests")
    assert req_ja4 != ja4_of(summary, "firefox")
    assert req_ja4 != ja4_of(summary, "chromium")


def test_curl_cffi_impersonation_matches_chromium_ja4(summary):
    # This is the strongest evasion result measured in this lab:
    # curl_cffi's chrome impersonation reproduced Chromium's exact
    # raw JA4 on this machine.
    assert ja4_r_of(summary, "curl_cffi") == ja4_r_of(summary, "chromium")


def test_compare_isolates_alpn_as_the_only_diff_between_curl_and_requests(summary):
    d = diff(ja4_r_of(summary, "curl"), ja4_r_of(summary, "python_requests"))
    assert set(d.keys()) == {"alpn"}
    assert d["alpn"]["left"] == "h2"
    assert d["alpn"]["right"] == "h1"
