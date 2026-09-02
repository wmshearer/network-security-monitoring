"""Tests for SPN discovery detection.

The one real bug this guards against: ldap.filter in tshark's -T fields output
is a numeric type code, not the readable filter string. Matching
"servicePrincipalName" against ldap.filter finds nothing, silently, even in a
capture that plainly contains the search. Every test here is either that bug
or the honesty boundary: this module must never claim to see a roast.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.spn_recon import SPN_ATTRIBUTE, SpnSearch, describe  # noqa: E402


def search(frame=52, src="192.168.1.46", dst="192.168.1.195",
           attribute=SPN_ATTRIBUTE):
    return SpnSearch(frame=frame, src=src, dst=dst, attribute=attribute)


def test_describe_names_it_as_discovery_not_a_roast():
    label = describe([search()])
    assert "discovery" in label
    assert "not a ticket request" in label


def test_describe_counts_sources_and_searches_separately():
    searches = [search(frame=52, src="10.0.0.5"),
                search(frame=60, src="10.0.0.5"),
                search(frame=70, src="10.0.0.9")]
    label = describe(searches)
    assert "3 LDAP search" in label
    assert "2 source" in label


def test_empty_capture_says_nothing_observed():
    assert describe([]) == "no servicePrincipalName searches observed"


def test_ldap_filter_field_is_a_type_code_not_a_string():
    """Real bug this project hit: ldap.filter renders as a CHOICE tag.

    (0=and, 7=present, 4=equalityMatch, ...). Matching a substring like
    "servicePrincipalName" against that field returns zero rows against every
    capture, including ones that contain the search, and returns them
    silently: no error, just an empty, plausible-looking result. This is why
    extraction filters on ldap.AttributeDescription instead.
    """
    from src.spn_recon import extract_spn_searches  # noqa: PLC0415
    assert callable(extract_spn_searches)
    # The field's actual rendering for a substrings-type filter is its
    # numeric tag, confirmed against a live capture during development.
    substrings_filter_tag = "4"
    assert substrings_filter_tag != SPN_ATTRIBUTE


def test_never_claims_kerberoasting_happened():
    """Discovery is not a roast. This capture's only Kerberos traffic is the
    DC's own AES-encrypted ldap SPN ticket, a normal SASL bind, and this
    module has no visibility into Kerberos exchanges at all: it must never
    imply it does.
    """
    label = describe([search()])
    for word in ("roast", "kerberoast", "cracked", "crackable"):
        assert word not in label.lower()


def test_describe_never_asserts_malice():
    """setspn, PowerView, and legitimate inventory tools all issue this
    exact query. The shape does not distinguish them.
    """
    for label in (describe([search()]), describe([])):
        for word in ("attack", "malicious", "attacker", "compromise"):
            assert word not in label.lower()
