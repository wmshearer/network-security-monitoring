"""Tests for DCSync (DsGetNCChanges from a non-DC) detection.

The whole detector is one membership check: is the source of a DsGetNCChanges
call in the known-DC set. Every test here guards a way that check can go
quietly wrong: the wrong opnum, the wrong direction, an empty capture, or a
legitimate DC being flagged for doing its actual job.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.dcsync import (  # noqa: E402
    DSGETNCCHANGES_OPNUM,
    ReplicationCall,
    classify,
    flag_non_dc_replication,
)

DC = "192.168.1.195"
CLIENT = "192.168.1.46"
OTHER_DC = "192.168.1.196"
KNOWN_DCS = frozenset({DC})


def call(opnum, src=CLIENT, dst=DC, frame=1):
    return ReplicationCall(frame=frame, src=src, dst=dst, opnum=opnum)


def test_dsgetncchanges_from_a_non_dc_is_flagged():
    """The core case: a client, not a DC, pulling directory replication data."""
    calls = [call(DSGETNCCHANGES_OPNUM, src=CLIENT, dst=DC)]
    flagged = flag_non_dc_replication(calls, known_dcs=KNOWN_DCS)
    assert len(flagged) == 1
    assert flagged[0].src == CLIENT


def test_dsgetncchanges_from_a_known_dc_is_not_flagged():
    """Two real DCs replicating with each other is the protocol working.

    Without this, the detector would fire on every ordinary replication cycle
    in a healthy multi-DC domain and be useless.
    """
    calls = [call(DSGETNCCHANGES_OPNUM, src=DC, dst=OTHER_DC)]
    flagged = flag_non_dc_replication(calls, known_dcs=frozenset({DC, OTHER_DC}))
    assert flagged == []


def test_other_drsuapi_opnums_from_a_non_dc_are_not_flagged():
    """DsBind, DsCrackNames, and DsGetDomainControllerInfo are not replication.

    Only opnum 3 transfers directory data. Flagging every DRSUAPI call a
    non-DC makes would bury the one call that matters under calls that any
    domain member can legitimately issue.
    """
    calls = [call(0, src=CLIENT), call(16, src=CLIENT), call(12, src=CLIENT),
             call(1, src=CLIENT)]
    assert flag_non_dc_replication(calls, known_dcs=KNOWN_DCS) == []


def test_empty_capture_flags_nothing():
    assert flag_non_dc_replication([], known_dcs=KNOWN_DCS) == []


def test_response_direction_is_not_mistaken_for_a_replication_pull():
    """The DC's reply to DsGetNCChanges carries the same opnum, reversed.

    If direction were ignored, the DC's own response would be read as the DC
    "pulling" from the client, since the opnum matches either way.
    """
    request = call(DSGETNCCHANGES_OPNUM, src=CLIENT, dst=DC, frame=17)
    response = call(DSGETNCCHANGES_OPNUM, src=DC, dst=CLIENT, frame=20)
    flagged = flag_non_dc_replication([request, response], known_dcs=KNOWN_DCS)
    assert len(flagged) == 1
    assert flagged[0].frame == 17


def test_classify_names_the_dc_membership_fact():
    non_dc = call(DSGETNCCHANGES_OPNUM, src=CLIENT, dst=DC)
    from_dc = call(DSGETNCCHANGES_OPNUM, src=DC, dst=OTHER_DC)
    assert "outside the known DC set" in classify(non_dc, KNOWN_DCS)
    assert "known domain controller" in classify(from_dc, frozenset({DC, OTHER_DC}))


def test_classify_on_non_replication_call_says_so():
    assert classify(call(0, src=CLIENT), KNOWN_DCS) == "not a DsGetNCChanges call"


def test_classify_never_asserts_malice():
    """Output names who issued the call, not what they intended by it.

    A backup product or an Azure AD Connect server with delegated replication
    rights produces the identical DsGetNCChanges call a stolen-credential
    DCSync pull does. This module cannot and does not claim to tell them apart.
    """
    labels = [
        classify(call(DSGETNCCHANGES_OPNUM, src=CLIENT, dst=DC), KNOWN_DCS),
        classify(call(DSGETNCCHANGES_OPNUM, src=DC, dst=OTHER_DC),
                 frozenset({DC, OTHER_DC})),
    ]
    for label in labels:
        for word in ("attack", "malicious", "attacker", "compromise"):
            assert word not in label.lower()
