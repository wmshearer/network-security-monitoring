"""Tests for SAMR group-membership enumeration detection.

The chain match is a subsequence check, not an exact match, because real
traffic interleaves extra Close calls and repeats between the opnums that
matter. Tests here guard that the subsequence logic actually requires order,
not just presence, and that the privileged-group label depends on the
resolved group name rather than firing on any SAMR traffic.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.samr_enum import (  # noqa: E402
    ENUMERATION_CHAIN,
    PRIVILEGED_GROUP_NAMES,
    EnumerationSequence,
    SamrCall,
    describe,
    group_sequences,
)

CLIENT = "192.168.1.46"
DC = "192.168.1.195"


def call(opnum, group_name=None, frame=1, src=CLIENT, dst=DC):
    return SamrCall(frame=frame, src=src, dst=dst, opnum=opnum,
                     group_name=group_name)


def test_full_chain_targeting_domain_admins_is_recognised():
    """The reference net group "Domain Admins" /domain chain, as captured."""
    calls = [call(64), call(6), call(5), call(7), call(17, "Domain Admins"),
             call(19), call(25), call(18), call(1)]
    seq = EnumerationSequence(src=CLIENT, dst=DC, calls=tuple(calls))
    assert seq.matches_enumeration_chain
    assert seq.group_name == "Domain Admins"
    assert "privileged group (Domain Admins)" in describe(seq)


def test_chain_recognised_even_with_extra_calls_interleaved():
    """Real traffic has repeats: multiple Close calls, in this capture three.

    A subsequence match tolerates that; an exact-sequence match would break
    on the very first real capture it was pointed at.
    """
    calls = [call(64), call(6), call(5), call(7), call(17, "Domain Admins"),
             call(19), call(25), call(18),
             call(1), call(1), call(1)]  # three closes, as observed
    seq = EnumerationSequence(src=CLIENT, dst=DC, calls=tuple(calls))
    assert seq.matches_enumeration_chain


def test_out_of_order_opnums_do_not_match():
    """Order matters: the same opnums shuffled are not the same chain.

    OpenGroup before LookupNames could not have resolved a RID yet, so a
    subsequence check must respect order, not just membership.
    """
    shuffled = list(reversed(ENUMERATION_CHAIN))
    calls = [call(op) for op in shuffled]
    seq = EnumerationSequence(src=CLIENT, dst=DC, calls=tuple(calls))
    assert not seq.matches_enumeration_chain


def test_partial_chain_does_not_match():
    """Missing a step (here, no OpenGroup) means it is not the full chain."""
    calls = [call(64), call(6), call(5), call(7), call(17, "Domain Admins")]
    seq = EnumerationSequence(src=CLIENT, dst=DC, calls=tuple(calls))
    assert not seq.matches_enumeration_chain
    assert "not a full group-membership enumeration chain" in describe(seq)


def test_group_name_missing_is_still_reported_not_hidden():
    """The response side of the conversation never carries the resolved name
    in this dataset's server-to-client direction; the chain can still be
    recognised without it, and describe() says so rather than guessing.
    """
    calls = [call(op) for op in ENUMERATION_CHAIN] + [call(18), call(1)]
    seq = EnumerationSequence(src=DC, dst=CLIENT, calls=tuple(calls))
    assert seq.matches_enumeration_chain
    assert seq.group_name is None
    assert "group name not resolved" in describe(seq)


def test_non_privileged_group_is_named_but_not_flagged_privileged():
    calls = [call(op, group_name=("Print Operators" if op == 17 else None))
             for op in ENUMERATION_CHAIN]
    seq = EnumerationSequence(src=CLIENT, dst=DC, calls=tuple(calls))
    assert seq.group_name == "Print Operators"
    assert "Print Operators" not in PRIVILEGED_GROUP_NAMES
    label = describe(seq)
    assert "Print Operators" in label
    assert "privileged" not in label


def test_group_sequences_splits_by_source_destination_pair():
    calls = [call(64, src=CLIENT, dst=DC), call(64, src=DC, dst=CLIENT),
             call(6, src=CLIENT, dst=DC)]
    seqs = group_sequences(calls)
    assert len(seqs) == 2
    pairs = {(s.src, s.dst) for s in seqs}
    assert pairs == {(CLIENT, DC), (DC, CLIENT)}


def test_empty_capture_produces_no_sequences():
    assert group_sequences([]) == []


def test_describe_never_asserts_malice():
    """A help-desk password-reset tool and PowerView enumeration walk the
    identical opnum chain to answer "who is in this group". This module
    names the group targeted, not the caller's purpose.
    """
    calls = [call(op, group_name=("Domain Admins" if op == 17 else None))
             for op in ENUMERATION_CHAIN]
    seq = EnumerationSequence(src=CLIENT, dst=DC, calls=tuple(calls))
    label = describe(seq)
    for word in ("attack", "malicious", "attacker", "compromise"):
        assert word not in label.lower()
