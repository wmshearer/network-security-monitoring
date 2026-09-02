"""Detect a SAMR group-membership enumeration sequence over \\PIPE\\samr.

`net group "Domain Admins" /domain` does not ask a domain controller one
question, it asks a fixed sequence of them over SAMR (MS-SAMR), the RPC
interface behind every "who is in this group" and "what accounts exist"
operation on Windows. The client connects to the SAM database, resolves the
domain name to a handle, resolves the group name to a RID, opens the group,
and reads its membership. Any tool that answers "who is in Domain Admins" -
`net group`, PowerView's Get-DomainGroupMember, a hand-rolled RPC client -
walks the same handles for the same reason: SAMR requires you to open each
object before you can query it, so the open-then-query pairing is structural,
not a tool fingerprint.

The sequence, by opnum (MS-SAMR section 3.1.5), as issued by the reference
`net group /domain` chain analysed here:

    64  SamrConnect5              get a handle to the SAM server
     6  SamrEnumerateDomains      list domains the server knows
     5  SamrLookupDomainInSamServer   resolve a domain NAME to a SID
     7  SamrOpenDomain            get a handle to that domain
    17  SamrLookupNamesInDomain   resolve a group NAME to a RID
    19  SamrOpenGroup             get a handle to that group
    25  SamrGetMembersInGroup     read the group's member RIDs
    18  SamrLookupIdsInDomain     resolve those RIDs back to account names
     1  SamrCloseHandle           release a handle (issued once per handle held)

The group name resolved at LookupNamesInDomain (opnum 17) is the interesting
field: "Domain Admins", "Enterprise Admins", or "Schema Admins" is privileged
group enumeration. "Print Operators" issued through the identical opnum
sequence is not, and this module cannot tell the difference from shape alone,
which is why the group name is captured and reported rather than assumed.

WHAT THIS DOES NOT COVER
    Enumerating a group's membership is not the same as ITS EFFECT, and SAMR
    enumeration alone is common: password-reset tools, help-desk software,
    and Windows itself query group membership constantly. This module
    recognises the shape of the query chain and reports which group was the
    target; whether that target and that caller are expected to look this up
    is a fact about the environment, not something the opnum sequence can
    settle.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from src.common import run_tshark

# Opnum -> name, MS-SAMR section 3.1.5. Only the calls this module reasons
# about are named; anything else observed on the samr interface is reported
# by number rather than guessed at.
OPNUM_NAMES = {
    1: "SamrCloseHandle",
    5: "SamrLookupDomainInSamServer",
    6: "SamrEnumerateDomainsInSamServer",
    7: "SamrOpenDomain",
    17: "SamrLookupNamesInDomain",
    18: "SamrLookupIdsInDomain",
    19: "SamrOpenGroup",
    25: "SamrGetMembersInGroup",
    64: "SamrConnect5",
}

# The chain a group-membership lookup walks, in order. LookupIdsInDomain (18)
# is optional in this list: some callers stop at the RID list from
# GetMembersInGroup (25) without resolving names, so a sequence missing 18 is
# still counted as the enumeration shape rather than treated as incomplete.
ENUMERATION_CHAIN = (64, 6, 5, 7, 17, 19, 25)

# Groups whose membership is worth naming specifically when resolved from
# LookupNamesInDomain. Anything else observed through the same opnum chain is
# still reported, just not called out as privileged-group enumeration.
PRIVILEGED_GROUP_NAMES = frozenset({
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Administrators", "Account Operators", "Backup Operators",
})


@dataclass(frozen=True)
class SamrCall:
    """One SAMR request observed on the wire."""

    frame: int
    src: str
    dst: str
    opnum: int
    group_name: str | None = None  # populated for LookupNamesInDomain (17)

    @property
    def name(self) -> str:
        return OPNUM_NAMES.get(self.opnum, "opnum %d" % self.opnum)


@dataclass(frozen=True)
class EnumerationSequence:
    """One client's SAMR calls to one server, in the order they were sent."""

    src: str
    dst: str
    calls: tuple[SamrCall, ...]

    @property
    def opnums(self) -> tuple[int, ...]:
        return tuple(c.opnum for c in self.calls)

    @property
    def group_name(self) -> str | None:
        for c in self.calls:
            if c.group_name:
                return c.group_name
        return None

    @property
    def matches_enumeration_chain(self) -> bool:
        """True when the group-membership lookup chain appears, in order.

        Subsequence, not exact match: other SAMR traffic (extra Close calls,
        an unrelated LookupNames) can sit between the calls that matter
        without breaking recognition of the underlying chain.
        """
        it = iter(self.opnums)
        return all(op in it for op in ENUMERATION_CHAIN)


def describe(seq: EnumerationSequence) -> str:
    """Describe a SAMR call sequence by shape. A description, not a verdict."""
    if not seq.matches_enumeration_chain:
        return "SAMR activity, not a full group-membership enumeration chain"
    group = seq.group_name
    if group and group in PRIVILEGED_GROUP_NAMES:
        return "group-membership enumeration targeting a privileged group (%s)" % group
    if group:
        return "group-membership enumeration targeting %r" % group
    return "group-membership enumeration chain (group name not resolved on the wire)"


def extract_calls(pcap: Path, timeout: float = 3600.0) -> list[SamrCall]:
    """Pull every SAMR request in the capture, including the resolved group name."""
    rows = run_tshark(
        pcap, "samr",
        ["frame.number", "ip.src", "ip.dst", "samr.opnum",
         "samr.samr_LookupNames.names"],
        timeout=timeout,
    )
    calls: list[SamrCall] = []
    for parts in rows:
        if len(parts) < 5 or not parts[1] or not parts[3]:
            continue
        try:
            frame = int(parts[0])
            opnum = int(parts[3].split(",")[0])
        except ValueError:
            continue
        group_name = parts[4] if opnum == 17 and parts[4] else None
        calls.append(SamrCall(frame=frame, src=parts[1], dst=parts[2],
                               opnum=opnum, group_name=group_name))
    return calls


def group_sequences(calls: list[SamrCall]) -> list[EnumerationSequence]:
    """Group SAMR calls into per-(src,dst) sequences, in capture order.

    Requests only would double the picture with server echoes; SAMR responses
    carry the same opnum as the request they answer, and grouping by (src,dst)
    naturally separates a client's outbound calls from the server's replies
    coming back the other direction, since src and dst swap.
    """
    by_pair: dict[tuple[str, str], list[SamrCall]] = {}
    for c in calls:
        by_pair.setdefault((c.src, c.dst), []).append(c)
    return [EnumerationSequence(src=k[0], dst=k[1], calls=tuple(v))
            for k, v in by_pair.items()]
