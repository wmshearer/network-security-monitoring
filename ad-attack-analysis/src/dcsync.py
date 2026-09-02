"""Detect DCSync: a directory replication pull from a host that is not a DC.

DCSync abuses a legitimate Active Directory mechanism. Domain controllers
replicate the directory to one another using DRSUAPI, the same DCERPC
interface a real DC uses every few minutes to stay in sync with its peers.
The RPC method that carries the actual data is DsGetNCChanges, and it is
generous by design: give it the right rights (Replicating Directory Changes,
or the "All" variant) and it will hand back the requested naming context,
password hashes included, exactly as it would to another DC.

The protocol has no separate "read-only" mode for this. If a caller can issue
DsGetNCChanges and the domain controller answers, the caller now holds
whatever was requested. There is nothing else to check afterward: the
replication itself IS the exposure, not a side effect of it.

So the question this module asks is narrow and answerable from network
traffic alone: who is issuing DsGetNCChanges? In a healthy domain the answer
is always "a domain controller, replicating with another domain controller."
The set of domain controllers is a fact about the environment, not something
this module derives from what it observes, for the same reason the ICS write
allow-list is supplied rather than inferred: deriving "who is allowed to
replicate" from "who replicated" would define the theft as normal, since it
is the only traffic that would ever look like a DC replicating.

WHAT THIS DOES NOT COVER
    This looks at DsGetNCChanges (opnum 3) specifically, not the whole DRSUAPI
    surface. A capture can contain DsBind, DsCrackNames, and other DRSUAPI
    calls from non-DC hosts for unrelated, benign reasons; those are not
    flagged here. It also cannot tell whether the caller had legitimate
    delegated replication rights (a backup product, an Azure AD Connect
    server) versus stolen ones. The finding is "a non-DC replicated
    directory data"; whether that was authorized is a fact about the
    environment, not the packets.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from src.common import KNOWN_DCS, run_tshark

# The opnum for DsGetNCChanges on the drsuapi interface (MS-DRSR). This is the
# call that actually transfers directory data, as opposed to DsBind (0),
# DsCrackNames (12), or DsGetDomainControllerInfo (16), which do not.
DSGETNCCHANGES_OPNUM = 3


@dataclass(frozen=True)
class ReplicationCall:
    """One DRSUAPI call observed in a capture."""

    frame: int
    src: str
    dst: str
    opnum: int

    @property
    def is_nc_changes(self) -> bool:
        return self.opnum == DSGETNCCHANGES_OPNUM


def classify(call: ReplicationCall, known_dcs: frozenset[str]) -> str:
    """Describe a DsGetNCChanges call by who issued it. A shape, not a verdict.

    The description names the fact (non-DC source, DC source) rather than
    naming an actor's intent. A backup agent with delegated replication
    rights and a stolen-credential DCSync pull produce identical traffic;
    this module cannot and does not try to tell them apart.
    """
    if not call.is_nc_changes:
        return "not a DsGetNCChanges call"
    if call.src in known_dcs:
        return "directory replication pull from a known domain controller"
    return "directory replication pull from a host outside the known DC set"


def extract_calls(pcap: Path, timeout: float = 3600.0) -> list[ReplicationCall]:
    """Pull every DRSUAPI call in the capture, direction and opnum included."""
    rows = run_tshark(pcap, "drsuapi",
                       ["frame.number", "ip.src", "ip.dst", "drsuapi.opnum"],
                       timeout=timeout)
    calls: list[ReplicationCall] = []
    for parts in rows:
        if len(parts) < 4 or not parts[1] or not parts[3]:
            continue
        try:
            frame = int(parts[0])
            # drsuapi.opnum can appear more than once per line if a frame
            # carries more than one PDU; take the first, which is the one
            # tshark's own dissection lines this row up against.
            opnum = int(parts[3].split(",")[0])
        except ValueError:
            continue
        calls.append(ReplicationCall(frame=frame, src=parts[1], dst=parts[2],
                                      opnum=opnum))
    return calls


def flag_non_dc_replication(
    calls: list[ReplicationCall],
    known_dcs: frozenset[str] = KNOWN_DCS,
) -> list[ReplicationCall]:
    """DsGetNCChanges calls whose source is not in the known-DC set.

    This is the detection an operator deploys: alert on replication from
    anything that is not a domain controller. A legitimate DC pulling from
    another DC is excluded by construction, so this list only grows when
    something outside the DC set does what only a DC should do.
    """
    return [c for c in calls
            if c.is_nc_changes and c.src not in known_dcs]
