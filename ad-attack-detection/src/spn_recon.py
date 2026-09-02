"""Detect SPN discovery: an LDAP search for accounts with a servicePrincipalName.

Kerberoasting has two steps, and only the first one is what this module looks
for. Step one is discovery: ask the directory which accounts have a
servicePrincipalName set, because any account with one can be asked for a
service ticket. That is an ordinary LDAP search, `(servicePrincipalName=*/*)`,
and it is how tools like setspn, PowerView's Get-SPN, and Rubeus/GetUserSPNs
find targets before requesting anything. Step two is the roast: request a TGS
for one of those SPNs and take the ticket away to crack offline. That second
step is a Kerberos exchange, not an LDAP search, and this module never claims
to see it.

The distinction matters because the two steps look nothing alike on the wire
and conflating them overclaims what a capture shows. Discovery is a single
LDAP query anyone with directory read access can run, domain admin or not,
and plenty of legitimate inventory and auditing tools run the exact same
query. A roast additionally requires requesting service tickets, and the
signature there is the encryption type: a ticket requested and returned with
etype 23 (RC4) for a service account is crackable offline, because RC4 keys
derive directly from the account password. AES (etype 17/18) service tickets
are not practically crackable the same way, and a modern domain issues AES by
default whenever it can.

So this module answers one narrow question: did an LDAP client search for
servicePrincipalName? That is the recon step, worth flagging because it is
usually the first sign someone is enumerating Kerberoasting targets. It is
not evidence a roast happened, and a capture with only this in it should be
reported as discovery, not as an attack in progress.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from src.common import run_tshark

# The attribute that marks a Kerberoasting-relevant account: any object with
# a servicePrincipalName can be issued a service ticket. `(servicePrincipalName
# =*/*)` is the filter setspn, PowerView, and GetUserSPNs all issue to find
# them.
SPN_ATTRIBUTE = "servicePrincipalName"


@dataclass(frozen=True)
class SpnSearch:
    """One LDAP searchRequest that referenced servicePrincipalName."""

    frame: int
    src: str
    dst: str
    attribute: str


def describe(searches: list[SpnSearch]) -> str:
    """Describe what this set of searches shows. A shape, not a verdict.

    Always names this as discovery. There is nothing this module extracts
    that could distinguish "found the SPNs and stopped" from "found the SPNs
    and then requested tickets", because that next step is a Kerberos
    exchange this module does not look at.
    """
    if not searches:
        return "no servicePrincipalName searches observed"
    sources = {s.src for s in searches}
    return ("service-account discovery: %d LDAP search(es) for "
            "servicePrincipalName from %d source(s) (recon step, "
            "not a ticket request)" % (len(searches), len(sources)))


def extract_spn_searches(pcap: Path, timeout: float = 3600.0) -> list[SpnSearch]:
    """Pull LDAP searchRequests that reference servicePrincipalName.

    ldap.filter in tshark's -T fields output renders as the filter's numeric
    type code (0 = and, 7 = present, 4 = equalityMatch, ...), not the readable
    string a human would recognise. Matching "servicePrincipalName" against
    that field finds nothing, even in a capture that plainly contains the
    search, which is the kind of failure this project's tests exist to catch:
    a filter with a typo returns an empty, plausible-looking result instead of
    an error. ldap.AttributeDescription carries the attribute name the filter
    actually references and is what this module filters and matches on.
    """
    rows = run_tshark(
        pcap,
        'ldap.AttributeDescription == "%s"' % SPN_ATTRIBUTE,
        ["frame.number", "ip.src", "ip.dst", "ldap.AttributeDescription"],
        timeout=timeout,
    )
    searches: list[SpnSearch] = []
    for parts in rows:
        if len(parts) < 4 or not parts[1]:
            continue
        try:
            frame = int(parts[0])
        except ValueError:
            continue
        # One search can reference the attribute more than once (as both the
        # filter target and a requested return attribute); tshark comma-joins
        # repeats onto one line. Record the search once per frame rather than
        # once per repeat, since it is one query regardless of how many times
        # the field appears in it.
        searches.append(SpnSearch(frame=frame, src=parts[1], dst=parts[2],
                                   attribute=parts[3].split(",")[0]))
    return searches
