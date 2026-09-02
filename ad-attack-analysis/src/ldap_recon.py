"""Detect a manual full-directory LDAP dump: one bind, one wholeSubtree query.

Active Directory answers `ldapsearch` the same way it answers BloodHound: a
bind, a searchRequest, and a stream of entries back. That shared shape makes
"someone queried LDAP" nearly useless as a finding on its own, since it is
also what every domain-joined computer does at logon. What is worth
separating out is a single query that asks for the entire subtree at once,
because that is a directory dump: not "does this object exist" or "what is
this one attribute", but "give me everything under this base DN".

`(objectclass=*)` is a maximally permissive filter: every object in the
directory has an objectClass, so it matches all of them. Combined with scope
wholeSubtree (2) starting at the domain's own base DN, that filter returns
the entire directory contents in one query. The same filter at scope
baseObject (0) is a different and much smaller thing: it asks for exactly one
object (often `<ROOT>`, the RootDSE) and is how a client politely discovers
what the server supports before doing anything else. Both use the identical
filter string, so scope is what separates a routine capability probe from a
full pull.

WHAT THIS DOES NOT SAY
    A wholeSubtree `(objectclass=*)` dump is what a human runs by hand with
    `ldapsearch -x`. It is not what BloodHound/SharpHound produce: those tools
    issue a series of targeted filters (userAccountControl bit checks,
    samAccountType, servicePrincipalName, group membership attributes) built
    to collect specific fields efficiently across many objects, not one
    everything-filter in a single request. Seeing only `(objectclass=*)` with
    no such filters present is a reason to call this manual reconnaissance
    rather than automated collection, but this module has no way to identify
    a specific tool; it only distinguishes dump-shaped queries from
    probe-shaped ones.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from src.common import run_tshark

# LDAP scope values (RFC 4511 4.5.1.2).
SCOPE_BASE_OBJECT = 0
SCOPE_SINGLE_LEVEL = 1
SCOPE_WHOLE_SUBTREE = 2


@dataclass(frozen=True)
class LdapSearch:
    """One LDAP searchRequest."""

    frame: int
    src: str
    dst: str
    scope: int
    base_object: str
    filter_present: bool  # True when the filter is the maximally permissive "present" type


@dataclass(frozen=True)
class BindEvent:
    """One LDAP bindRequest (anonymous or with a name)."""

    frame: int
    src: str
    dst: str
    name: str  # empty string for anonymous / unauthenticated bind


def is_subtree_dump(search: LdapSearch) -> bool:
    """A wholeSubtree search with the maximally permissive filter.

    Scope is the discriminator, not the filter string alone: baseObject and
    wholeSubtree searches both legitimately use `(objectclass=*)`, and only
    one of them returns the whole directory.
    """
    return search.scope == SCOPE_WHOLE_SUBTREE and search.filter_present


def describe(search: LdapSearch) -> str:
    """Describe one search by shape. Never a verdict on the caller's intent."""
    if search.scope == SCOPE_BASE_OBJECT:
        return "capability probe (single object, base %s)" % (search.base_object or "<ROOT>")
    if is_subtree_dump(search):
        return "full-subtree query over %s (directory dump shape)" % search.base_object
    scope_name = {SCOPE_SINGLE_LEVEL: "single-level"}.get(search.scope, "scope %d" % search.scope)
    return "%s query over %s" % (scope_name, search.base_object or "<ROOT>")


def extract_searches(pcap: Path, timeout: float = 3600.0) -> list[LdapSearch]:
    """Pull every LDAP searchRequest's scope, base DN, and filter type."""
    rows = run_tshark(
        pcap, "ldap.protocolOp==3",
        ["frame.number", "ip.src", "ip.dst", "ldap.scope",
         "ldap.baseObject", "ldap.filter"],
        timeout=timeout,
    )
    searches: list[LdapSearch] = []
    for parts in rows:
        if len(parts) < 6 or not parts[1]:
            continue
        try:
            frame = int(parts[0])
            scope = int(parts[3]) if parts[3] else -1
        except ValueError:
            continue
        # ldap.filter is the filter's numeric CHOICE tag (RFC 4511 4.5.1.7);
        # 7 is "present", the maximally permissive form used by (attr=*).
        filter_present = parts[5].split(",")[0] == "7"
        searches.append(LdapSearch(frame=frame, src=parts[1], dst=parts[2],
                                    scope=scope, base_object=parts[4],
                                    filter_present=filter_present))
    return searches


def extract_binds(pcap: Path, timeout: float = 3600.0) -> list[BindEvent]:
    """Pull every LDAP bindRequest, so a dump can be tied to who authenticated."""
    rows = run_tshark(pcap, "ldap.protocolOp==0",
                       ["frame.number", "ip.src", "ip.dst", "ldap.name"],
                       timeout=timeout)
    binds: list[BindEvent] = []
    for parts in rows:
        if len(parts) < 4 or not parts[1]:
            continue
        try:
            frame = int(parts[0])
        except ValueError:
            continue
        binds.append(BindEvent(frame=frame, src=parts[1], dst=parts[2],
                                name=parts[3]))
    return binds
