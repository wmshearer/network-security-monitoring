# Active Directory recon and theft: what four captures show on the wire

Four captures, four steps of the same story: find the domain, find its
privileged accounts, find its service accounts, and pull its password
database. None of these techniques need malware. Every one of them uses a
legitimate Windows protocol exactly as designed, which is what makes them
worth analysing from packets rather than from a signature list: there is no
malicious byte string to match on, only a shape that a normal admin action
would not usually take.

Lab domain `picklesworth.local`, domain controller
`snicklefritz.picklesworth.local` at `192.168.1.195`, client host at
`192.168.1.46`. Captures from `github.com/elcabezzonn/Pcaps`; provenance and
full detail in the Provenance section below.

## 1. DCSync: a directory replication pull from a non-DC

**Capture:** `dcsync.pcapng`, 23 frames, 12 DRSUAPI calls.

Domain controllers replicate the directory to one another using DRSUAPI. The
call that actually moves data is `DsGetNCChanges` (opnum 3), and it is
generous by design: whoever can call it with the right rights gets back
whatever naming context they asked for, password hashes included. The
protocol has no separate read-only mode for this. Issuing the call and
receiving an answer IS the exposure.

The capture shows a full call sequence: `DsBind`(0) `DsGetDomainControllerInfo`
(16) `DsCrackNames`(12) `DsBind`(0) `DsGetNCChanges`(3) `DsUnbind`(1). Every
call in that chain is `192.168.1.46 -> 192.168.1.195`.

| Frame | Direction | Opnum | Call |
|---|---|---|---|
| 17 | 192.168.1.46 -> 192.168.1.195 | 3 | DsGetNCChanges (request) |
| 20 | 192.168.1.195 -> 192.168.1.46 | 3 | DsGetNCChanges (response) |

`192.168.1.46` is the lab's client host, not a domain controller. The
detector's rule is a membership check against a known-DC set supplied by
whoever runs the environment (here, just `192.168.1.195`): a `DsGetNCChanges`
call whose source is not in that set gets flagged.

```
$ python3 scripts/run_analysis.py
== DCSync: dcsync.pcapng ==
frames: 23 | DRSUAPI calls: 12 | flagged: 1
  frame 17  192.168.1.46 -> 192.168.1.195  directory replication pull from a
  host outside the known DC set
```

One call flagged, at the one frame that matters. The response at frame 20 is
not flagged, because its source is the DC answering, not a non-DC replicating.

**What this does not cover.** The known-DC set is an operational fact
supplied to the detector, not something derived from the traffic. Deriving
it from who issues `DsGetNCChanges` would be circular: it would define
whatever replicated as allowed to replicate, which is exactly the assumption
this technique benefits from. This also only looks at opnum 3; the other
DRSUAPI calls in the chain (`DsBind`, `DsCrackNames`, and so on) are not
inherently suspicious and are not flagged from any source. The detector
cannot tell a stolen-credential pull from a backup product or an Azure AD
Connect server with legitimately delegated replication rights; both produce
the identical call.

## 2. SPN discovery: finding accounts worth Kerberoasting later

**Capture:** `find_service_accounts.pcap`, 81 frames, 1 matching search out of
4 total LDAP searchRequests.

This capture shows the recon step of Kerberoasting, not a roast. The filter
`(servicePrincipalName=*/*)` asks the directory for every account that has a
servicePrincipalName set, because any account with one can later be asked for
a service ticket. That is what setspn, PowerView's `Get-SPN`, and
`GetUserSPNs` all issue as their first move. Requesting and cracking a ticket
is a separate, later step this capture does not contain.

```
$ python3 scripts/run_analysis.py
== SPN discovery: find_service_accounts.pcap ==
frames: 81 | searches: 1
  service-account discovery: 1 LDAP search(es) for servicePrincipalName from
  1 source(s) (recon step, not a ticket request)
```

**The honest nuance, checked directly against the packets.** This capture
does contain Kerberos traffic, and it needed checking rather than assuming.
Every ticket actually issued in the capture (the AS-REP at frame 23, the
TGS-REP at frame 33) uses etype **18, AES256**, for the `krbtgt` and the DC's
own `ldap` SPN (`SnickleFritz.picklesworth.local`). That is the domain
controller's normal SASL bind sequence, not a roast, and not a Kerberoastable
ticket: AES service tickets are not practically crackable offline the way RC4
(etype 23) ones are. One `KRB-ERROR` frame (frame 15) lists etype 23 as a
*supported* type the DC offers during negotiation, which is not the same as
an actual ticket being issued with it, and no issued ticket in this capture
ever uses it. This capture is SPN discovery, correctly labelled as recon, and
does not show Kerberoasting.

**What this does not cover.** The detector only recognises the LDAP search
for `servicePrincipalName`. It has no visibility into whether a ticket
request follows, what encryption type it used, or whether it was ever taken
offline for cracking. Reporting this as a roast would be a claim the capture
does not support. It is also worth naming that legitimate inventory and
auditing tools issue the identical query, so the finding is "someone
enumerated service accounts," not "someone is roasting."

## 3. Manual LDAP recon: a single query for the whole directory

**Capture:** `tinkersec-ldapsearch.pcap`, 252 frames, 2 searchRequests, 2
bindRequests.

| Frame | Scope | Base object | Shape |
|---|---|---|---|
| 10 | baseObject (0) | `<ROOT>` | capability probe |
| 32 | wholeSubtree (2) | `DC=picklesworth,DC=local` | full-subtree dump |

Both searches use the identical filter, `(objectclass=*)`, which matches
every object in the directory because every object has an objectClass. The
filter string alone does not distinguish a polite capability check from a
full pull; scope does. Frame 10's scope is `baseObject`, which returns
exactly one object, the way a client discovers what a server supports before
doing anything else. Frame 32's scope is `wholeSubtree` starting at the
domain's own base DN, `DC=picklesworth,DC=local`, which returns the entire
directory in one query.

The subtree dump follows an authenticated bind: frame 6 is anonymous, frame
28 binds as `chewbacca@picklesworth` with a simple bind, and it is that
authenticated session that issues the wholeSubtree pull at frame 32.

```
$ python3 scripts/run_analysis.py
== LDAP recon: tinkersec-ldapsearch.pcap ==
frames: 252 | searchRequests: 2 | bindRequests: 2
  frame 10  capability probe (single object, base <ROOT>)
  frame 32  full-subtree query over DC=picklesworth,DC=local (directory dump shape)
  frame 6  bind as '(anonymous)'
  frame 28  bind as 'chewbacca@picklesworth'
```

**This is manual reconnaissance, not BloodHound, and the capture supports
saying so.** BloodHound/SharpHound collect the directory through a series of
targeted filters built to pull specific fields efficiently: `userAccountControl`
bit checks, `samAccountType`, `servicePrincipalName`, group-membership
attributes, issued repeatedly across many objects. None of those filters
appear anywhere in this capture. What is here is one everything-filter in a
single request, which is what `ldapsearch -x` produces when pointed at a base
DN with no filter narrowing applied. The traffic is consistent with a human
running `ldapsearch` by hand, and the module labels it that way rather than
naming a specific automated tool it has no evidence for.

**What this does not cover.** The detector distinguishes dump-shaped queries
from probe-shaped ones by scope and filter type; it cannot identify a
specific tool, and a tool other than manual `ldapsearch` that happened to
issue one wholeSubtree `(objectclass=*)` query would look identical. A single
bind pulling the entire subtree is unusual for a legitimate application (most
query narrowly for what they need), but "unusual" is a shape observation, not
proof of intent.

## 4. SAMR enumeration of Domain Admins membership

**Capture:** `net_group_DAs.pcap`, 86 frames, 42 SAMR calls.

`net group "Domain Admins" /domain` walks a fixed opnum chain over
`\PIPE\samr`, because SAMR requires opening each object (server, domain,
group) before it can be queried. The capture shows this chain twice in a row,
both times resolving the group name "Domain Admins" and both times ending
with a resolved account name from the membership:

| Opnum | Call | Frame (first pass) |
|---|---|---|
| 64 | SamrConnect5 | 30 |
| 6 | SamrEnumerateDomainsInSamServer | 32 |
| 5 | SamrLookupDomainInSamServer | 34 |
| 7 | SamrOpenDomain | 36 |
| 17 | SamrLookupNamesInDomain ("Domain Admins") | 38 |
| 19 | SamrOpenGroup | 42 |
| 20 | SamrQueryInformationGroup | 44 |
| 1 | SamrCloseHandle x3 | 46, 48, 50 |

A second, complete pass follows at frames 62-83, this time reaching
`SamrGetMembersInGroup` (opnum 25) and `SamrLookupIdsInDomain` (opnum 18),
which resolves the group's member RIDs back to a name: `Administrator`.

```
$ python3 scripts/run_analysis.py
== SAMR group enumeration: net_group_DAs.pcap ==
frames: 86 | SAMR calls: 42 | matching sequences: 2
  192.168.1.46 -> 192.168.1.195  group-membership enumeration targeting a
  privileged group (Domain Admins)
  192.168.1.195 -> 192.168.1.46  group-membership enumeration chain (group
  name not resolved on the wire)
```

The second row is the server's own replies grouped by direction, not a
second enumeration; SAMR responses carry the same opnums as the requests they
answer, so grouping by `(src, dst)` naturally separates the client's outbound
calls from the server's replies coming back.

**A correction made against the official spec, not just the capture.** An
earlier read of this chain (before verifying opnum names against
[MS-SAMR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/))
mislabelled opnum 20 as `QueryGroupMember` and opnum 18 as
`GetMembersInGroup`. The spec and tshark's own dissector agree: opnum 20 is
`SamrQueryInformationGroup` (attributes about the group), opnum 25 is
`SamrGetMembersInGroup` (the actual member RID list), and opnum 18 is
`SamrLookupIdsInDomain` (RID to account name). The detector's chain, and the
table above, reflect the verified names.

**What this does not cover.** Enumerating group membership through this
opnum chain is not inherently suspicious; password-reset tools, help-desk
software, and Windows itself query group membership constantly through the
identical calls. The group name resolved at `SamrLookupNamesInDomain` is what
separates "someone checked who's in Print Operators" from "someone checked
who's in Domain Admins," which is why the detector reports the group name
rather than firing on SAMR traffic generally. Whether this particular caller
and this particular group are an expected pairing in this environment is a
fact this module cannot settle from opnums alone.

## What this does NOT cover

Four AD techniques with no usable public capture were left out entirely
rather than approximated:

- **Kerberoasting proper.** The published network indicator is a TGS-REP for
  a service account SPN encrypted with RC4 (etype 23), the encryption type
  that makes the ticket crackable offline. None of the captures available for
  this project contain one. `find_service_accounts.pcap` shows the discovery
  step only, as detailed above; generating an actual roast to fill the gap
  was out of scope for this project (running attack tooling, even in a lab,
  is a different activity than analysing existing captures).
- **AS-REP roasting.** No public capture of a `DONT_REQUIRE_PREAUTH` AS-REP
  exchange was available.
- **LLMNR/NBT-NS poisoning.** No public capture was available.
- **NTLM relay.** No public capture was available.

One additional file from the source repository,
`rubeus-kerberoast-cmdline-parameter.pcap`, was pulled and checked before
being discarded: it contains LDAP traffic only, zero Kerberos frames, and its
filename overclaims what it holds. It is not used or cited as evidence of
anything here. Checking a capture's contents against its filename, rather
than trusting the name, is what caught this before it became a wrong finding.

A fifth capture, a 2020 Trickbot ("Catbomber") sample that reaches a domain
controller over SMB, is parked in `data/captures/mta-catbomber/` for a
possible later addition; its archive is password-protected and the password
was not available at the time of this analysis.

## Provenance

Captures from `github.com/elcabezzonn/Pcaps`, a personal Active Directory lab
dump (no LICENSE file in the source repository; raw captures are not
redistributed in this project, see `data/captures/README.md`). Lab domain
`picklesworth.local`, domain controller `snicklefritz.picklesworth.local` at
`192.168.1.195`, client host at `192.168.1.46`. MS-SAMR opnum names verified
against Microsoft's own protocol documentation, not assumed from tshark's
column text alone.

Analysis is `python3 scripts/run_analysis.py`; 29 tests in `tests/` cover the
classification logic, including one per module asserting the output never
claims malice.
