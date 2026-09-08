# The 3G Tier — UMTS Core Network and Iu/Iuh Signalling (no radio, and no full 3G network either)

This is the 3G/UMTS addition to the lab, built on top of (and independent
from) the 5G core, the 2G tier (`docs/2G-TIER.md`), and the 4G tier
(`docs/4G-TIER.md`). Read the next section before anything else — this
tier's scope is narrower than the other three, and that is deliberate,
not an oversight.

## The RF boundary — read this first

**There is no RF-free path for the WCDMA Uu air interface.** No
open-source UMTS PHY simulator exists anywhere; neither srsRAN nor
OpenAirInterface ever built a ZMQ/virtual-radio equivalent for 3G the
way they did for LTE (srsRAN_4G's ZMQ mode, `docs/4G-TIER.md`) or GSM
(Osmocom's Virtual Um, `docs/2G-TIER.md`). This was confirmed via two
independent research angles before this build started, and this tier
does not attempt to find or fake one.

**What this tier therefore is: the 3G core network plus the Iuh/Iu
signalling stack — not "a 3G network".** Osmocom's own framing of their
FOSS UMTS stack is that it runs "from the core network right up to the
femto-cell's ethernet jack" — that ethernet jack is exactly the RF
boundary this tier stops at. Everything from there inward (Iuh over
SCTP/IP, the HNB-GW, Iu-CS/Iu-PS, the MSC/HLR) is ordinary IP signalling
between Linux processes, with the same "these are just UDP/SCTP sockets"
property the 2G, 4G, and 5G tiers already have. Everything from there
outward (the actual WCDMA radio link to a real handset) is not
represented here at all.

**What this tier does NOT cover, stated explicitly:**

- **No Uu air interface of any kind** — not simulated, not virtualised,
  not represented by any substitute transport. There is no equivalent
  here to Virtual Um (2G) or ZMQ virtual radio (4G).
- **No real UMTS handset ever attaches.** `osmo-hnodeb` (the software
  Home NodeB used here) implements only the HNBAP/RUA/RANAP *upper*
  layers of the Iuh interface; its own README states plainly that it is
  "a first step towards implementing a minimal hNodeB upper layer part
  ... not expected to be a full/usable hNodeB anytime soon [if ever]".
  It exposes a lower-layer socket (`ll-socket`, `/tmp/hnb_prim_sock`)
  where a real Uu/PHY/RRC stack would attach — no such client exists
  anywhere in this build or upstream.
- **No UE ever registered over Iuh in this build**, and consequently
  **no RANAP Initial UE Message, no NAS-PS/NAS-CS content, and no UMTS
  AKA/AUTN exchange was captured.** See "What was reached, precisely"
  and "What was investigated but not built" below for exactly why, and
  exactly what it would take.

If you came here expecting a 3G phone to attach to this lab the way the
2G tier's virtual handset or the 4G tier's `srsue` do, it does not — and
this document says so plainly rather than implying otherwise anywhere.

## Architecture

```
   (no Uu air interface exists anywhere in this diagram — see above)

  osmo-hnodeb                                      osmo-hnbgw
  (software HNB,           Iuh (HNBAP/RUA/RANAP     (Home NodeB
  host process,        <----   over SCTP/IP,   ---->  Gateway,
  no Uu/PHY/RRC             port 29169, loopback)     host process)
  client attached)                                          |
                                                    Iu-CS (RANAP over
                                                    SCCP/M3UA, shared
                                                    cs7 instance 0 with
                                                    the 2G tier's own
                                                    osmo-stp — see
                                                    "cs7/SCCP wiring"
                                                    below)
                                                              |
                                                              v
                                                         osmo-stp
                                                  (SCCP/M3UA transfer
                                                   point — SAME process
                                                   the 2G tier already
                                                   runs, untouched)
                                                              |
                                                              v
                                                         osmo-msc
                                              (mobile switching center —
                                               SAME process the 2G tier
                                               already runs; osmo-msc is
                                               both 2G AND 3G capable)
                                                    /
                                              GSUP (subscriber
                                              auth data)
                                                    v
                                                 osmo-hlr
                                        (SAME process the 2G tier already
                                         runs — holds BOTH the 2G and 3G
                                         test subscribers)

  osmo-sgsn / osmo-ggsn (PS/Iu-PS core) — installed (apt), NOT wired up
  in this build. See "What was not reached" below.
```

Three new/changed daemons on top of the six the 2G tier already runs:
`osmo-hnbgw` (Home NodeB Gateway, built from source) and `osmo-hnodeb`
(software Home NodeB, built from source) are new; `osmo-msc`,
`osmo-hlr`, and `osmo-stp` are the SAME already-running 2G-tier
processes, reused unmodified — osmo-msc 1.13.0 and osmo-hlr 1.9.4 are
both natively 2G AND 3G capable, and osmo-stp routes SCCP by point code
with no per-generation logic at all. `osmo-mgw` (media gateway) is also
reused. `osmo-sgsn`/`osmo-ggsn` (the PS/packet-switched side) were
installed from Kali's own apt repository but not configured or started
in this pass — see "What was not reached".

## Synthetic test subscriber

Same 3GPP-reserved test PLMN the 2G tier already uses, with its own
distinct IMSI so 2G and 3G subscribers are visibly different in any
shared capture or HLR listing — the same distinct-IMSI-per-tier
convention the 4G tier established relative to the 5G tier:

| Field | Value |
|-------|-------|
| PLMN (MCC/MNC) | 001/01 (3GPP test network, same as the 2G tier) |
| IMSI | `001010000000002` |
| Auth algorithm | **Milenage** (real UMTS AKA / 3G authentication data — deliberately NOT the 2G tier's COMP128v1, see below) |
| Key (K) | `465B5CE8B199B49FAA5F0A2EE238A6BC` (same value the 4G/5G tiers' own test subscribers use, reused here purely for cross-tier consistency — not a real key either way) |
| OPc | `E8ED289DEBA952E4283B54E88E6183CA` |

Provisioned directly into the already-running `osmo-hlr`:

```
subscriber imsi 001010000000002 create
subscriber imsi 001010000000002 update aud3g milenage \
  k 465B5CE8B199B49FAA5F0A2EE238A6BC opc E8ED289DEBA952E4283B54E88E6183CA
```

`aud3g milenage` was chosen deliberately over `aud2g` — this subscriber
carries real UMTS AKA authentication data, so a genuine AUTN-bearing
Authentication Request would have been possible had this build reached
a RANAP Initial UE Message (see "What UMTS AKA changed" and "What was
investigated but not built" below). No real IMSI, no real key, ever.

## cs7/SCCP wiring: shared cs7 instance 0, zero disruption to the 2G tier

`osmo-hnbgw` shares `cs7 instance 0` with the already-running 2G tier's
`osmo-stp`/`osmo-bsc`/`osmo-msc` rather than getting its own instance.
This was possible with **zero changes to `osmo-stp.cfg`** and **zero
restart of any live 2G daemon**, verified before writing any config:

- osmo-stp's existing `cs7 instance 0` already has `xua rkm
  routing-key-allocation dynamic-permitted` and `accept-asp-connections
  dynamic-permitted` — a new ASP (osmo-hnbgw) can register against the
  same `listen m3ua 2905` with no pre-declared route.
- Confirmed live via VTY (not assumed) before choosing a point code:
  osmo-msc holds `0.23.1`, osmo-bsc holds `0.23.3`. `osmo-hnbgw.cfg`
  uses `0.42.0` (confirmed free) and declares `sccp-address my-msc {
  point-code 0.23.1 }` / `msc 0 { remote-addr my-msc }` to reach the
  existing osmo-msc directly.
- This is the same pattern osmo-msc's own upstream example config
  (`osmo-msc_custom-sccp.cfg`) documents for sharing one cs7 instance
  across the A-interface and the Iu-interface (`cs7-instance-a 0` /
  `cs7-instance-iu 0`), just approached from the STP/hnbgw side —
  osmo-msc.cfg itself needed no edit at all.

Verified throughout the build: `ps aux | grep osmo` before and after
showed all six 2G-tier daemons (plus the 2G tier's own virtual handset
processes) still running with their original PIDs, and `show cs7
instance 0 asp` on osmo-stp showed the two original 2G ASPs still
`ASP_ACTIVE` alongside the new one for osmo-hnbgw.

## Building osmo-hnbgw and osmo-hnodeb (not packaged — from source)

Neither `osmo-hnbgw` nor `osmo-hnodeb` is packaged anywhere in Kali.
Both were cloned from Osmocom's own Gitea and built with the standard
`autoreconf -fi && ./configure && make`. Two real dependency/version
blockers were hit and fixed — full detail, including the exact `git
log` commit search used to resolve a library-version mismatch without
cascading into a second source build, is in `NOTES.md`. Summary:

- **osmo-hnbgw**: needed two missing `-dev` packages
  (`osmo-libasn1c-dev`, `libosmo-mgcp-client-dev`, both ordinary apt
  packages) and, more substantially, HEAD requires `libosmo-sigtran >=
  2.3.0` while Kali packages 2.1.0. Rather than also source-build
  libosmo-sccp/libosmo-sigtran (risking an ABI mismatch against the
  ALREADY-RUNNING 2G tier's own osmo-msc/osmo-hlr/osmo-stp, which link
  the packaged version), pinned to commit `5ebcace` (2025-05-06, the
  last commit before the version floor was raised) — every version
  floor it declares is met by what Kali packages. Built clean after
  that.
- **osmo-hnodeb**: HEAD is exactly tag `0.2.2` (the latest release) and
  its version floors (down to `libosmo-sigtran >= 1.9.0`) are all
  comfortably met by Kali's packages — no pin needed, no blocker beyond
  the same missing `-dev` header class already resolved for osmo-hnbgw.
  Built clean on the first attempt.

Both binaries: `build/osmo-hnbgw/src/osmo-hnbgw/osmo-hnbgw`,
`build/osmo-hnodeb/src/osmo-hnodeb/osmo-hnodeb` (both gitignored source
trees, same convention as the 2G tier's OsmocomBB build and the 4G
tier's srsRAN_4G build under `build/`).

## What was reached, precisely

1. **3G core up alongside the other tiers, not replacing them.**
   `osmo-hnbgw` and `osmo-hnodeb` run as plain host processes; `osmo-msc`,
   `osmo-hlr`, `osmo-stp`, `osmo-mgw` are the SAME already-running 2G-tier
   processes. The 5G Docker stack and 4G EPC containers were never
   touched. `osmo-sgsn`/`osmo-ggsn` (PS core) are installed but not
   started — see "What was not reached".
2. **A synthetic 3G subscriber provisioned in osmo-hlr** with real
   Milenage/UMTS AKA authentication data (IMSI `001010000000002`, test
   PLMN 001/01) — see above.
3. **An HNB registers over Iuh — captured.** `osmo-hnodeb` connects to
   `osmo-hnbgw` over SCTP (port 29169) and sends a genuine **HNBAP HNB
   REGISTER REQUEST**; `osmo-hnbgw` accepts it and replies with **HNBAP
   HNB REGISTER ACCEPT** (assigning RNC-ID 23). Captured end to end on
   loopback: `evidence/3g/iuh-hnb-register.pcap`. Full field decode
   (HNB-Identity, PLMN, Cell Identity, LAC/RAC/SAC) in
   `evidence/3g/iuh-hnb-register-hnbap-detail.txt`.
4. **Real RANAP signalling beyond HNBAP — captured, but not a UE
   procedure.** `osmo-hnodeb`'s VTY command `ranap reset (cs|ps)` sends
   a genuine RANAP Reset PDU over RUA/Iuh; `osmo-hnbgw` answers with a
   real RANAP ResetAcknowledge. Captured:
   `evidence/3g/iuh-ranap-reset.pcap`. This is real RANAP content (a
   connectionless/global procedure per TS 25.413, terminated at the
   HNBGW itself rather than relayed to the MSC) — it is NOT a UE
   registration and NOT proof of an Iu-CS hop reaching osmo-msc.
5. **UE registration signalling and RANAP Initial UE Message — NOT
   reached.** See the next section for exactly why, and exactly what it
   would take.

## What was investigated but not built: the path to a real UE registration

`osmo-hnodeb`'s own HNBAP layer has a complete, unused function for
sending an HNBAP UE REGISTER REQUEST —
`hnb_ue_register_tx(struct hnb *hnb, const char *imsi_str)` in
`src/osmo-hnodeb/hnbap.c` — but grepping the entire source tree confirms
it is never called from anywhere, and no VTY command is wired to it.
The only path to drive it is `osmo-hnodeb`'s own lower-layer primitive
socket ("HNBLLIF", Unix socket `/tmp/hnb_prim_sock`,
`include/osmocom/hnodeb/hnb_prim.h`) — exactly the "stub where a real
Uu/PHY/RRC stack would attach" the project's own README warns about. No
client for this socket ships anywhere upstream.

Building one from scratch would require BOTH:

1. Reverse-engineering `osmo_prim_srv`'s actual wire framing (not just
   the in-memory `struct osmo_prim_hdr` — `libosmocore`'s
   `osmo_prim_srv.c` has its own serialization the client must match
   exactly), including the SAPI-version-negotiation handshake
   (`llsk_rx_sapi_version_cb`) that must complete before
   `CONN_ESTABLISH` is even accepted, **and**
2. Hand-encoding a real, spec-conformant **RANAP Initial UE Message**
   ASN.1 PER payload — `struct hnb_iuh_conn_establish_req_param` takes a
   raw, caller-encoded RANAP message (`data`/`data_len`), with no
   existing tool in this lab to generate one RF-free.

This was assessed as a genuinely substantial, uncertain side-build —
not a config tweak — and was **not attempted**, per this task's own
instruction to budget time and prefer an honestly-bounded partial result
over an overclaimed one. Full reasoning: `NOTES.md`.

**Consequence stated plainly: no UMTS AKA / authentication exchange was
captured or demonstrated in this build.** The subscriber's real Milenage
data (provisioned above) has never been exercised — there is no
Authentication Request to point to, no AUTN token captured, no
"money shot" screenshot of it. This is the honest limit of what was
reached, not a claim of something that was not achieved.

## What was not reached: the PS (packet-switched) side

`osmo-sgsn` and `osmo-ggsn` were installed from Kali's apt repository
(both are ordinary packages, no source build needed) but were not
configured or started in this pass — with no UE ever reaching Iuh at
all (see above), there was no PS-side signalling to demonstrate even
if the SGSN/GGSN were wired up, so bringing them up was not judged to
add anything observable within this pass's effort budget. Both remain
available for a future pass that also builds the missing HNBLLIF
client.

## What UMTS AKA changed, relative to 2G — and why this matters even without a capture

This is the analytical point of this tier, and it stands even though no
UMTS AKA exchange was captured here: **3G is where mutual
authentication was actually introduced**, years before LTE.

- The 2G tier's core design gap (`docs/2G-TIER.md`): the network
  authenticates the handset (Authentication Request/Response), but the
  handset has **no way to authenticate the network back**. GSM shipped
  with this gap and never retrofitted a fix.
- **UMTS AKA (TS 33.102) closes this — in 3G, not 4G.** The network's
  Authentication Request in UMTS carries an **AUTN** (Authentication
  Token) alongside the RAND challenge, computed from a shared secret
  key and a sequence number — a value only a legitimate network holding
  the subscriber's key could produce. The handset verifies AUTN itself
  before responding; a network that can't produce a valid AUTN gets
  rejected. This is the exact same mechanism the 4G tier's own EPS-AKA
  writeup (`docs/4G-TIER.md`) describes as "genuinely, structurally"
  fixing the 2G gap — because EPS-AKA is UMTS AKA's direct descendant.
  **The fix arrived in 3G, seven-plus years before LTE**, not in 4G as
  the "LTE fixed 2G" framing might casually suggest.
- **What UMTS AKA did NOT fix: identity concealment.** Exactly like 2G
  and 4G, a UMTS attach with no valid temporary identity (P-TMSI/TMSI)
  sends the subscriber's permanent identity (IMSI) in the clear — 3G
  has no SUCI-equivalent concealment mechanism either. That gap
  survived three full generations (2G → 3G → 4G) before 5G's SUCI
  attempted to close it — and even then, only partially (this lab's own
  5G tier finding: SUCI ships with a null-scheme escape hatch,
  `detector/ngap_detector.py` signal #3).

**The honest four-generation story this lab's four tiers together
tell:** the network-impersonation half of GSM's original gap was fixed
in 3G, not 4G — years earlier than the "LTE introduced mutual auth"
version of the story usually told. The identity-exposure half of that
same story survived every generation's attempt to fix the OTHER half,
all the way through 4G, and was only partially addressed in 5G. This
tier could not capture the 3G fix in action (see above), but the
architecture and the spec both confirm it happened here first.

## Detector: `detector/iuh_detector.py`

One signal implemented, matching what this lab actually captured:

- **HNB-identity allowlist violation** (HNBAP HNB REGISTER REQUEST, TS
  25.469 §9.2.1) — the 3G/Iuh analogue of the 5G tier's signal #5 and
  the 4G tier's signal #16, one layer more primitive: HNBAP's
  id-HNB-Identity IE is an operator-defined string with no mandated
  format (TS 25.469 §9.2.19), so the allowlist matches on the exact
  decoded identity string plus PLMN rather than a numeric ID space.
  Proven against `evidence/3g/iuh-hnb-register.pcap` two ways: a clean
  pass against the correct allowlist (`detector/allowlist_hnb.json`),
  and a genuine violation (verified exit code 1, correct frame/identity
  citation) against a deliberately mismatched one.

**Cleartext IMSI in HNBAP UE REGISTER REQUEST was deliberately NOT
implemented.** This lab never captured a real HNBAP UE REGISTER REQUEST
(see "What was investigated but not built" above) — writing a check
against a message type never observed on the wire, with no way to
verify the relevant tshark field names or behaviour empirically, would
be exactly the hollow detector this project's own conventions warn
against. Full reasoning in the detector's own module docstring.

Run it:

```bash
cd /home/kali/director/projects/cellular-detection-lab
python3 detector/iuh_detector.py --pcap evidence/3g/iuh-hnb-register.pcap \
  --json-out /tmp/iuh-findings.jsonl
```

## GUI evidence

Wireshark GUI screenshots (Xvfb + scrot, same proven capture path the
2G/4G tiers used) are in `evidence/screenshots/`, prefixed `umts-`. See
`evidence/screenshots/README.md` for the caption of each one, including
an honest note on the one field (PLMNidentity's own decoded value) that
did not fit on screen alongside its required parent-node context under
Wireshark's fixed-size window in bare Xvfb — confirmed via the `tshark
-V` text dump instead of a misleading crop.

## Starting and stopping the 3G tier

This tier depends on the 2G tier's `osmo-msc`/`osmo-hlr`/`osmo-stp`
already running (`scripts/2g-tier-start.sh`) — start that first if it
isn't already up.

```bash
cd /home/kali/director/projects/cellular-detection-lab

# Start the 2G tier first if not already running (osmo-msc/osmo-hlr/osmo-stp)
scripts/2g-tier-start.sh a51

# Start osmo-hnbgw (Home NodeB Gateway)
./build/osmo-hnbgw/src/osmo-hnbgw/osmo-hnbgw -c config/osmocom/osmo-hnbgw.cfg &

# Start osmo-hnodeb (software Home NodeB — registers over Iuh automatically)
./build/osmo-hnodeb/src/osmo-hnodeb/osmo-hnodeb -c config/osmocom/osmo-hnodeb.cfg &

# Check the HNB registered:
echo -e 'enable\nshow hnb all' | nc 127.0.0.1 4261     # osmo-hnbgw VTY

# Optional: exercise a real RANAP Reset over Iuh (no UE needed)
echo -e 'enable\nranap reset cs' | nc 127.0.0.1 4273   # osmo-hnodeb VTY
```

Stop (this tier only — the 2G tier and everything else keeps running):

```bash
pkill -f "osmo-hnodeb -c config/osmocom/osmo-hnodeb.cfg"
pkill -f "osmo-hnbgw -c config/osmocom/osmo-hnbgw.cfg"
```

VTY ports (all `127.0.0.1` only): `osmo-hnbgw` 4261, `osmo-hnodeb` 4273.

## Explicit statement of this tier's limits

Stated once already above; restated here for a single place to check
the framing is honest end to end:

- **No RF hardware, no Uu air interface, anywhere in this tier.**
  Everything captured here is SCTP/IP on loopback.
- **No real UMTS handset ever attached.** `osmo-hnodeb` implements only
  HNBAP/RUA/RANAP upper-layer signalling; its lower-layer socket has no
  client anywhere in this build or upstream.
- **No UE registered over Iuh, no RANAP Initial UE Message, no NAS-PS/
  NAS-CS content, and no UMTS AKA/AUTN exchange was captured.** The
  subscriber's real Milenage authentication data was provisioned but
  never exercised.
- **The PS (packet-switched) core (osmo-sgsn/osmo-ggsn) is installed
  but not wired up or started.**
- What WAS captured and is real: an HNB registering over Iuh (HNBAP HNB
  REGISTER REQUEST/ACCEPT) and a RANAP Reset/ResetAcknowledge exchange —
  genuine signalling, on a network this lab owns end to end, with zero
  radio hardware anywhere.
