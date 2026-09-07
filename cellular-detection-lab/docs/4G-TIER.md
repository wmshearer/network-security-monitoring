# The 4G Tier — LTE EPC (no radio hardware, anywhere)

This is the 4G/LTE addition to the lab, built on top of (and independent
from) the 5G Standalone core described in the main `README.md`, and
sitting between the 2G tier (`docs/2G-TIER.md`) and the 5G tier in this
lab's own history of the same recurring problem. Its purpose is narrower
and more precise than either of the other two: 2G has **no mutual
authentication at all** (the network authenticates the handset, never
the reverse); 5G ships **SUCI**, a real identity-concealment mechanism,
but with a documented escape hatch (the null-scheme) and a default
configuration in this lab that uses it. LTE is the generation **in
between**, and it is where the 2G weakness was genuinely, structurally
fixed: **EPS-AKA gives the handset a real cryptographic way to
authenticate the network too**, via the AUTN field in the Authentication
Request, not just the reverse. This tier exists to answer, from real
captured packets, a single question: **did LTE also fix identity
exposure, or only the network-impersonation half of the 2G problem?**

## The short answer, stated up front

**Only the network-impersonation half.** EPS-AKA is real and it works —
this tier's own capture shows a full mutual-authentication exchange. But
LTE's Attach Request still carries the subscriber's permanent identity
(IMSI) **completely in the clear** whenever the UE has no valid GUTI to
present instead — a normal, spec-mandated, unavoidable occurrence, not a
misconfiguration or an attack. This is exactly the gap 5G's SUCI was
later built to close (see the 5G tier's own null-scheme SUCI finding,
`detector/ngap_detector.py`'s signal #3, for the same story one
generation later). The evidence for this claim is in
`evidence/4g/lte-attach-full.pcap`, frame 17, and reproduced below.

## Why this needs no radio hardware at all

Exactly the same property the 5G tier (UERANSIM/UDP sockets) and the 2G
tier (Virtual Um/GSMTAP multicast) already have: the "radio interface"
between the simulated eNodeB and the simulated handset is **srsRAN_4G's
ZMQ virtual-radio driver** — a pair of loopback TCP sockets carrying
baseband I/Q samples, not any RF waveform. `srsenb` (the eNodeB) and
`srsue` (the handset) are the exact same C++ binaries a real over-the-air
srsRAN deployment would run; only the RF front-end is swapped out for
ZMQ. No SDR, no antenna, no RF frontend, and nothing is ever transmitted
over the air, anywhere in this stack.

## Architecture

```
                    ┌───────────────────────────────────────────────┐
                    │              Open5GS 4G EPC                    │
  srsue             │                                                 │
  (simulated  ──ZMQ──▶ srsenb ──S1AP/SCTP──▶ MME ──S6a/Diameter──▶ HSS│
  handset,     loop-  (simulated              │  (mobility mgmt)  (subscriber
  host process) back  eNodeB,                 │  GTPv2-C (S11)    DB + AuC)
                      host process)           ▼
                                            SGW-C ──PFCP──▶ SGW-U ── (data plane)
                                              │  GTPv2-C (S5C)
                                              ▼
                                            PGW-C ──PFCP──▶ PGW-U ── NAT ── host
                                          (smf-4g)  (upf-4g)
                                              │
                                            Gx/Diameter
                                              ▼
                                            PCRF (policy)

  All Open5GS components above are Docker containers on the SAME
  172.22.0.0/24 bridge the 5G tier's containers already use. srsenb and
  srsue are plain host processes (no Docker), reaching the MME over that
  same bridge via the host's own bridge IP (172.22.0.1). No radio, no
  SDR, no over-the-air transmission anywhere in the diagram above.
```

- **EPC (Open5GS 2.8.0, the SAME image already used for the 5G tier)** —
  `open5gs-mmed` (MME), `open5gs-hssd` (HSS), `open5gs-sgwcd`/
  `open5gs-sgwud` (SGW-C/SGW-U), `open5gs-smfd`/`open5gs-upfd` acting as
  PGW-C/PGW-U (same binaries the 5G tier uses for SMF/UPF, run as a
  SECOND, independent pair of containers with 4G-only config — Open5GS
  documents this as the standard way to build a 4G-only EPC deployment),
  and `open5gs-pcrfd` (PCRF, needed here — see "What EPS-AKA changed" and
  "What was harder than expected" below). **Zero new Docker images.**
- **RAN + UE (srsRAN_4G, ZMQ virtual radio)** — `srsenb` simulates the
  eNodeB's S1AP and GTP-U interfaces; `srsue` simulates an LTE handset
  performing NAS EMM/ESM attach and PDN connectivity. Built from source
  (not packaged in Kali) — see "The srsRAN_4G build" below.
- **MongoDB** — the SAME subscriber database the 5G tier already uses.
  Open5GS's subscriber document schema has been unified across 4G and 5G
  since v2.2.0 (`slice[].session[]`), so the 4G HSS reads exactly the
  same shape of document the 5G tier's UDR already writes — no new
  schema was invented for this tier.

## Why these components, not something else

Per the task's own evaluation order, three RAN/UE options were
considered:

1. **UERANSIM** — already in this lab for the 5G tier, but is **5G-SA
   only**. It has no 4G/EPC support at all. Not attempted, per explicit
   instruction — there was never a version of "make UERANSIM do LTE."
2. **srsRAN_4G in ZMQ mode** — the option actually used. Needed a source
   build (`cmake` and `libzmq3-dev` were absent from this host, but both
   are ordinary Kali-rolling apt packages, not missing from the distro
   entirely). See "The srsRAN_4G build" below for exactly what that took.
3. **A packaged/pip-installable S1AP/NAS-EPS traffic generator** — never
   needed; option 2 succeeded.

## The srsRAN_4G build

Cloned from `github.com/srsRAN/srsRAN_4G` (HEAD of `agpl_next`, no
version-pinned release) into `build/srsRAN_4G` (gitignored — source tree
and build artefacts, not committed, same convention as the 2G tier's
OsmocomBB build under `build/`). Six apt packages installed cleanly on
the first attempt (`cmake`, `libzmq3-dev`, `libfftw3-dev`,
`libmbedtls-dev`, `libboost-program-options-dev`, `libconfig++-dev`,
`libsctp-dev` — the host already had `libsctp-dev`, boost, and libconfig
runtime libraries from the 2G tier's own OsmocomBB build).

`cmake ../` configured cleanly and found ZMQ on the first try
(`ZEROMQ_LIBRARIES=/usr/lib/x86_64-linux-gnu/libzmq.so`, the
`srsran_rf_zmq` target linked against it) — no missing-dependency loop.
The one real build failure: `make -j20` failed partway through with

```
lib/src/phy/fec/block/test/block_test.c:79:11: error: writing 1 byte into
a region of size 0 [-Werror=stringop-overflow=]
```

— GCC 15.3.0 (this host) is considerably newer than whatever GCC this
srsRAN_4G snapshot's own CI targets, and its stricter
`-Wstringop-overflow` analysis trips on a **test-only** source file
unrelated to `srsenb`/`srsue` functionality. The project's own
`CMakeLists.txt` already has a documented `ENABLE_WERROR` option
(default `ON`) gating exactly this class of problem. Reconfigured with
`cmake -DENABLE_WERROR=OFF -DENABLE_ALL_TEST=OFF ../` (a supported build
flag, not a source patch) and it built clean end to end on the second
attempt. Full log: `NOTES.md`, "Build log addendum — 4G/LTE tier".

## What EPS-AKA changed, in plain language

GSM's core design gap (`docs/2G-TIER.md`): the network authenticates the
handset, but the handset has no way to authenticate the network back.
LTE's **EPS-AKA** (Evolved Packet System Authentication and Key
Agreement, TS 33.401 clause 6.1) genuinely closes this: the
**Authentication Request** carries not just a random challenge (RAND)
but an **AUTN** (Authentication Token) — a value the home network
computes using a shared secret key (K) and a sequence number, which only
a legitimate network could have produced. The handset independently
verifies AUTN using its own copy of K before it will respond at all; if
AUTN doesn't check out, the handset rejects the challenge outright. This
is a REAL cryptographic mechanism, not cosmetic — a rogue base station
that doesn't know the subscriber's K cannot forge a valid AUTN, and the
handset can detect and refuse the forgery.

**What that fix did NOT touch:** identity concealment. The Attach
Request — the very first message the UE sends, *before* EPS-AKA has run
at all — still carries the UE's identity in an EPS Mobile Identity IE
that is either a **GUTI** (a temporary identity the network issued on a
previous registration) or, whenever the UE has no valid GUTI, the
**IMSI**, sent as plain digits with **no concealment mechanism of any
kind**. TS 24.301 clause 5.5.1.2.2 mandates this exact fallback: a UE
with no valid GUTI (its very first-ever attach, or one the network
invalidated) *must* use IMSI. There was no SUCI-equivalent identity
concealment anywhere in the LTE specification — that mechanism did not
exist until 5G, introduced specifically to close this exact gap (TS
33.501 clause 6.12).

**The consequence, stated precisely:** LTE fixed the half of the 2G
problem that let a rogue base station *impersonate the network* to a
handset. It did not fix the half that lets *any* passive observer on the
S1/radio interface see a subscriber's permanent identity, on a
completely ordinary occasion (first attach, GUTI reallocation), with no
attack required at all.

## Synthetic test subscriber

Same 3GPP-reserved test PLMN as the rest of this lab (999/70), with its
own IMSI so 4G and 5G identities are visibly distinct in any shared
capture or allowlist — Open5GS's HSS (`open5gs-hssd`) reads the exact
same subscriber document shape the 5G tier's UDR already writes, so no
new schema was needed:

| Field  | Value                              |
|--------|-------------------------------------|
| IMSI   | `999700000000099` (MCC 999 / MNC 70, same reserved test PLMN the 5G tier uses) |
| Key (K)| `465B5CE8B199B49FAA5F0A2EE238A6BC` (same value the 5G tier's own test subscriber uses) |
| OPc    | `E8ED289DEBA952E4283B54E88E6183CA` |
| APN/DNN| `internet`                          |

Provisioned via `scripts/provision-subscriber-4g.js` (mirrors
`scripts/provision-subscriber.js`'s own structure).

## Starting and stopping the 4G tier

```bash
cd /home/kali/director/projects/cellular-detection-lab

# Start the 7-container EPC (independent of the 5G tier - see below)
docker compose -f docker-compose.yml -f docker-compose.4g.yml \
  up -d mme hss sgwc sgwu smf-4g upf-4g pcrf

# Provision the test subscriber (only needed once, or after a fresh
# mongo_data volume - shares the SAME MongoDB the 5G tier uses)
docker cp scripts/provision-subscriber-4g.js o5gs-mongo:/tmp/provision-subscriber-4g.js
docker exec o5gs-mongo mongosh --quiet /tmp/provision-subscriber-4g.js

# Start the eNodeB (host process, needs no special privilege)
scripts/lte-run-enb.sh &

# Start the UE (host process, needs sudo for its TUN device)
sudo scripts/lte-run-ue.sh &

# Check the attach succeeded:
tail -f logs/srsran/ue.log        # look for "Network attach successful"
sudo ip addr show tun_srsue       # should show an IP on 10.46.0.0/16
sudo ping -I tun_srsue -c 4 8.8.8.8
```

Stop everything (4G tier only — the 5G tier and its 17 containers are
never touched by any of this):

```bash
sudo pkill -f "srsue ue.conf"
sudo pkill -f "srsenb enb.conf"
docker compose -f docker-compose.yml -f docker-compose.4g.yml \
  stop mme hss sgwc sgwu smf-4g upf-4g pcrf
```

`docker compose up -d` with only `docker-compose.yml` (no `-f
docker-compose.4g.yml`) continues to bring up the 5G tier exactly as
before, completely unaware this tier exists — this file is only ever
combined via `-f`, never merged into the base compose file itself.

## What was harder than expected: the config surface, not the radio

The srsRAN_4G build was the risk this task itself flagged going in, and
it succeeded cleanly (see above). The actual time sink was a chain of
Open5GS configuration bugs, each one a variant of the same mistake:
**copying a Docker service name from Open5GS's own stock, single-EPC-
deployment sample config, unmodified, onto a network where that name is
already taken by the 5G tier's own, different service.** Full diagnosis
of each, with the exact log lines and source-code lines that led to the
fix, is in `NOTES.md`. Summary:

1. **MME/HSS mutual freeDiameter bootstrap race** — each daemon resolves
   its S6a peer's Docker DNS name *at config-parse time*, and Docker
   only registers a name once that container exists — a genuine circular
   cold-start race, fixed with `restart: on-failure` on both services.
2. **LTE Attach silently routed to the 5G tier's own SMF** — MME's
   `gtpc.client.smf` config said `address: smf` (Open5GS's own stock
   template's assumption that "smf" unambiguously means "this
   deployment's one PGW-C"), but on this shared network "smf" is already
   the 5G tier's SMF. Every session request went to the wrong,
   live, already-running container, which accepted the message
   (dormant EPC-interworking code) but could never complete it. Fixed:
   `address: smf-4g`.
3. **PGW-C's classic S5C/GTPv2-C path requires a live Gx (PCRF) peer**,
   unlike the 5G tier's PFCP-only flow — confirmed by reading
   `src/smf/s5c-handler.c` directly. Stood up a `pcrf` service (same
   image, `open5gs-pcrfd` — zero new images) and hit the identical
   stock-template landmine as #2 in `pcrf.conf`'s own `ConnectTo`,
   fixed the same way.
4. **A third, distinct Diameter application (Gy/OCS) falsely detected as
   available**, because freeDiameter's default relay capability makes
   any peer look like it supports every application ID. Fixed with
   `NoRelay;` in this tier's own `pcrf.conf` override.
5. **NAT masquerading the wrong subnet** — the image's own entrypoint
   script defaults `$IPV4_TUN_SUBNET` to the 5G tier's `10.45.0.0/16`
   unless told otherwise. Fixed with an explicit `IPV4_TUN_SUBNET`
   environment variable on `upf-4g`.

None of these are radio-layer problems — every one of them was a Docker/
Diameter/GTP config-routing mistake, found and fixed by reading the
actual Open5GS log line and, in three cases, the actual C source that
produced it, not by guessing from the symptom.

## Evidence

`evidence/4g/lte-attach-full.pcap` (Docker-bridge tshark capture,
`sctp port 36412 or udp portrange 2152-2153 or udp port 2123`) contains
a complete S1 Setup **and** a complete LTE Attach in a single capture:

```
S1SetupRequest / S1SetupResponse
InitialUEMessage, Attach request, PDN connectivity request
DownlinkNASTransport, Authentication request
UplinkNASTransport, Authentication response
DownlinkNASTransport, Security mode command
UplinkNASTransport, Security mode complete
DownlinkNASTransport, ESM information request
UplinkNASTransport, ESM information response
InitialContextSetupRequest, Attach accept, Activate default EPS bearer context request
InitialContextSetupResponse, UplinkNASTransport, Attach complete, Activate default EPS bearer context accept
```

The UE (`srsue`) received IP `10.46.0.2`/`10.46.0.3` on `tun_srsue`
across different runs; both internal (UE → PGW-U gateway) and external
(UE → 8.8.8.8) ping succeeded through the SGW-U/PGW-U data plane —
`evidence/4g/pdu-session-ping-internal.txt`,
`evidence/4g/pdu-session-ping-external.txt`,
`evidence/4g/ue-tunnel-interface.txt`.

## Packet-capture detector: does the evidence support the "only half fixed" claim?

`detector/lte_detector.py` reads S1AP/NAS-EPS message contents directly,
same conventions as `detector/ngap_detector.py` and
`detector/gsm_detector.py` (stdlib + `tshark` subprocess only, no pip
deps). Run against this tier's own real capture, it found:

- **Cleartext IMSI in the Attach Request — FIRED.** Frame 17 of
  `evidence/4g/lte-attach-full.pcap`: EPS Mobile Identity, Type of
  identity IMSI (1), `IMSI: 999700000000099`, visible in plain text.
  This is the direct evidence for this tier's own headline claim above —
  found on this lab's own default configuration (`force_imsi_attach =
  true` in `config/srsran/ue.conf`, chosen deliberately so this always
  reproduces the TS 24.301 "no valid GUTI" case, rather than depending on
  a UE's literal first-ever boot), not contrived after the fact.
- **Null-ciphering in the Security Mode Command — FIRED.** Frame 24:
  `Type of ciphering algorithm: EPS encryption algorithm EEA0 (null
  ciphering algorithm)`, selected for a normal, fully-authenticated
  subscriber whose own advertised capabilities (in the same message)
  include EEA1/EEA2/EEA3. Traced to Open5GS's own **stock, unmodified**
  `ciphering_order: [EEA0, EEA1, EEA2]` default (verified against the
  live `mme.yaml.in` template on GitHub — this is what Open5GS ships,
  not something this lab configured to manufacture a finding) — EEA0 is
  listed FIRST/most-preferred, and Open5GS selects the first mutually
  supported algorithm. Integrity, by contrast, IS real (EIA2/AES) — see
  the next point.
- **Null-integrity in the Security Mode Command — checked, did NOT
  fire.** The same message selected EIA2 (128-bit AES-based integrity)
  for the integrity algorithm — a genuine, working, non-null choice.
  Reported as a clean, checked result (`lte-null-integrity-ok`), not
  silently omitted.
- **Identity Request soliciting IMSI — checked, did NOT fire.** Zero
  Identity Request messages appeared in this capture; the MME never
  needed to ask, since the UE's very first message already carried its
  IMSI. Reported as `lte-identity-request-ok`, same honest-clean-result
  posture the other two detectors use for their own equivalent zero-
  count checks.
- **eNodeB identity allowlist violation (S1 Setup Request) — checked,
  did NOT fire.** `detector/allowlist_lte.json` lists this lab's one
  legitimate eNodeB (PLMN 999/70, macro eNB ID `0x0019b0`, TAC 1); the
  observed S1 Setup Request (frame 5) matched it exactly. A rogue-eNB
  demonstration (a second `srsenb` instance presenting a different eNB
  ID, the 4G analogue of the 5G tier's `gnb-rogue` detection target) was
  **not built for this pass** — a second ZMQ-radio eNB/UE pair needs its
  own distinct TCP port pair and its own radio link, and was judged out
  of scope for the effort remaining; the allowlist LOGIC is implemented
  and verified against the real legitimate eNB (no false positive), the
  same honest partial-completion posture this project takes whenever a
  demonstration wasn't built rather than silently skipping the gap.

Run it yourself:

```bash
cd /home/kali/director/projects/cellular-detection-lab
python3 detector/lte_detector.py --pcap evidence/4g/lte-attach-full.pcap \
  --json-out /tmp/lte-findings.jsonl
```

## GUI evidence

Wireshark GUI screenshots (Xvfb + scrot, same proven capture path the 2G
and 5G tiers used) are in `evidence/screenshots/`, prefixed `lte-`. See
`evidence/screenshots/README.md` for the caption of each one.

## Known limitations

- No rogue-eNB detection target was built for this tier (see "eNodeB
  identity allowlist violation" above) — the allowlist check itself is
  implemented and correct, just not demonstrated against a genuine
  second, unauthorised eNodeB in this pass.
- `lte_detector.py`'s Identity Request signal counts messages per
  capture window, same stateless, single-pass posture (and the same
  documented limitation) as `ngap_detector.py`'s signal #8.
- The S1 Setup allowlist check reads the raw on-wire `macroENB_ID` hex
  string rather than reinterpreting it against `enb.conf`'s own
  `enb_id` value's bit-width — documented in `allowlist_lte.json`'s own
  comments for exactly how to derive the correct value from a real
  capture, same approach `allowlist.json`'s own comments take for NGAP
  gNB IDs.

## Explicit safety statement

No SDR or radio hardware is attached to or referenced by this tier. All
"radio" traffic between `srsenb` and `srsue` is ZeroMQ over loopback TCP
sockets (127.0.0.1:2000/2001); all EPC signalling is SCTP/UDP on the
same private Docker bridge (`172.22.0.0/24`) the 5G tier already uses,
fully contained on this machine. Nothing in this tier connects to,
scans, or interacts with any real cellular network, carrier, or
subscriber. All identifiers (IMSI, K, OPc) are synthetic test values on
the 3GPP-reserved test PLMN 999/70, the same convention the rest of this
lab uses throughout.
