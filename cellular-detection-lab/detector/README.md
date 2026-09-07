# NGAP/NAS-5GS rogue base-station detector

`ngap_detector.py` reads NGAP and NAS-5GS packet contents directly - things
Prometheus counters cannot express at all, because they only see aggregate
rates, never message contents - and flags rogue-base-station indicators.
Research basis and full signal catalogue: `../docs/DETECTION-SIGNALS.md`.

## Why this exists, in plain language

Prometheus/Grafana in this lab (`../README.md`, "Monitoring and detection
dashboards") can tell you *how many* authentication failures happened per
minute. It cannot tell you *which gNB identity* just sent an NG Setup
Request, *whether* a UE's SUCI was actually encrypted, or *how many times*
the network just asked a phone to hand over its permanent identity. Those
facts only exist inside individual NGAP/NAS-5GS messages on the wire. This
detector reads them there, using `tshark` as the protocol dissector (its
ASN.1 PER decoder for NGAP and IE decoder for NAS-5GS are both mature and
already installed in this lab - see `../NOTES.md`) and reasoning about the
decoded fields in plain Python. No pyshark, no third-party Python packages -
standard library plus `subprocess` calling the system `tshark` binary.

## The three signals implemented

### Signal #5 - Cell-identity allowlist violation (highest value)

**Cellular concept:** every gNB announces itself to the core with an NG
Setup Request the moment it connects, before any authentication of the gNB
itself ever happens - there is no cryptographic proof anywhere in 5G that a
gNB's claimed identity is genuine (3GPP studied this gap directly in
TR 33.809 and closed every proposed fix as "not concluded" - see
`../docs/DETECTION-SIGNALS.md`, "Orientation"). The NG Setup Request carries
the gNB's **Global gNB ID** (PLMN + gNB ID) and its **Supported TA List**
(which Tracking Area Codes it claims to serve). A gNB can put whatever it
wants in these fields.

**Logic:** maintain a list of the (PLMN, gNB ID, TAC) tuples that are
actually supposed to exist (`allowlist.json`). Any NG Setup Request
presenting a tuple that isn't on that list is a candidate rogue base
station. This lab owns ground truth about which gNBs are legitimate, which
is exactly why this check can be 100% reliable *here* - a real-world
detector never gets that luxury, which is the point worth demonstrating.

**Spec citation:** 3GPP TS 38.413 §9.2.6.1 (NG Setup Request: id-GlobalRANNodeID,
id-SupportedTAList IEs).

### Signal #3 - Null-scheme SUCI

**Cellular concept:** a 5G UE's permanent identity (SUPI, effectively an
IMSI) is supposed to be concealed the very first time it's sent to the
network, before any security context exists - it's encrypted into a SUCI
using the home network's public key (ECIES). The **Protection Scheme
Identifier** field inside the SUCI says which scheme was used. Scheme `0`
means **null-scheme**: no encryption was applied, and the SUPI travels as
plain digits in the same message.

**Logic:** TS 33.501 §6.12.2 permits null-scheme in exactly three cases -
emergency registration with no valid 5G-GUTI, a home network deliberately
configured for null-scheme, or a USIM with no home-network public key
provisioned. Outside those, null-scheme defeats the entire purpose of
SUCI. The detector cannot itself know an operator's provisioning policy
(that's out of band), so it reports every null-scheme SUCI as a finding
for a human to check against those three permitted cases - which is
exactly what the spec intends this to be: a rare, deliberate exception,
never a silent default.

**Spec citation:** 3GPP TS 33.501 §6.12.2 (SUCI protection scheme,
null-scheme exceptions).

**What this actually found in this lab, run against real traffic:** the
lab's UE (`ueransim-ue`, no SUCI keys configured - see `../README.md`'s
subscriber table) uses **null-scheme SUCI by default**. `evidence/
detector-findings.jsonl` frame 22 shows the Registration Request's SUCI
with `scheme_id: 0` and the MSIN (`0000000001`) sitting in plaintext right
next to it. This is a genuine finding about this lab's own default
configuration, not a simulated one: UERANSIM ships without ECIES public-key
provisioning configured, so unless an operator explicitly sets one up,
every UE registration re-exposes its permanent identity on the wire. That's
the real-world failure mode signal #3 exists to catch, caught here on the
lab's own legitimate UE talking to its own legitimate gNB - no rogue
anything involved.

### Signal #8 - Excessive Identity Request

**Cellular concept:** NAS-5GS Identity Request is the network asking a UE
"tell me who you are" - normally used sparingly (e.g. the AMF lost track of
a 5G-GUTI after a restart). It is sent as **plain, unprotected NAS** -
no integrity, no ciphering - because it can be sent before a security
context exists. Any device that can inject this message can solicit a
UE's identity. This exact mechanism, in 2G/3G/4G, is the textbook
IMSI-catcher technique, and 5G inherited the same pre-security-context
Identity Request procedure without closing the gap.

**Logic:** count Identity Request messages per UE (keyed by
RAN-UE-NGAP-ID, the per-radio-connection identifier NGAP assigns - not by
IP, since every UE in this lab shares its gNB's IP address at the NGAP
layer) within the capture window. Two or more (configurable via
`--identity-request-threshold`) is reported as IMSI-catcher-shaped
behaviour, especially notable if the UE had already presented a valid
5G-GUTI (meaning the network shouldn't need to ask again at all).

**Spec citation:** 3GPP TS 24.501 §5.4.4 (Identity Request procedure).

**What this found in this lab:** zero Identity Request messages in every
capture taken so far - this lab's AMF has never needed to re-ask a UE for
its identity, because the one provisioned subscriber always registers
cleanly. This is reported explicitly as a good, checked outcome (see
`evidence/detector-findings.jsonl`'s `8-ok` entries), not silently omitted.
The check is implemented and does fire correctly against synthetic input
(verified with a hand-built pcap containing repeated Identity Request
messages during development) - the lab just hasn't produced the real
underlying condition yet, since that would require either a rogue network
actively probing, or the AMF losing GUTI state, neither of which happens in
normal operation.

## Running it

Offline, against an existing pcap:

```bash
cd /home/kali/director/projects/cellular-detection-lab
python3 detector/ngap_detector.py --pcap evidence/rogue-gnb-detection.pcap \
  --json-out /tmp/findings.jsonl
```

Live, against the lab's core Docker bridge (find it with
`docker network inspect cellular-detection-lab_core -f '{{.Id}}'`, then the
interface is `br-<first 12 chars>`; this lab's is `br-89d61b12981f`):

```bash
python3 detector/ngap_detector.py --iface br-89d61b12981f --duration 30 \
  --json-out /tmp/findings.jsonl
```

No `sudo` is required if your user is in the `wireshark` group (this lab's
`kali` user already is) - `dumpcap` carries `cap_net_raw`/`cap_net_admin`
as file capabilities. If capture fails with a permission error, either add
your user to that group (`sudo usermod -aG wireshark $USER`, then re-login)
or run with `sudo`.

Exit code is `0` if no actionable finding fired, `1` if at least one did -
suitable for wiring into a CI gate or cron job.

### Options

| Flag | Meaning |
|------|---------|
| `--pcap PATH` | Offline mode: analyse an existing capture. |
| `--iface IFACE` | Live mode: capture from this interface first. |
| `--duration N` | Live capture duration in seconds (default 30). |
| `--save-pcap PATH` | Live mode: keep the capture instead of deleting it after analysis. |
| `--allowlist PATH` | Cell-identity allowlist file (default: `allowlist.json` next to the script). |
| `--identity-request-threshold N` | Fire signal #8 at N+ Identity Requests per UE (default 2). |
| `--json-out PATH` | Write findings as JSON lines, in addition to the console summary. |

## The allowlist (`allowlist.json`)

The legitimate gNB identity is **never hardcoded into the detector** - it
lives in `allowlist.json`, so the same script works unmodified against a
different lab or a different set of legitimate cells. See the comments in
that file for exactly how to read each field (PLMN, gNB ID, TAC) off a real
NG Setup Request using `tshark`.

## Reproducing the rogue-gNB detection demonstration

This is what actually proves the detector works: a second, unauthorised
gNB container joins the same core, and the detector catches its NG Setup
Request.

**Framing, important:** `ueransim-gnb-rogue` (compose service `gnb-rogue`,
profile `rogue`, not started by default) is a **detection target, not an
attack tool**. It is a stock UERANSIM gNB pointed at the same AMF, whose
only deviation from the legitimate gNB is the Global gNB ID and TAC it
presents in its NG Setup Request (`0xBADDAD` / TAC 666 - deliberately
synthetic and obvious, defined in `../config/ueransim/gnb-rogue.yaml`). It
never intercepts, decrypts, downgrades, or denies service to anything.

```bash
cd /home/kali/director/projects/cellular-detection-lab

# 1. Start a capture on the core bridge (find the bridge name if it
#    differs from this lab's: docker network inspect
#    cellular-detection-lab_core -f '{{.Id}}', then br-<first 12 chars>).
timeout 90 tshark -i br-89d61b12981f -f "sctp port 38412" \
  -w evidence/rogue-gnb-detection.pcap &

# 2. Force the legitimate gNB (and UE) to re-run NG Setup / Registration,
#    so the capture contains a fresh, known-good baseline.
docker restart ueransim-gnb
sleep 4
docker restart ueransim-ue
sleep 10

# 3. Start the rogue gNB (opt-in profile, not part of `docker compose up -d`).
docker compose --profile rogue up -d gnb-rogue
sleep 4

# 4. Stop the rogue gNB - leave the lab in its clean default state.
docker compose --profile rogue stop gnb-rogue
docker compose --profile rogue rm -f gnb-rogue

# (wait for the capture's timeout to finish, then:)

# 5. Run the detector against the capture.
python3 detector/ngap_detector.py --pcap evidence/rogue-gnb-detection.pcap \
  --json-out evidence/detector-findings.jsonl
```

Expected result (already captured in `evidence/`): the legitimate gNB's NG
Setup Request produces a `5-ok` finding (no false positive); the rogue
gNB's NG Setup Request produces a `signal #5 critical` finding naming the
observed identity (PLMN 999/70, gNB-ID 12246445 / `0xBADDAD`, TAC 666)
against the expected allowlisted identity (PLMN 999/70, gNB-ID 16, TAC 1);
and the legitimate UE's own Registration Request in the same capture
produces the genuine `signal #3` null-scheme SUCI finding described above.

## Known limitations

- Signal #5 reads only the **first** Supported TA Item per NG Setup
  Request (via tshark's `occurrence=f`). A gNB legitimately serving
  multiple TACs would need every item checked, not just the first - not
  exercised in this lab, since every gNB here serves exactly one TAC.
- Signal #8's threshold is per capture window, not a sliding window across
  multiple detector invocations - a determined attacker pacing Identity
  Requests one-per-run would evade it. A stateful, cross-run version would
  need to persist per-UE counters somewhere (out of scope here; this
  detector is intentionally a single-pass, stateless tool per its "no
  external dependencies" constraint).
- All three signals require the message to be visible on the observed
  capture point (the core's docker bridge). A rogue gNB that reaches the
  AMF over a path this detector isn't observing would not be seen - this
  is a core-side detector, not a radio-side one (see
  `../docs/DETECTION-SIGNALS.md`, "The core-side advantage").
