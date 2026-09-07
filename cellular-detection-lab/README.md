# Cellular Detection Lab — 5G Standalone Core (Software-Simulated)

A fully virtual, software-simulated 5G Standalone (SA) network, built as the
foundation for a cellular fault- and rogue-base-station detection lab.

## What this is (and is not)

**This is entirely software. There is no RF hardware anywhere in this stack,
and nothing here ever transmits over the air.** The "radio access network"
(gNB) and the "phone" (UE) are both simulated processes that talk to each
other over plain UDP sockets on a private Docker bridge network. There is no
SDR, no antenna, and no RF frontend of any kind attached to this machine or
referenced by this configuration. If you strip away the 5G terminology, this
is just a handful of Linux processes on a private 172.22.0.0/24 Docker
network exchanging normal IP packets (SCTP for signalling, UDP/GTP-U for the
user plane).

This exists to build hands-on skill in 5G core signalling (NGAP, NAS-5GS,
PFCP) and to give a later detection layer (fault injection, rogue-gNB
simulation, anomaly detection) something real to observe.

## Architecture

```
                      ┌─────────────────────────────────────────────┐
                      │           Open5GS 5G Core (SA)               │
                      │                                                │
  ueransim-ue         │  NRF  SCP  AUSF  UDM  UDR  PCF  NSSF  BSF     │
  (simulated phone) ──┼─▶ AMF  (N2/NGAP, signalling)                  │
  10.45.0.2/16         │  SMF  (session control, PFCP)                 │
  (uesimtun0)          │  UPF  (N3/GTP-U, user plane) ── NAT ── host   │
                      │                                                │
  ueransim-gnb         │  MongoDB (subscriber store) + WebUI (:3000)  │
  (simulated radio) ───┘                                                │
                                                                          │
  All of the above communicate over a single Docker bridge network      │
  (172.22.0.0/24). No radio, no SDR, no over-the-air transmission.       │
  └──────────────────────────────────────────────────────────────────────┘
```

- **Core network (Open5GS 2.8.0)** — one container per network function:
  NRF, SCP, AMF, SMF, UPF, AUSF, UDM, UDR, PCF, NSSF, BSF. All 5G-SA only;
  no IMS/VoLTE, no 4G/EPC components.
- **RAN + UE simulator (UERANSIM 3.3.0)** — `gnb` simulates the gNodeB's NGAP
  (N2) and GTP-U (N3) interfaces; `ue` simulates a 5G NR UE performing NAS
  registration and PDU session establishment. UERANSIM has no RF/PHY layer
  at all — it replaces the entire radio interface with a UDP socket.
- **MongoDB** — subscriber database (IMSI/keys/OPc/slice data).
- **Open5GS WebUI** — subscriber management GUI, port 3000.

## Why these images

We evaluated `herlesupreeth/docker_open5gs`, a well-known all-in-one compose
bundle, but it bundles IMS/VoLTE/eNB/4G components we explicitly do not need
for a 5G-SA-only lab. Instead we hand-wrote a minimal `docker-compose.yml`
using `gradiant/open5gs` (one image, one binary per NF, actively maintained,
version-tagged) and `gradiant/ueransim` (same pattern for gNB/UE). This
keeps the stack small, readable, and fully under our control, at the cost of
having to work through a few container-privilege issues ourselves (see
`NOTES.md`).

- `gradiant/open5gs:2.8.0` — Open5GS 2.8.0
- `gradiant/open5gs-webui:2.7.7` — Open5GS WebUI
- `gradiant/ueransim:3.3.0` — UERANSIM 3.3.0
- `mongo:6.0` — subscriber store

## Synthetic test subscriber

One subscriber is provisioned, using the standard Open5GS/UERANSIM
documentation test values (these are the values published in Open5GS's own
docs/tutorials for exactly this purpose — not a real SIM, not a real
carrier's key material):

| Field  | Value                              |
|--------|-------------------------------------|
| IMSI   | `999700000000001` (MCC 999 / MNC 70 — a 3GPP-reserved test PLMN, never allocated to a real operator) |
| Key (K)| `465B5CE8B199B49FAA5F0A2EE238A6BC` |
| OPc    | `E8ED289DEBA952E4283B54E88E6183CA` |
| APN/DNN| `internet`                          |
| Slice  | SST 1                                |

Provisioned directly into MongoDB via `scripts/provision-subscriber.js`
(the same record the WebUI's subscriber page would create).

## Starting the lab

```bash
cd /home/kali/director/projects/cellular-detection-lab
docker compose up -d
```

Containers come up in roughly this order: `mongo` → core NFs (`nrf`, `scp`,
`ausf`, `udm`, `udr`, `pcf`, `nssf`, `bsf`, `amf`) → `upf`/`smf` → `webui` →
`gnb` → `ue`. `docker compose up -d` starts everything; Compose's
`depends_on` ordering handles the sequencing, but because `open5gs-smfd`
needs `upf`'s DNS entry to exist before it parses its PFCP client config,
give it a few seconds after first boot (or just run `docker compose up -d`
twice) if `smf` is not `Up` after the first `docker compose ps`.

Provision the test subscriber (only needed once, or after a fresh
`mongo_data` volume):

```bash
docker cp scripts/provision-subscriber.js o5gs-mongo:/tmp/provision-subscriber.js
docker exec o5gs-mongo mongosh --quiet /tmp/provision-subscriber.js
```

**Ordering note:** if the `ue` container starts before the subscriber is
provisioned (e.g. on a fresh `docker compose up -d` with an empty database),
UERANSIM's NAS layer gets a hard `FIVEG_SERVICES_NOT_ALLOWED` reject and
gives up retrying on its own. After provisioning the subscriber, restart the
UE container once to force a fresh registration attempt:

```bash
docker restart ueransim-ue
```

Check the UE registered and got a tunnel IP:

```bash
docker logs ueransim-ue
docker exec ueransim-ue ip addr show uesimtun0
docker exec ueransim-ue ping -I uesimtun0 -c 4 8.8.8.8
```

Open5GS WebUI: http://localhost:3000 (default credentials `admin` / `1423`
per upstream Open5GS documentation).

## Monitoring and detection dashboards (Prometheus + Grafana)

Added on top of the core above, purely as read-only observers - **no core
NF service definition or config was modified** to add this (all four NFs
already shipped a `metrics: server:` stanza in their `config/open5gs/*.yaml`
listening on container port 9090; only `docker-compose.yml` gained two new
services, `prometheus` and `grafana`).

- **Prometheus**: http://localhost:9091 — scrapes `amf:9090`, `smf:9090`,
  `upf:9090`, `pcf:9090` by Docker service name (not IP - container IPs are
  not stable across restarts) every 10s. Config: `config/prometheus/prometheus.yml`.
  Check target health at http://localhost:9091/targets or
  `curl -s http://localhost:9091/api/v1/targets`.
- **Grafana**: http://localhost:3001 — **anonymous viewing is enabled**
  (`GF_AUTH_ANONYMOUS_ENABLED=true`, Viewer role), so the dashboards are
  visible immediately with no login. An admin account also exists
  (`admin` / `admin`) if you need to edit a provisioned dashboard in the UI.
  Everything (datasource, dashboard provider, dashboard JSON) is provisioned
  as code under `config/grafana/` and loads automatically on
  `docker compose up -d` — nothing is hand-clicked.

Two dashboards, both under the "5G Detection Lab" folder:

- **5G Core Health** (`config/grafana/dashboards/5g-core-health.json`) —
  is the network doing its job: registered subscribers, gNB/RAN-UE/AMF
  session gauges, registration attempts vs successes vs failures,
  registration procedure time histogram (may show "No histogram found in
  response" - `rm_regtime` is declared by Open5GS but had not yet emitted a
  bucketed sample as of this build; that is an honest empty panel, not a
  broken query), PDU session creation (SMF), N4/PFCP session counters
  (SMF+UPF), and UPF/PCF gauges.
- **Cellular Threat Detection** (`config/grafana/dashboards/cellular-threat-detection.json`) —
  the security tier, built from `docs/DETECTION-SIGNALS.md`'s priority
  list. Centrepiece panel: **authentication failures broken out by 5GMM
  cause**, with cause 20 (MAC failure - forged/replayed challenge) and
  cause 21 (Synch failure - replay/SQN desync) as distinct Prometheus
  series, each with an in-panel description of what it means. Also:
  registration failures by cause, authentication rejects, registration
  request rate (flood detection via `rate()`), registration success ratio
  (collapse detection), RAN-UE-vs-AMF-session divergence (MITM/relay
  signature), and paging request vs success divergence. A text panel notes
  which signals from the catalogue (null-scheme SUCI, cell-identity
  allowlist, 2G cipher-mode/identity-request signatures) are **not**
  representable as Prometheus counters and would need NGAP/NAS/GSMTAP
  packet decoding instead - not fabricated as dashboard panels here.

See `evidence/` for live Prometheus target status, per-metric query
results (before and after a real anomaly-generating event), and PNG
screenshots of both rendered dashboards (`evidence/screenshots/`).

## Packet-capture detector: catching what Prometheus can't see

`detector/ngap_detector.py` reads NGAP/NAS-5GS message *contents* directly
via `tshark` - the Cellular Threat Detection dashboard above explicitly
notes that null-scheme SUCI and cell-identity allowlist violations are
**not** representable as Prometheus counters; this is that missing piece,
built and proven working. Three signals implemented and demonstrated
against real lab traffic:

- **Cell-identity allowlist violation** (NGAP NG Setup Request) — a second,
  intentionally-unauthorised gNB (`ueransim-gnb-rogue`, opt-in via
  `docker compose --profile rogue up -d gnb-rogue`, **not** started by
  default) presents a Global gNB ID/TAC that isn't on
  `detector/allowlist.json`, and the detector catches it. This is the
  proof that the detector works against a real rogue base station in this
  lab, not a simulated one.
- **Null-scheme SUCI** (NAS-5GS Registration Request) — checked against
  this lab's own legitimate UE, genuinely found firing: the default
  `ueransim-ue` configuration has no SUCI public key provisioned, so every
  registration sends the subscriber's permanent identity (SUPI) in the
  clear. Real finding about this lab's own defaults, not a contrived one.
- **Excessive Identity Request** (NAS-5GS) — implemented and unit-verified;
  never observed firing in normal lab operation (zero Identity Requests
  seen to date), reported as an honest checked-and-clean result.

Full writeup, spec citations, and how to reproduce the rogue-gNB
demonstration: `detector/README.md`. Evidence from the actual run:
`evidence/rogue-gnb-detection.pcap`, `evidence/detector-findings.jsonl`,
`evidence/detector-console-output.txt`.

## The 2G tier: GSM over Virtual Um, still no radio hardware

Added on top of everything above, **independently startable/stoppable**
and not sharing any Docker network, port, or container with the 5G core:
a full 2G/GSM network (`osmo-stp`/`osmo-hlr`/`osmo-mgw`/`osmo-msc`/
`osmo-bsc`/`osmo-bts-virtual`) plus a virtual handset (OsmocomBB's
`virtphy` + `mobile`, built from source), connected entirely by GSMTAP
over loopback-only UDP multicast ("Virtual Um") — no SDR, no antenna,
nothing transmitted over the air, exactly the same "these are just UDP
sockets" property the 5G tier above already has.

This tier exists to make GSM's core design gap directly observable: **the
network authenticates the handset, but the handset can never authenticate
the network.** Two textbook IMSI-catcher signatures follow directly from
that gap and are demonstrated here, on this lab's own network, from the
inside:

- **Signal #11** — the network can select A5/0 (null cipher) in the
  Ciphering Mode Command. The same network, subscriber, and procedure,
  with one config line changed (`config/osmocom/osmo-bsc-a50.cfg` vs
  `osmo-bsc-a51.cfg`), produces either a real A5/1-encrypted channel or
  one with no ciphering at all.
- **Signal #12** — the network can send an Identity Request soliciting
  the IMSI in the clear, even to a handset that already holds a valid
  TMSI.

Full architecture, how Virtual Um works, exact start/stop commands, the
OsmocomBB build (not packaged in Kali — built from source), and both
signatures explained in plain language: **`docs/2G-TIER.md`**. Full build
log including every dead end (multicast leaking off loopback, an
undeclared `libosmo-gprs` dependency, a config-ordering VTY parser quirk,
an auth-algorithm mismatch): **`NOTES.md`**. Detector:
**`detector/gsm_detector.py`**, same conventions as `ngap_detector.py`.

```bash
scripts/2g-tier-start.sh a51   # or a50 for the null-cipher demonstration
scripts/2g-tier-stop.sh
```

## The 4G tier: LTE EPC, still zero radio hardware

Added on top of everything above, **independently startable/stoppable**
from the 5G core (same shared Docker network and MongoDB subscriber
store, but its own containers - `docker-compose.4g.yml`, combined via
`-f` with the base compose file). Full 4G/LTE Evolved Packet Core
(MME/HSS/SGW-C/SGW-U/PGW-C/PGW-U/PCRF) on the SAME `gradiant/open5gs:2.8.0`
image the 5G tier already uses - zero new Docker images - plus a real
`srsRAN_4G` eNodeB/UE pair in ZMQ virtual-radio mode (built from source;
UERANSIM cannot do 4G at all), completing a genuine LTE Attach.

This tier sits between the other two for a reason: LTE is where the 2G
gap (no mutual authentication) was actually fixed - EPS-AKA gives the
handset a real cryptographic way to authenticate the network, via AUTN.
But LTE never got a SUCI-equivalent identity-concealment mechanism, so
the Attach Request still carries the subscriber's IMSI in the clear
whenever the UE has no valid GUTI - a normal, spec-mandated occurrence,
not an attack. This lab's own capture proves it: `evidence/4g/
lte-attach-full.pcap` frame 17 shows `IMSI: 999700000000099` in plain
text in the very first message of a completely ordinary Attach, and
frame 24's Security Mode Command selects EEA0 (null ciphering) - Open5GS's
own unmodified stock default - while integrity (EIA2) is genuinely
protected.

Full architecture, the srsRAN_4G build (the one genuine build blocker,
fixed via a documented `-DENABLE_WERROR=OFF` cmake flag, not a source
patch), every Open5GS config landmine hit and fixed (each one a Docker
service name collision with the 5G tier's own same-named service), and
the plain-language identity-exposure finding: **`docs/4G-TIER.md`**.
Full build log: **`NOTES.md`**. Detector: **`detector/lte_detector.py`**,
same conventions as `ngap_detector.py`/`gsm_detector.py`.

```bash
docker compose -f docker-compose.yml -f docker-compose.4g.yml \
  up -d mme hss sgwc sgwu smf-4g upf-4g pcrf
scripts/lte-run-enb.sh &
sudo scripts/lte-run-ue.sh &
```

## Stopping the lab

```bash
docker compose down          # stop and remove containers, keep the mongo volume
docker compose down -v       # also wipe the subscriber database
```

## What "working" means here, and what was actually verified

1. Core network functions running — NRF, SCP, AMF, SMF, UPF, AUSF, UDM, UDR,
   PCF, NSSF, BSF (11 NFs, all 5G-SA-required functions) — `evidence/core-container-status.txt`,
   `evidence/final-container-status.txt`.
2. Test subscriber provisioned — `evidence/subscriber-provisioned.txt`.
3. gNB → AMF NG Setup procedure succeeded — `evidence/gnb-ng-setup.txt`.
4. UE registration + PDU session establishment + `uesimtun0` with IP
   `10.45.0.2` — `evidence/ue-registration.txt`, `evidence/ue-tunnel-interface.txt`.
5. Data plane traffic passes both internally (UE → UPF gateway) and
   externally (UE → 8.8.8.8 through UPF NAT) — `evidence/pdu-session-ping-internal.txt`,
   `evidence/pdu-session-ping-external.txt`.
6. WebUI reachable on port 3000 (HTTP 200, renders the Open5GS login page) —
   `evidence/webui-reachable.txt`.
7. Packet-capture detector (`detector/ngap_detector.py`) proven against a
   real rogue gNB standing up in the lab and joining the same AMF —
   `evidence/rogue-gnb-detection.pcap`, `evidence/detector-findings.jsonl`.

See `NOTES.md` for the full build log, including the two real blockers hit
(UPF's TUN device permissions, SMF's Diameter/CTF init) and exactly how each
was diagnosed and fixed.

## Explicit safety statement

No SDR or radio hardware is attached to or referenced by this lab. All
"radio" traffic is UDP/SCTP on a private Docker bridge network
(`172.22.0.0/24`), fully contained on this machine. Nothing in this
repository connects to, scans, or interacts with any real cellular network,
carrier, or subscriber. All identifiers (IMSI, K, OPc) are synthetic test
values taken from Open5GS/UERANSIM's own published test configuration.
