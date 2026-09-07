# Build log — Cellular Detection Lab (5G SA, Open5GS + UERANSIM)

Date: 2026-09-06/07. Host: bare-metal Kali, Docker 28.5.2, no SDR/RF
hardware attached, no over-the-air transmission anywhere in this build.

## Decision: minimal hand-written compose, not herlesupreeth/docker_open5gs

`herlesupreeth/docker_open5gs` is active and well-known but bundles
IMS/VoLTE/4G-EPC components that are out of scope for a 5G-SA-only lab. Went
with `gradiant/open5gs` (one image, per-NF binaries, actively tagged up to
2.8.0) and `gradiant/ueransim` (same pattern, up to 3.3.0) in a compose file
we wrote and fully understand. Both image families pulled clean from Docker
Hub and are recently updated (checked tag lists before committing to them).

## What worked first try

- All 11 core NFs (NRF, SCP, AUSF, UDM, UDR, PCF, NSSF, BSF, AMF) started
  cleanly with the image's shipped default config files (`/opt/open5gs/etc/open5gs/*.yaml`),
  which already use Docker-friendly service-name discovery (`scp:`, `nrf:`,
  service DNS names) rather than hardcoded IPs. Only two edits were needed
  across all of them: point `udr.yaml`/`pcf.yaml`'s `db_uri` at the `mongo`
  compose service instead of `localhost`.
- gNB → AMF NG Setup succeeded on the very first attempt once the AMF was
  reachable — UERANSIM's `AMF_HOSTNAME` + `envsubst`-templated config Just
  Worked over Docker DNS.

## Blocker 1: UPF's TUN device — "ioctl(TUNSETIFF): Operation not permitted"

**Symptom:** `o5gs-upf` container exited immediately with
`Creating ogstun device` followed by `ioctl(TUNSETIFF): Operation not permitted`,
even with `cap_add: [NET_ADMIN]` and `devices: [/dev/net/tun]` set in compose
(the textbook fix everyone's tutorial says is sufficient).

**Diagnosis (took 3 real attempts, each with an independent test isolated
from Docker Compose):**

1. First hypothesis: AppArmor's `docker-default` profile blocking the ioctl.
   Tested with `--security-opt apparmor=unconfined` — still failed. Ruled out.
2. Second hypothesis: seccomp blocking it. Tested with
   `--security-opt seccomp=unconfined` and separately with `--privileged`
   alone — still failed (at the time; see note below about a broken test
   harness). This looked like it ruled out capabilities entirely, which was
   momentarily worrying (would have meant a kernel-level host restriction
   unrelated to Docker).
3. Went back to basics and reproduced the *exact same* "Operation not
   permitted" on the **bare host**, as the normal unprivileged user, using a
   raw Python `ioctl(TUNSETIFF)` call — confirming this is standard, expected
   Linux behavior (host root works, host non-root doesn't) and not a Docker
   or Kali-specific issue.
4. Went back to the container tests with a cleaner harness (`--entrypoint sh`
   to bypass the image's own `entrypoint.sh`, which was swallowing output on
   non-daemon commands and had made an earlier "as root, still fails" result
   spurious). With the clean harness: `--user root` + `--cap-add NET_ADMIN` +
   `--device /dev/net/tun` **succeeded**. The open5gs image's default
   container user is UID 999 (`open5gs`), not root — and a non-root UID does
   not get to exercise an added Linux capability like `CAP_NET_ADMIN` for a
   privileged ioctl the way root implicitly can, even though `docker inspect`
   correctly showed the capability as added to the container.

**Root cause:** the `gradiant/open5gs` image runs as UID 999 by default.
`cap_add: NET_ADMIN` alone is not sufficient for a non-root process to
create a TUN device.

**Fix, attempt A (partial):** added `user: root` to the `upf` service. This
got past `TUNSETIFF` but immediately hit a second wall (see Blocker 1b
below), so ended up superseding this with full `privileged: true` instead
(see final fix).

## Blocker 1b: `sysctl: permission denied on key "net.ipv6.conf.all.disable_ipv6"`

**Symptom:** after fixing the TUN permission (as root + NET_ADMIN), the UPF
entrypoint's next line — `sysctl -w net.ipv6.conf.all.disable_ipv6=0` —
failed with `permission denied`, again even as root with NET_ADMIN.

**Diagnosis:** tested the same sysctl write with `--privileged` in isolation
— succeeded immediately. This is a known Docker/kernel interaction: some
`net.ipv6.conf.all.*` wildcard sysctls are gated behind the *initial* user
namespace's privilege in a way that `NET_ADMIN` + a per-container `--sysctl`
declaration does not satisfy; only `--privileged` (or `--network host`)
clears it.

**Final fix:** set `privileged: true` on the `upf` service (in addition to
`user: root`; the explicit `cap_add`/`devices` lines became redundant under
`--privileged` and were removed for clarity). This is scoped to the single
container that legitimately needs raw device/netns access to build the
lab's own virtual tunnel interface — it does not grant any host RF/radio
access, and it does not extend to any other container in the stack (gNB, UE,
and every other core NF still run with default/no elevated privilege except
UE, which needs the same TUN capability for its own `uesimtun0` and already
ran as root by default in the UERANSIM image).

## Blocker 2: SMF `FATAL: smf_fd_init: Assertion 'rv == 0' failed`

**Symptom:** once UPF was up, `o5gs-smf` progressed further but aborted with
a Diameter (`freeDiameter`) config parse error:
`fd_conf_parse@config.c:281: ERROR ... Invalid argument`, tracing back to
`ogs_diam_init`.

**Diagnosis:** the default `smf.yaml` ships `ctf: enabled: auto` plus
`freeDiameter: /opt/open5gs/etc/freeDiameter/smf.conf`. CTF (Charging
Trigger Function, the Gy interface to a PCRF/OCS over Diameter) is a
legacy-EPC/charging feature we have no PCRF for and do not need — this lab
has no offline/online charging component in scope. First attempt (`ctf:
enabled: no`) was not enough: Open5GS still calls `ogs_diam_init` whenever a
`freeDiameter:` key is present in config, independent of the `ctf.enabled`
flag, and that init failed on a name-resolution error inside the shipped
`smf.conf` (`Identity = "smf.gradiant"`, which doesn't resolve to anything
meaningful in this compose network).

**Fix:** removed the `freeDiameter:` key from `smf.yaml` entirely (in
addition to keeping `ctf: enabled: no` for clarity), which skips Diameter
initialization altogether. SMF then started cleanly and immediately
PFCP-associated with UPF.

## Everything else

- WebUI image listens on **9999** internally, not 3000 as most Open5GS
  tutorials assume for the non-containerized install — fixed the port
  mapping to `3000:9999` in compose.
- WebUI's `/api/login` returned 403 to a plain `curl -X POST` even with
  cookies/Origin/Referer set, most likely due to a CSRF token embedded in
  the rendered login page that a scripted client would need to extract
  first. Did not chase this further since the task only requires the WebUI
  to be reachable (confirmed: HTTP 200, correct login page HTML), and the
  test subscriber was already provisioned directly into MongoDB using the
  same schema the WebUI itself writes.
- Subscriber provisioned via a small mongosh script
  (`scripts/provision-subscriber.js`) rather than the WebUI, for
  reproducibility — same effect, same database, same schema version.

## Blocker 3 (minor): UE registers before subscriber exists on a fresh volume

Ran a full `docker compose down -v` / `docker compose up -d` cycle to prove
reproducibility from a completely empty MongoDB volume. On that run the `ue`
container started, as expected, before the subscriber had been provisioned
(provisioning is a manual step run once against the fresh database) and its
Initial Registration got a hard `FIVEG_SERVICES_NOT_ALLOWED` reject from the
AMF — correct behavior for an unknown SUPI. UERANSIM's NAS state machine
treats that as terminal (`MM-DEREGISTERED/NO-SUPI`) and does not keep
retrying on its own. Fix: provision the subscriber, then `docker restart
ueransim-ue` once — it then registers immediately and gets the same
`uesimtun0` / `10.45.0.2` result as the very first run. Documented as an
ordering note in `README.md` rather than something to "fix" in compose,
since the reject is the AMF correctly doing its job.

## End state

Full registration + PDU session + working data plane, both to the UPF's own
gateway address and out through NAT to the public internet (8.8.8.8), on the
first attempt after fixing the three items above. See `README.md` for the
exact evidence files.

## Build log addendum — Prometheus + Grafana detection dashboards (2026-09-07)

Added `prometheus` and `grafana` services on top of the running core.
**No existing core service definition or config file was modified.** All
four instrumented NFs (amf/smf/upf/pcf) already had a `metrics: server:
[{dev: eth0, port: 9090}]` stanza in their shipped `config/open5gs/*.yaml`
from the original build — nothing needed to be turned on.

### What went right first try

- `prom/prometheus:v2.55.1` scraping `amf:9090`, `smf:9090`, `upf:9090`,
  `pcf:9090` by Docker service name came up UP on all four targets on the
  first `docker compose up -d`, no config iteration needed
  (`evidence/prometheus-targets.json`).
- `grafana/grafana-oss:11.3.1` (OSS/AGPL image, confirmed non-enterprise)
  with `config/grafana/provisioning/{datasources,dashboards}` +
  `config/grafana/dashboards/*.json` mounted read-only picked up both
  dashboards automatically on container start — verified via
  `GET /api/search` showing both dashboards under the provisioned "5G
  Detection Lab" folder, no manual import.
- Anonymous Viewer access (`GF_AUTH_ANONYMOUS_ENABLED=true`) confirmed by
  `curl` returning HTTP 200 on both dashboard URLs with no session/cookie.

### Metric-name verification before building panels

Pulled a live scrape from all four NFs before writing any panel query
(`curl` from the host for AMF's already-host-published `:9090`, and a
throwaway `curlimages/curl` container on the `cellular-detection-lab_core`
network for smf/upf/pcf, since none of the NF containers ship curl). Two
things worth recording:

- `fivegs_amffunction_rm_regtime` is a declared histogram
  (`# TYPE ... histogram`) but had emitted **zero** `_bucket`/`_sum`/`_count`
  samples at verification time — it exists in the metric registry but
  Open5GS had not yet recorded a completed timing sample to populate it.
  Included the panel anyway (with an explanatory description) since the
  metric is real and may populate later; Grafana correctly renders "No
  histogram found in response" for it right now, which is an honest empty
  panel, not a wrong query. Confirmed still empty after the anomaly-
  generation step below.
- `fivegs_amffunction_amf_authfail{cause="20"}` (MAC failure) has never
  fired on this lab — only `cause="21"` (Synch failure) has occurred
  historically (see `evidence/metrics-authfail-cause-label.txt`, captured
  2026-09-06). Prometheus does not emit a zero-valued series for a label
  combination that has never occurred, so the "cause 20" legend entry is
  correctly absent from the dashboard rather than shown as a flat zero
  line. This is real Prometheus/Grafana behaviour, not a dashboard bug.

### Anomaly-generation step (proving live data, not just live wiring)

Restarted `ueransim-ue` twice in succession (no attack tooling, no flood,
nothing touching an external network) to force fresh NAS Initial
Registration + Authentication Request cycles against the live AMF.
`fivegs_amffunction_rm_reginitreq`/`rm_reginitsucc`/`amf_authreq` all
incremented by 1 per restart, visible both via direct Prometheus API query
and in the rendered Grafana panels (`evidence/anomaly-generation-log.txt`,
`evidence/prometheus-panel-queries-before-anomaly.txt`,
`evidence/prometheus-panel-queries-after-anomaly.txt`). Both restarts
produced clean re-registrations (Open5GS's per-subscriber SQN state stayed
synchronized across a container restart, which is correct behaviour) —
this did **not** reproduce a fresh cause-20/21 auth failure, and that is
stated plainly rather than faked. The historical cause=21 event from the
original build is still visible and correctly attributed because
Prometheus counters are cumulative and were never reset.

### Screenshots

Chromium 150 (already installed on this host) is available for headless
rendering — no extra install needed. `chromium --headless --disable-gpu
--no-sandbox` alone produced a screenshot of only the page chrome (panels
hadn't finished their async data-fetch/render by the time the screenshot
fired). Fixed by adding `--virtual-time-budget=8000
--run-all-compositor-stages-before-draw` and using each dashboard's kiosk
URL (`?orgId=1&kiosk`) — both screenshots then show fully rendered panels
with real data and are saved at `evidence/screenshots/5g-core-health.png`
and `evidence/screenshots/cellular-threat-detection.png`.

### Nothing else on the host was touched

Verified `opencti-*` and `rita_default`-network containers were untouched
(different Docker network, different ports) and every pre-existing core
container (`o5gs-*`, `ueransim-*`) remained `Up` throughout, confirmed via
`docker compose ps` before and after.

## Build log addendum — Packet-capture NGAP/NAS-5GS detector + rogue gNB (2026-09-07)

Built `detector/ngap_detector.py` (stdlib + `tshark` subprocess only, no
pyshark, no third-party Python packages) implementing signals #5
(cell-identity allowlist), #3 (null-scheme SUCI), and #8 (excessive
Identity Request) from `docs/DETECTION-SIGNALS.md`, plus a second
UERANSIM gNB (`gnb-rogue` compose service, `rogue` profile, opt-in only)
presenting an unauthorised identity to prove signal #5 catches a real
rogue base station in this lab, not a simulated one.

### Field discovery, from real captures, before writing any detection logic

Captured the legitimate gNB's actual NG Setup Request and the UE's actual
Registration Request first, then read tshark's own `-T json` output to
find the real field names, rather than guessing from documentation:

- NG Setup Request Global gNB ID: `e212.mcc` / `e212.mnc` (PLMN),
  `ngap.gNB_ID` (colon-or-not hex octet string, parse as unsigned int),
  `ngap.tAC` (decimal). Verified against this lab's own `gnb.yaml`:
  `nci: '0x0000000100'` with `idLength: 32` decodes to gNB-ID `0x10` (16) -
  confirmed by direct capture, not just arithmetic.
- NAS-5GS SUCI: `nas-5gs.mm.suci.scheme_id` (0 = null-scheme),
  `nas-5gs.mm.suci.msin` (plaintext when scheme_id is 0). No dedicated
  `nas-5gs.mm.suci.mcc`/`.mnc` fields exist in this tshark version (4.6.6) -
  removed from the field list after `tshark` reported them invalid at
  runtime, rather than left in as silently-empty columns.
- NAS-5GS message types confirmed via `tshark -G values`: Registration
  Request = 65 (0x41), Identity Request = 91 (0x5b), Registration Reject =
  68 (0x44) - read from tshark's own value_string table, not assumed from
  a spec table, since the wire value is what the detector actually filters
  on.

### Real bug found and fixed during verification: silent row misalignment across two tshark calls

First implementation of the allowlist check queried `ngap.tAC` in a
*separate* `tshark -T fields` invocation from the PLMN/gNB-ID fields (on
the theory that TAC lives in a different nested IE), then `zip()`-ped the
two row lists together by position. Against the real rogue-gNB capture,
this silently produced a **wrong pairing**: `tshark -T fields` only emits a
row for a packet if at least one of *that specific call's* requested
fields is non-empty for that packet, so a capture containing an
NGSetupResponse/Failure alongside each NGSetupRequest gave the two calls
different row *counts* (4 rows for the PLMN/gNB-ID call, 2 rows for the
TAC-only call), which `zip()` paired positionally rather than by frame
number - frame 16 (an NGSetupResponse, no gNB-ID) silently got matched
against frame 26's TAC (666). This surfaced as the detector reporting an
`incomplete`/warning finding instead of firing on the real rogue NG Setup
Request in frame 26 - caught by manually inspecting the detector's raw
per-row output against `tshark -r ... -V` ground truth for the same
frames, not by trusting the summary line.

**Fix:** pull every field the allowlist check needs (PLMN, gNB ID, TAC,
RANNodeName) in a **single** tshark invocation, and filter on
`ngap.NGSetupRequest_element` (the message-type-specific element) rather
than `ngap.procedureCode == 21` (id-NGSetup, which is shared by
NGSetupRequest, NGSetupResponse, *and* NGSetupFailure - all three are the
same "procedure", different message types). This eliminates both the
row-count mismatch and the need to distinguish request-vs-response rows
after the fact. Re-verified against the same capture: correct pairing,
correct finding, on the first re-run after the fix.

### Rogue gNB: NG Setup rejected by the AMF, which does not matter for detection

`config/ueransim/gnb-rogue.yaml` presents gNB-ID `0xBADDAD` (nci
`0x0baddad0`, idLength 32) and TAC 666 - both deliberately synthetic and
obviously not real values. Open5GS's AMF rejects this NG Setup Request
with `Cause: Misc=unknown-PLMN-or-SNPN` (TAC 666 isn't in the AMF's own
supported-TA config), so the rogue gNB never reaches "Running"/associated
state. This is **expected and does not affect the demonstration**: the
NG Setup Request itself was sent, was captured on the wire, and is exactly
what signal #5 needs to see - a rogue gNB doesn't need to be accepted by
the core to prove the detector can spot its unauthorised identity; in a
real attack scenario, an operator would want exactly this AMF-level
rejection PLUS the detector's earlier warning, not one or the other.

### Full working proof, in one capture (`evidence/rogue-gnb-detection.pcap`)

Single ~90s capture on the core's docker bridge (`br-89d61b12981f`,
`sctp port 38412`) containing, in order: the legitimate gNB's NG Setup
Request (accepted), the legitimate UE's fresh Registration Request
(genuine null-scheme SUCI), the rogue gNB's NG Setup Request (rejected by
AMF, but seen and flagged by the detector), and the rogue gNB's clean
shutdown. Running `detector/ngap_detector.py` against this single pcap
produces, from real traffic with no fabrication:

- `5-ok` on the legitimate gNB's NG Setup (no false positive).
- `5` / critical on the rogue gNB's NG Setup, naming observed
  (PLMN 999/70, gNB-ID 12246445 / `0xBADDAD`, TAC 666) against expected
  (PLMN 999/70, gNB-ID 16, TAC 1).
- `3` / high on the legitimate UE's own Registration Request - a genuine
  finding about this lab's own default config, not contrived.
- `8-ok` - no Identity Requests observed (checked, clean, not silently
  omitted).

Live-capture mode (`--iface br-89d61b12981f --duration N`, no pcap file
needed) verified working end-to-end without `sudo`, since the `kali` user
is already in the `wireshark` group and `dumpcap` carries
`cap_net_raw,cap_net_admin` as file capabilities.

### Lab left in clean default state

`docker compose --profile rogue stop gnb-rogue && docker compose --profile
rogue rm -f gnb-rogue` after the evidence capture - confirmed via
`docker compose ps` that only the original 16 containers remain, with no
`gnb-rogue`/`ueransim-gnb-rogue` container present.

## Build log addendum — 2G tier, Virtual Um core-side stack (2026-09-07)

Building the 2G/GSM tier per `docs/2G-TIER.md` (not yet written at this
point in the log - see final version). This addendum covers steps 1-3 of
the build order: apt packages, configs, and BTS-to-BSC link.

### Packages installed (apt, Kali repos)

| Package | Installed version |
|---------|-------------------|
| osmo-stp | 2.1.0-3+b1 |
| osmo-hlr | 1.9.4+dfsg1-1 |
| osmo-mgw | 1.15.0+dfsg1-1 |
| osmo-msc | 1.13.0+dfsg1-2 |
| osmo-bsc | 1.13.0-2 |
| osmo-bts | 1.9.0+dfsg1-2 (ships `/usr/bin/osmo-bts-virtual`) |

All installed with systemd units present but **disabled/inactive**
(`osmo-*.service` all showed `disabled disabled` in `systemctl
list-unit-files` before any manual start) - confirmed no conflict with
running these as plain foreground/background processes per the task's
"start simple" instruction. `osmo-mgw` was not in the original apt-install
list from the task brief but turned out to be required: both
`osmo-bsc.cfg` and `osmo-msc.cfg`'s shipped examples reference an `mgw
0 remote-ip/remote-port` client config, and both daemons refuse to
proceed cleanly without an MGW to connect to (even though this lab never
places a voice call - the MGCP client connection is set up at daemon
start regardless). Installed via `apt install osmo-mgw`, worked with a
minimal config.

### Config approach

All configs live in `config/osmocom/`, based directly on the
package-shipped examples in `/etc/osmocom/*.cfg` and
`/usr/share/doc/osmo-{bsc,msc,hlr,stp}/examples/`, with only PLMN and
lab-specific values changed:

- PLMN: MCC **001** / MNC **01** (the two-digit-MNC form of the 3GPP test
  network) - matches the sample `mobile.cfg` from Osmocom's own Virtual Um
  wiki page (see below), which provisions its test SIM as `imsi
  001010000000001` and `rplmn 001 01`.
- LAC 1 (`0x0001`), Cell Identity 1, BSIC 63 - the same obviously-fake
  test values already used by the package's own `osmo-bsc.cfg` example
  (`cell_identity 6969` was changed to `1`; everything else kept as
  shipped, since it's a working reference config, not a production one).
- `ipa unit-id 6969 0` kept identical between `osmo-bsc-a5*.cfg`'s `bts 0`
  stanza and `osmo-bts-virtual.cfg`'s `bts 0` stanza - this is the value
  the BSC uses to recognize which physical BTS connection belongs to
  which configured `bts 0` entry (confirmed via the Virtual Um wiki page,
  which calls this out explicitly as one of only two values that must
  match your local config).
- **Two BSC config variants**, `osmo-bsc-a51.cfg` (baseline,
  `encryption a5 1`) and `osmo-bsc-a50.cfg` (demo, `encryption a5 0` -
  null cipher only) - identical in every other line, by design, so the
  single-line diff *is* the signal #11 demonstration (see
  `docs/2G-TIER.md`).

### Osmocom's own Virtual Um wiki page (verified primary source)

`https://projects.osmocom.org/projects/cellular-infrastructure/wiki/Virtual_Um`
(fetched 2026-09-07) confirmed the exact facts the task brief predicted,
plus new details not in the brief:

- Downlink GSMTAP multicast group: **239.193.23.1**, port **4729**
  (confirmed, matches the brief).
- There are **two separate multicast groups**, one uplink one downlink -
  the brief's "ports 4729/4730 for the two directions" was directionally
  right but it's actually two *addresses* (239.193.23.1 downlink,
  239.193.23.2 uplink per `strings /usr/bin/osmo-bts-virtual`), not two
  ports on the same address - corrected via direct binary inspection, not
  assumed from the brief.
- `virtphy` needs **zero configuration** - it hardcodes the multicast
  group/port and just needs to be run.
- The wiki's own downloadable `mobile.cfg` attachment (fetched directly,
  `attachments/download/2717/mobile.cfg`) is a complete, working
  OsmocomBB `mobile` config using `sim test` (software SIM emulation,
  required since `virtphy` implements no physical/virtual SIM card
  itself) with `test-sim imsi 001010000000001 / ki xor 00...00 / rplmn
  001 01` - used verbatim as the basis for this lab's MS config (only the
  IMSI kept, since it's already a synthetic 3GPP-test-PLMN value with an
  all-zero placeholder Ki, not a real credential).

### Real dead end found and fixed: GSMTAP leaking onto the LAN NIC, not loopback

First attempt at the BTS-to-BSC link came up fine (OML/RSL both showed
connected), but a `dumpcap -i lo` capture of the GSMTAP multicast traffic
came back **empty** - looked like a broken link even though the VTY
showed both link types connected. Diagnosis: `ip route get
239.193.23.1` resolved to `wlan0` (this host's actual WiFi NIC), not
`lo` - the kernel picks an outbound interface for a multicast destination
based on the default *unicast* route unless told otherwise, and this
host's default route is via `wlan0`. Capturing on `wlan0` instead showed
the GSMTAP traffic immediately (BCCH/CCCH System Information, Paging
Request). This matches the Virtual Um wiki's own caveat almost verbatim
("on a typical workstation... the multicast traffic should appear on
[the interface with the default route]") - not a bug, expected upstream
behaviour, but wrong for this lab's "loopback only" requirement.

**First fix attempt (insufficient alone):** added a host route
`sudo ip route add 239.193.23.1/32 dev lo`. This did NOT change the
outbound interface - osmo-bts-virtual's multicast socket setup evidently
does not re-consult the routing table per-packet in a way this static
route affects; traffic kept appearing on `wlan0` (source address stayed
`192.0.2.93`, this host's WiFi address) even with the route present.

**Actual fix:** osmo-bts-virtual has an undocumented-in-the-wiki (but
present in its own VTY grammar - confirmed via `--vty-ref-xml` and
`strings` on the binary) `virtual-um net-device NETDEV` config line under
the `phy 0`/`phy 0 instance 0` stanza, which explicitly binds the
multicast TX/RX sockets to a named interface via `osmo_sock_mcast_iface_set`.
Added `virtual-um net-device lo` to `osmo-bts-virtual.cfg`; after
restarting osmo-bts-virtual, GSMTAP traffic confirmed appearing on `lo`
and **confirmed absent** from `wlan0` (zero packets in a 5-second
`dumpcap -i wlan0` capture with the BTS actively transmitting BCCH). This
is a genuinely better fix than the route-only approach: it constrains the
traffic at the socket level regardless of what the host's routing table
says, which is more robust and more clearly satisfies "loopback only,
nothing touches the LAN" than a routing-table-only fix would have been.
The `ip route add ... dev lo` static route was kept anyway (harmless,
and belt-and-suspenders for any other multicast-aware Osmocom process
started later, e.g. `virtphy`), and is now added idempotently by
`scripts/2g-tier-start.sh`.

**Caveat worth recording plainly:** the TTL on the leaked `wlan0` packets
was 1, meaning even the "wrong-interface" traffic could never have left
the local Ethernet/WiFi broadcast domain (TTL=1 multicast dies at the
first router hop) - so at no point was there any risk of this reaching
a real network beyond this host's own LAN segment, and at no point was
there ever any RF/cellular-waveform transmission of any kind (this is
IP-over-Ethernet/WiFi multicast, categorically unrelated to a GSM radio
interface) - but "confirmed harmless if it happened" is not the same
bar as "confined to loopback as designed", so the `net-device lo` fix
was pursued and applied rather than accepted as good enough.

### Milestone: BTS-to-BSC link established (checkpoint, step 3 of the build order)

`osmo-bsc`'s own `show bts` VTY output (127.0.0.1:4242) confirms, from a
clean process start via `scripts/2g-tier-start.sh`:

```
OML Link: (r=127.0.0.1:<ephemeral><->l=127.0.0.1:3002)
OML Link state: connected 0 days 0 hours 0 min. N sec.
Number of RSL links connected (same as num_trx:rsl_connected): 1
Number of TRX in this BTS where RSL is up: 1
```

And the BSC's own log line confirms the RSL bootstrap used the correct
synthetic PLMN: `bootstrapping RSL on ARFCN 871 using MCC-MNC 001-01
LAC=1 CID=1 BSIC=63`. Evidence:
`evidence/2g/checkpoint-oml-rsl-link.txt`,
`evidence/2g/bsc-show-bts-checkpoint.txt`.

### Start/stop scripts

`scripts/2g-tier-start.sh [a50|a51]` and `scripts/2g-tier-stop.sh` -
tested end-to-end (full stop from a running state, confirm all six
processes exit, full cold start, confirm OML/RSL link re-establishes and
GSMTAP reappears on loopback). Confirmed throughout that the 5G tier's 17
containers stayed `Up` and untouched (`docker ps` before/after).

### Next up

Step 4-5 of the build order: build OsmocomBB from source (`virtphy` +
`mobile` are not packaged in Kali) and attach a virtual handset for a
LOCATION UPDATE. This is the highest-risk remaining step per the task
brief's own risk assessment - logging attempts as they happen below.

## Build log addendum — OsmocomBB (virtphy + mobile) built from source (2026-09-07)

Step 4 of the build order. This was the task's own flagged highest-risk
step, and it did hit a real, non-trivial blocker - logged in full below,
including the dead end before the fix.

### Sources cloned

| Repo | URL | Commit built |
|------|-----|--------------|
| osmocom-bb | `https://gitea.osmocom.org/phone-side/osmocom-bb.git` | `6fef14bc6dbdd0370ce1cfff856fc6b10827db50` (2026-04-11) |
| libosmo-gprs | `https://gitea.osmocom.org/osmocom/libosmo-gprs.git` | `e96ddd833251845e5c625e92b121d6bcabe6f3d3` (2026-07-27) |

Both cloned with `--depth 30/50` (shallow, we only need a buildable HEAD,
not full history). Checked out into `build/` (gitignored - source trees
and build artefacts are not committed, only this log and the resulting
commit hashes).

### `virtphy` - built on the first attempt, no blockers

`src/host/virt_phy` only needs system `libosmocore`/`libosmogsm`
(confirmed via its `configure.ac` - just two `PKG_CHECK_MODULES` calls).
Installed `libosmocore-dev` (1.14.2-1, a single Debian dev package that
also ships the vty/gsm/coding/codec pkg-config files - confirmed via
`pkg-config --modversion libosmocore libosmogsm libosmovty libosmocodec
libosmocoding libosmoctrl`, all report 1.14.2). `autoreconf -fi &&
./configure && make -j$(nproc)` completed clean (only obsolete-macro
warnings from autoconf itself, zero compile errors). Binary confirmed at
`build/osmocom-bb/src/host/virt_phy/src/virtphy`, and its `--help`
confirms the exact multicast/interface options the Virtual Um wiki page
described plus one it didn't mention: `-D/--mcast-dev NETDEV` to bind to
a specific interface (the same fix used for osmo-bts-virtual's
loopback-confinement, see the "2G tier" addendum above).

### `mobile` (layer23) - real blocker found: undeclared external dependency on `libosmo-gprs-*`

`src/host/layer23/configure.ac` unconditionally requires five
pkg-config modules that turned out to be **not packaged anywhere in
Kali/Debian and not vendored inside the osmocom-bb tree**:
`libosmo-gprs-rlcmac`, `libosmo-gprs-llc`, `libosmo-gprs-sndcp`,
`libosmo-gprs-gmm`, `libosmo-gprs-sm` (confirmed via `apt-cache search
libosmo-gprs` returning nothing, and `pkg-config --exists
libosmo-gprs-rlcmac` failing). This is a genuine, undocumented (by the
task brief - reasonably so, since it's an implementation detail one
level deeper than "OsmocomBB isn't packaged") extra dependency: modern
OsmocomBB's `mobile` binary links GPRS/PS support in unconditionally
(`grep`'d `src/mobile/Makefile.am`, confirmed the GPRS libs are linked
into the `mobile` binary itself, not just the separate `modem` app) even
though this lab only needs CS (circuit-switched) Location Update, not a
GPRS/PS attach.

**First reaction considered and rejected:** patching `configure.ac` to
drop the `PKG_CHECK_MODULES` lines for the GPRS libs. Rejected without
trying, because the actual object files in `src/mobile/Makefile.am` are
compiled against those libraries' headers/symbols - stripping the
configure check would only push the failure to the link stage with a
worse error message, not avoid the dependency.

**Fix:** `libosmo-gprs` is itself a real, separate Osmocom project
(confirmed via web search - `gitea.osmocom.org/osmocom/libosmo-gprs`,
implements RLC/MAC, LLC, SNDCP, GMM, SM per 3GPP TS 44.060/44.064/44.065
etc.), also autotools-based, with its own `configure.ac` depending on
nothing but system `libosmocore`/`libosmogsm` >= 1.10.0 (already
satisfied by the 1.14.2 installed above). Cloned and built it exactly
the same way as virtphy (`autoreconf -fi && ./configure && make -j$(nproc)`,
clean build, zero errors), then `sudo make install` (installs to
`/usr/local/lib` + `/usr/local/lib/pkgconfig`, the standard prefix) and
`sudo ldconfig` to refresh the linker cache. Re-ran `pkg-config
--modversion` for all five GPRS modules afterward - all report
`0.2.1.1-e96d`, confirming they're now discoverable.

**Result after the fix:** `src/host/layer23`'s own `./configure`
succeeded cleanly (all five `libosmo-gprs-*` checks now report `yes`),
and `make -j$(nproc)` built `mobile` with zero errors (a handful of
harmless deprecation/unused-variable warnings, e.g.
`lapdm_channel_init` being superseded by `lapdm_channel_init3` upstream -
not touched, since it's a working warning in upstream's own code, not
something this lab's build introduced). Binary confirmed at
`build/osmocom-bb/src/host/layer23/src/mobile/mobile`.

**Lesson for the log, stated plainly:** the task brief predicted the
OsmocomBB build itself would be the fiddly part, and it was right, but
the actual blocker was one dependency layer removed from what the brief
anticipated (not the ARM cross-toolchain, which turned out to be
unnecessary for the *host* tools `virtphy`/`mobile` - only needed for
building real phone firmware, which this lab never does) - it was a
second, separate from-source Osmocom project (`libosmo-gprs`) that
current `mobile` silently requires even for pure 2G-CS use. Both builds
together took under 10 minutes of actual compile time; the time cost was
almost entirely in diagnosing *which* package was missing, not in
compiling it once identified.

### No RF, no cross-compilation, no firmware build anywhere in this path

`osmocom-bb/src/README.building`'s "How to build" section describes
building **firmware for a real phone target** (needs an ARM
`arm-elf-*` cross-toolchain) - that path was never touched. Only
`src/host/virt_phy` and `src/host/layer23` (both plain host-native x86_64
builds against system libraries) were built, which is exactly and only
what Virtual Um needs; no phone firmware, no SDR, no radio driver of any
kind was built or touched.

## Build log addendum — Virtual handset attach, full LOCATION UPDATE with zero radio (2026-09-07)

Step 5 of the build order - THE MILESTONE. Hit one more real blocker
(uplink multicast group leaking to the LAN NIC, same class of bug as the
downlink one already fixed for osmo-bts-virtual, but this time on
`virtphy`'s side and only affecting one of its two multicast groups) -
documented in full below since it directly explains why the first
several attempts silently stalled instead of erroring.

### Subscriber provisioning (osmo-hlr VTY)

```
subscriber imsi 001010000000001 create
subscriber imsi 001010000000001 update aud2g xor-2g ki 00000000000000000000000000000000
```

IMSI matches the Osmocom Virtual Um wiki's own reference `mobile.cfg`
(`001010000000001`, on the 3GPP test PLMN 001/01). Ki is all-zero,
XOR-2G algorithm (matches `mobile.cfg`'s `ki xor 00 00 00 00 00 00 00 00
00 00 00 00`) - both synthetic, no real credential of any kind.

### Dead end found and fixed: `mobile.cfg`'s VTY grammar rejects the wiki's own reference file on this build

The Virtual Um wiki's downloadable `mobile.cfg` (used as the starting
point, see the "2G tier" addendum above) does **not** parse against this
lab's built `mobile` binary - `Inconsistent indentation` errors that
have nothing to do with actual whitespace (confirmed byte-for-byte
identical indentation to a config the same binary itself considers
valid). Diagnosed by generating a known-good baseline directly from the
binary's own VTY (configure the `ms 1`/`test-sim`/`support` nodes
interactively, then `show running-config`) and diffing structurally
against the wiki file:

- The wiki file places `test-sim { ... } exit` **after** `support { ...
  } exit`. The binary's own generated config places `test-sim { ... }`
  (no explicit trailing `exit` line - the next sibling command at the
  same indent depth is what signals the dedent) **immediately after**
  `sim test`, before `support`.
- Reordering to match the generated form fixed it. Root cause not fully
  understood (likely a state-machine edge case in this specific
  commit's generated VTY parser code when transitioting out of the
  `test-sim` child node via an explicit `exit` versus an implicit
  dedent) - documented as a workaround, not a full explanation, since
  chasing it further into libosmocore's VTY code generator was out of
  scope for what's otherwise a working config.
- Final `config/osmocom/mobile.cfg` is therefore built directly from
  this binary's own generated output (values changed: ARFCN 871, IMSI/Ki/
  rplmn/hplmn-search from the wiki's synthetic test values, `no
  shutdown` to power on at start) rather than hand-authored from the
  wiki example, specifically to avoid re-triggering this fragility.
- Separately, the wiki file's `gps host/device/baudrate/enable` lines
  under `ms 1` don't exist as VTY commands in this build (no GPS/gpsd
  support compiled in - `libgps-dev` not installed, not needed here);
  the generated config correctly has `gps device`/`gps baudrate`/`no gps
  enable` as **top-level** nodes instead, with no `gps host` at all.

### Real blocker found and fixed: uplink Virtual Um multicast (239.193.23.2) also leaked off loopback

After fixing the config, `mobile` started, camped on the cell
(`show ms` reported `cell selection state: C3 camped normally,
ARFCN=871(DCS) CGI=001-01-1-1`), and began a Location Update attempt -
then stalled indefinitely in `radio resource layer state: connection
pending` / `mobility management layer state: wait for RR connection
(location updating)`, retransmitting its RACH Channel Request four times
with no response, never progressing.

**Diagnosis:** a `dumpcap -i lo` capture during a stalled attempt showed
the MS's Channel Request messages genuinely being sent
(`192.0.2.93 -> 239.193.23.2 GSMTAP (RACH) Channel Request`, 4 retries)
but **zero** corresponding activity in osmo-bts-virtual's own log (no
RACH-received line at all) - the BTS was not receiving them. This is the
same class of bug already fixed for the BTS's *downlink* group
(239.193.23.1, see the "2G tier" addendum above): `ip route get
239.193.23.2` showed it resolving to `wlan0`, not `lo` - a static
loopback route had only been added for `.1` (the group osmo-bts-virtual
transmits on), not `.2` (the group virtphy transmits on and
osmo-bts-virtual must receive on). `virtphy`'s own `-D/--mcast-dev`
option was already passed (`virtphy -D lo`), which correctly bound
*virtphy's* send/receive sockets to loopback (confirmed: the Channel
Request WAS visible via `dumpcap -i lo`) - but osmo-bts-virtual's
receive socket for the *uplink* group had been set up (at its last
start, before this diagnosis) while `239.193.23.2`'s route still pointed
at `wlan0`, so its multicast group *membership join* used the wrong
interface even though the packet was reaching `lo` at the OS level.

**Fix:** `sudo ip route add 239.193.23.2/32 dev lo` (mirroring the
existing `.1` route), then **restart osmo-bts-virtual** (multicast group
membership is joined at socket-setup time, not re-evaluated per-packet -
confirmed this same lesson once already for the downlink case, see
above - so an already-running osmo-bts-virtual process does not pick up
a route added after it started). After the restart (OML/RSL
re-confirmed connected), and a fresh `virtphy`/`mobile` start, the RACH
Channel Request was answered immediately and the Location Update
completed within one RACH attempt (5.2s into the capture, no retries
needed).

**Lesson generalized for `scripts/2g-tier-start.sh`:** both multicast
groups (`239.193.23.1` AND `239.193.23.2`) must have their loopback
route added **before** osmo-bts-virtual's first start in any given
session - the start script was updated accordingly (see below).

### MILESTONE: full LOCATION UPDATE completed, zero radio hardware anywhere

`evidence/2g/location-update-a51-encrypted.pcap` - captured on loopback
via `dumpcap -i lo -f "udp portrange 4729-4730"` while `mobile` performed
a fresh Location Update against the encrypted (`osmo-bsc-a51.cfg`,
`encryption a5 1`) BSC config. `mobile`'s own VTY confirms the end
state:

```
show ms
MS '1' is up, service is normal
  automatic network selection state: A2 on PLMN
                                     MCC=001 MNC=01 (Test, Test)
  cell selection state: C3 camped normally
                        ARFCN=871(DCS) CGI=001-01-1-1
  radio resource layer state: idle
  mobility management layer state: MM idle, normal service
```

And the capture itself (`evidence/2g/location-update-a51-dtap-only.txt`,
filtered on `gsm_a.dtap`) shows the complete, correct GSM 04.08
procedure, in order:

```
Measurement Report                    (MS -> BTS, uplink 239.193.23.2)
Location Updating Request  [SABM]     (MS -> BTS, uplink)
Location Updating Request  [UA]       (BTS -> MS, downlink 239.193.23.1, LAPDm ack)
Location Updating Accept              (Network -> MS, downlink)
TMSI Reallocation Complete            (MS -> Network, uplink)
Channel Release                       (Network -> MS, downlink)
Measurement Report                    (MS -> BTS, uplink, idle-mode)
```

Frame-level detail (`evidence/2g/location-update-a51-verbose-frames-95-105.txt`)
confirms the actual identity exchange: the Location Updating Request
carries `Mobile Identity - IMSI (001010000000001)` with the *old* LAI
showing LAC `0xfffe` (i.e. "unknown location area", since this is the
handset's first-ever registration with no prior TMSI) - and the Location
Updating Accept carries the *new* LAI (MCC 001/MNC 01, LAC 1 - this
lab's cell) plus a freshly-allocated `Mobile Identity - TMSI/P-TMSI
(0xb7e78448)`. This is a textbook-correct GSM Location Update, observed
end-to-end with **zero RF hardware, zero SDR, and no packet ever leaving
loopback** (confirmed no traffic on `wlan0` throughout, same check as
the earlier BTS-only test).

### `scripts/2g-tier-start.sh` updated

Added the `239.193.23.2` loopback route alongside the existing
`239.193.23.1` one (both added idempotently, before any daemon starts).
Documented the "must restart osmo-bts-virtual after adding a route" gotcha
inline as a comment, since it is the single most likely way this exact
stall recurs if someone adds the routes after the tier is already up.

## Build log addendum — Signal #11 (A5/0 vs A5/1 contrast) and gsm_detector.py (2026-09-07)

Steps 6-7-9 of the build order (Um capture, A5/0 vs A5/1 demonstration,
detector). Two real blockers found and fixed before the contrast was
observable at all - both are genuine findings worth recording, since
without them signal #11 could not fire on this lab.

### Real blocker: `authentication optional` meant NO ciphering ever ran

The first Location Update capture (`evidence/2g/location-update-a51-
encrypted.pcap`, the "MILESTONE" capture in the previous addendum) has
**no Authentication Request and no Cipher Mode Command at all** - the
whole procedure was Location Updating Request -> Accept -> TMSI
Reallocation Complete, done. Ciphering can only start once authentication
derives Kc (per Osmocom's own docs: "the Kc resulting from authentication
is the key used for ciphering"), so with no authentication there was
nothing for signal #11 to observe - not a bug, but not usable for the
demonstration the task needs either.

**Root cause:** `osmo-msc.cfg`'s `network / encryption a5 0` and lack of
an explicit `authentication` line meant it inherited the shipped
example's default, `authentication optional` - a real network may
legitimately run this way for interoperability, but it meant this lab's
test subscriber's Location Update never triggered authentication at all.

**Fix:** added `authentication required` and changed `encryption a5 0`
to `encryption a5 0 1` (permits both, so ONE msc config serves both the
a50 and a51 BSC-side demonstrations - only osmo-bsc-a5*.cfg needs to
switch to produce the encrypted-vs-null contrast) to `osmo-msc.cfg`.
Documented inline in the file itself, since this is a config choice that
directly determines whether signal #11 is observable, not just cosmetic.

### Real blocker: XOR-2G auth algorithm mismatch between osmo-hlr and OsmocomBB's test-sim

With `authentication required` now set, every Location Update immediately
started failing: `GSM AUTH failure: mismatching sres (expected
sres=d074c1b2)` (osmo-msc log), with the MS's software SIM computing
`d501c1ed` for the identical all-zero Ki and RAND. This is the exact
combination (`ki xor 00...00` on the MS side, `aud2g xor-2g` on the HLR
side) the Osmocom Virtual Um wiki's own `mobile.cfg` uses - it happened
to "work" in the earlier milestone capture only because authentication
was never actually exercised (`authentication optional` skipped it
entirely), so the mismatch was latent, not actually fixed.

**Diagnosis:** XOR-2G is Osmocom's own non-3GPP-standard test
convenience algorithm (unlike COMP128, it is not a documented 3GPP
algorithm with an independent reference implementation to check either
side against), so there is no external spec to determine which side (HLR
or OsmocomBB) has the "correct" XOR-2G behaviour for a given Ki/RAND -
they simply don't agree with each other on this build combination.

**Fix:** switched both sides to **COMP128v1** (`aud2g comp128v1` in
osmo-hlr, `ki comp128 <32-hex-digit all-zero key>` in `mobile.cfg`'s
test-sim), a real, specified 2G algorithm both implementations agree on
- confirmed by authentication succeeding immediately on the very first
retry after the switch, no further mismatch. Same all-zero synthetic
key, no real credential either way.

### Signal #11 demonstrated: full encrypted-vs-null-cipher contrast

With authentication now working, both variants produce the complete
GSM procedure: Location Updating Request -> Authentication Request ->
Authentication Response -> **Ciphering Mode Command** -> Ciphering Mode
Complete -> Location Updating Accept -> TMSI Reallocation Complete.

- **`osmo-bsc-a51.cfg` (`encryption a5 1`)**:
  `evidence/2g/location-update-a51-cipher.pcap`, Ciphering Mode Command
  (frame 177) decodes as `Cipher Mode Setting: SC: Start ciphering (1)`,
  `Algorithm identifier: Cipher with algorithm A5/1 (0)` -
  `evidence/2g/cipher-mode-a51-verbose.txt`.
- **`osmo-bsc-a50.cfg` (`encryption a5 0`)**:
  `evidence/2g/location-update-a50-null-cipher.pcap`, Ciphering Mode
  Command (frame 184) decodes as `Cipher Mode Setting: SC: No ciphering
  (0)` - no Algorithm Identifier sub-field at all, since SC=0 means no
  algorithm applies - `evidence/2g/cipher-mode-a50-verbose.txt`.

**The contrast is exactly what the task asks for:** identical network,
identical subscriber, identical procedure, ONE line changed
(`osmo-bsc-a50.cfg` vs `osmo-bsc-a51.cfg`'s `encryption a5` line) and the
Cipher Mode Command's own on-the-wire semantics flip from "start
ciphering with A5/1" to "no ciphering at all" - traffic that follows on
this channel goes from encrypted to plaintext by a pure network-side
configuration choice the handset has no way to refuse (see
`docs/2G-TIER.md`).

### `detector/gsm_detector.py` built and verified against both real captures

Same style/conventions as `detector/ngap_detector.py` (stdlib +
`subprocess` calling `tshark`, no pyshark, structured JSON findings +
console summary, every finding citing its spec basis). Implements:

- **Signal #11** - Cipher Mode Command with SC=0 (null cipher). Field
  discovery from real captures first (`tshark -T json` on both
  demonstration pcaps), not guessed: `gsm_a.rr.SC` (0/1),
  `gsm_a.rr.algorithm_identifier` (0=A5/1 through 6=A5/7, confirmed via
  `tshark -G values`), message type filter
  `gsm_a.dtap.msg_rr_type == 0x35` (Ciphering Mode Command, also
  confirmed via `tshark -G values` rather than assumed).
- **Signal #12** - Identity Request soliciting IMSI
  (`gsm_a.dtap.msg_mm_type == 0x18`, `gsm_a.dtap.type_of_identity == 1`).
- Bonus: cleartext IMSI anywhere on the Um (`e212.imsi` field, same one
  used to read the Location Updating Request's Mobile Identity in the
  milestone capture).
- Bonus: LAC/ARFCN allowlist violation (2G analogue of signal #5),
  `detector/allowlist_gsm.json`.

**Real false positive found and fixed during verification:** the LAC
allowlist check initially flagged LAC `65534` (`0xFFFE`) as a rogue cell
on every single capture - this is TS 24.008's reserved "deleted/no valid
LAI" placeholder value, which a handset with no prior stored LAI (this
lab's test subscriber, on its very first-ever attach) correctly reports
as its OLD LAI inside the Location Updating Request, not a real cell's
broadcast identity. Fixed by excluding `LAC_DELETED_PLACEHOLDER = 0xFFFE`
from the allowlist check with its own explanatory `lac-ok` finding,
rather than either silently dropping it (which would hide a legitimate
edge case from the report) or leaving the false positive in place.

**Run against real traffic, real findings, no fabrication:**
- `evidence/2g/gsm-detector-findings-a51.jsonl` - `11-ok` (A5/1
  correctly not flagged), `12-ok` (no Identity Request in this
  capture), `imsi-clear` (IMSI genuinely visible twice - the Location
  Updating Request and its LAPDm ack), `lac-ok` (LAC 1 matches the
  allowlist), `lac-ok` (LAC 65534 correctly excluded as the placeholder).
- `evidence/2g/gsm-detector-findings-a50.jsonl` - **`11` / high**, the
  real finding: Ciphering Mode Command with SC=0 on frame 184, same
  network, same subscriber, only the BSC config's `encryption a5` line
  different from the a51 run above.

### Next up

Step 8: signal #12's stronger form - an Identity Request to a subscriber
that ALREADY holds a valid TMSI (not just "no Identity Request observed
at all", which is what both captures above show, since this lab's
authentication procedure resolves identity via the Authentication
Request/Response exchange, never needing a separate Identity Request).
Forcing this deliberately (see the "signal #12" addendum for the
approach and what did/didn't work) is next, followed by GUI screenshots.

## Build log addendum — Signal #12 (Identity Request to a TMSI-holding subscriber) and GUI screenshots (2026-09-07)

Steps 8 and the GUI-screenshot requirement of the build order.

### Getting the STRONG form of signal #12: an Identity Request to a subscriber that already has a valid TMSI

The task explicitly asks for this stronger case, not just "no Identity
Request observed" (which is what every capture up to this point showed -
this lab's subscriber always successfully authenticated via Authentication
Request/Response, so the network never needed to separately ask for its
identity). Getting the network to genuinely need to ask - without
fabricating it - took several real attempts, logged here in full since
most of them are legitimate dead ends worth recording:

1. **`test re-selection`** (mobile's VTY) - rejected outright
   ("Cannot trigger cell re-selection, because we stick to a cell!"),
   since this lab's `mobile.cfg` pins `stick 871`. Dead end, by design of
   the lab's own config.
2. **`sim lai <MS> <MCC> <MNC> <LAC>`** (mobile's VTY, sets the SIM's own
   stored LAI directly) - accepted the command, but did not itself
   trigger a live re-registration; it just updates a stored value the
   next natural registration event would use. Also had a side effect
   worth recording: after this command, `show subscriber`'s own TMSI
   field went blank, complicating direct comparison for this specific
   attempt. Not pursued further as the primary path once the periodic-
   timer approach below worked.
3. **`shutdown` / `no shutdown` power-cycle** (mobile's VTY) - this DOES
   trigger a fresh registration, but a real GSM power-off first sends an
   **IMSI Detach Indication**, which makes the MS itself forget its own
   TMSI - so the next registration is a plain first-ever-style attach
   presenting IMSI directly (confirmed via capture: `Mobile Identity -
   IMSI` in the post-power-cycle Location Updating Request, not TMSI).
   This does demonstrate a DIFFERENT valid case of cleartext IMSI (a
   legitimate detach/reattach cycle), but not the specific "TMSI holder
   gets asked for IMSI anyway" scenario the task wants.
4. **Restarting `osmo-msc` (wiping its in-memory VLR/TMSI table) while
   `mobile` stays running, camped, and IMSI-ATTACHED (no shutdown, no
   detach)** - this is the fix. `mobile` still holds its previously
   allocated TMSI in memory (confirmed via `show subscriber`); the VLR
   restart has zero effect on the *handset's* belief that it is already
   registered. The remaining problem was purely "how do you make the
   still-running, already-registered MS re-contact the network at all
   without it detaching or re-attaching from scratch" - solved by using
   the **periodic Location Update timer (T3212)**, a completely standard
   GSM mechanism (TS 04.08/24.008): every GSM handset re-registers
   periodically on its own, with no detach, presenting its current TMSI.

**T3212 tuning, and a real sub-blocker:** `osmo-bsc-a5*.cfg` shipped the
package example's `timer net T3212 5` (30 minutes - units are 6-minute
increments). First attempt: changed this live via BSC VTY
(`timer net T3212 1` for 6 minutes) and waited - **this did not work**;
a `dumpcap` capture of the live BCCH showed `gsm_a.rr.t3212` still
broadcasting `5`, not `1`, even ~9 minutes after the VTY change. A
running `osmo-bts-virtual`'s System Information content, like its
multicast socket setup (see the earlier addendum), is apparently fixed
at some point after OML bring-up and does not live-update from a later
BSC VTY change alone. **Fix:** set `timer net T3212 1` directly in
BOTH `osmo-bsc-a50.cfg` and `osmo-bsc-a51.cfg` (the actual config files,
not just a live VTY edit) and did a full `2g-tier-stop.sh` / `2g-tier-
start.sh` cycle - confirmed via a fresh 5-second capture that SI now
broadcasts `gsm_a.rr.t3212: 1` before proceeding.

**Full sequence that worked, end to end:**
```
2g-tier-start.sh a50            # T3212=1 (6 min) now baked into the config
virtphy -D lo &
mobile -c config/osmocom/mobile.cfg &   # attaches, gets TMSI 0x3b646534
# (osmo-msc restarted here - VLR forgets the TMSI mapping; mobile stays up)
kill <osmo-msc pid>; osmo-msc -c config/osmocom/osmo-msc.cfg &
# start a long (420s) capture, then wait for the periodic timer
```

At T+~6 minutes, `show subscriber` on `mobile`'s VTY showed the TMSI
change from `0x3b646534` to `0x24f36698` - the periodic Location Update
fired and completed. The capture
(`evidence/2g/identity-request-demo.pcap`) shows exactly the sequence
the task asks for:

```
Location Updating Request   (MS -> Network, presents TMSI 0x3b646534 -
                              the MS believes it is already registered)
Identity Request             (Network -> MS, Type of identity: IMSI -
                              the VLR does NOT recognize this TMSI,
                              because it was restarted and its table
                              was wiped)
Identity Response            (MS -> Network, IMSI 001010000000001 IN
                              THE CLEAR)
Authentication Request/Response, Ciphering Mode Command/Complete,
Location Updating Accept, TMSI Reallocation Complete, Channel Release
```

Confirmed via `tshark -V` on frames 5224/5234/5237
(`evidence/2g/identity-request-demo-verbose.txt`): frame 5224's Mobile
Identity IE is `TMSI/P-TMSI (0x3b646534)` (NOT IMSI - the MS genuinely
believed it had a valid registration); frame 5234 is `Type of identity:
IMSI (1)`; frame 5237 is `Mobile Identity - IMSI (001010000000001)` in
plain, unprotected Layer 3 signalling. This is the strongest, most
convincing form of signal #12 - a genuinely-held-valid-TMSI subscriber
still gets asked for its permanent identity in the clear - and it was
produced honestly (a real VLR-state-loss scenario, not a fabricated
message), not by any interception or injection technique.

Because this same run happened to use the `osmo-bsc-a50.cfg` (null-
cipher) tier, `detector/gsm_detector.py` fired BOTH signal #11 (Cipher
Mode Command, SC=0, frame 5261) and signal #12 (Identity Request
soliciting IMSI, frame 5234) against this single capture -
`evidence/2g/gsm-detector-findings-identity-request.jsonl`.

### GUI screenshots (Wireshark under Xvfb) - worked, with one real fix needed

`xvfb-run`/`Xvfb` + `wireshark` + `scrot` (all already installed) worked
on the first genuine attempt for loading a pcap and rendering the packet
list - no headless-Chromium workaround needed, matches the task's own
prediction that Xvfb (not headless-Chromium) is the right tool for a
GTK app.

**Real snag, fixed:** the Wireshark main window would not actually
resize to fill a larger Xvfb screen via `xdotool windowsize`/
`windowmove` (X11 reported the window AS resized, but Wireshark's own
GTK layout kept rendering into only the original ~980px-wide area,
leaving the rest of the screen black) - no window manager is running
under bare `Xvfb`, and GTK's own resize negotiation seems to depend on
one being present. Rather than fight this further, used Wireshark's own
column-visibility feature instead (right-click a column header ->
uncheck Source/Destination, both redundant here since every packet in
this lab's captures shares the same loopback address pair) to reclaim
horizontal space for the Info column within the existing pane width -
this achieved a fully readable packet list without ever needing the
outer window to actually resize.

**Screenshots captured (`evidence/screenshots/`), all from real,
already-verified captures, no fabrication:**
- `gsm-location-update-packet-list.png` - full `gsm_a.dtap`-filtered
  packet list of a complete Location Update (Location Updating Request
  through Channel Release, including Authentication and Ciphering Mode
  Command/Complete).
- `gsm-cipher-mode-a50-detail.png` - Ciphering Mode Command (A5/0
  variant) expanded in the detail pane, showing `Cipher Mode Setting:
  SC: No ciphering (0)`.
- `gsm-cipher-mode-a51-detail-contrast.png` - the same message from the
  A5/1 capture, `SC: Start ciphering (1)`, `Algorithm identifier: Cipher
  with algorithm A5/1` - the direct visual contrast pair for signal #11.
- `gsm-identity-response-imsi-detail.png` - the Identity Response from
  the TMSI-holding-subscriber scenario above, expanded, showing `Mobile
  Identity - IMSI (001010000000001)` and the decoded IMSI digits in the
  clear.

Right-click "Expand Subtrees" (not "Expand All", which expands from the
Frame root and buries the relevant GSM A-I/F DTAP node many screens
down) on the specific protocol node is the reliable way to get a
useful, on-topic detail-pane screenshot.

## Redaction before publishing (2026-09-07)

The 2G multicast-leak debugging captures recorded this host's own WiFi address,
because the leak being diagnosed was GSMTAP escaping loopback onto `wlan0`. That
real address appeared 2,146 times across 11 evidence transcripts.

Before pushing to a public repo it was replaced with `192.0.2.93`, which is in
TEST-NET-1 (RFC 5737, reserved for documentation). The transcripts read exactly
the same and the leak they document is just as legible, but the repo no longer
carries a real host address from a home network.

Nothing else needed redacting. Every IMSI in the tree is a reserved test-PLMN
value (999/70 and 001/01), the IMEI in `config/ueransim/ue.yaml` is UERANSIM's
own upstream sample value, and the `hnet/*.key` files are Open5GS's public
default SUCI keys shipped with every install.
