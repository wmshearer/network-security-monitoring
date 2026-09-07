# The 2G Tier — GSM over Virtual Um (no radio hardware, anywhere)

This is the 2G/GSM addition to the lab, built on top of (and independent
from) the 5G Standalone core described in the main `README.md`. Its
purpose is narrower and different in kind from the 5G tier: 5G ships a
mandatory SUPI-concealment mechanism (SUCI) with a documented escape
hatch (the null-scheme); GSM never had mutual authentication to begin
with. This tier exists to make that difference directly observable, on
the wire, on a network we own end to end.

## Why GSM needs no radio hardware at all: "Virtual Um"

Every real GSM deployment has a physical radio interface between the
handset and the base station — the "Um" interface, standardized in the
GSM 04-series specs (LAPDm framing, RR/MM/CC layer-3 messages). Osmocom
maintains a *software-only* substitute for that interface, called
**Virtual Um**, introduced in 2017
(<https://projects.osmocom.org/projects/cellular-infrastructure/wiki/Virtual_Um>):

- **On the network side**, `osmo-bts-virtual` is a full `osmo-bts` BTS
  process with the RF/PHY layer replaced by a software scheduler
  (`scheduler_virtbts.c`). It still speaks OML/RSL to a real `osmo-bsc`
  exactly like a hardware BTS would; the only thing missing is anything
  that touches an antenna.
- **On the handset side**, OsmocomBB's `virtphy` is a "virtual physical
  layer" that implements the same `L1CTL` protocol a real OsmocomBB
  phone's Layer 1 firmware would speak to the host-side `layer23`
  programs (`mobile`, the soft-UE). `mobile` itself is completely
  unmodified and unaware it isn't talking to real hardware.
- **The two are connected by GSMTAP over UDP multicast**, not by any RF
  waveform. `osmo-bts-virtual` transmits downlink (BTS → MS) frames to
  multicast group `239.193.23.1:4729`; `virtphy` transmits uplink
  (MS → BTS) frames to `239.193.23.2:4729`; each side also subscribes to
  the other's group to receive. GSMTAP is itself just Osmocom's own
  debug/analysis encapsulation for GSM/LAPDm/L3 frames over UDP — designed
  originally so Wireshark could dissect real captured Um traffic, reused
  here as the *only* transport between MS and BTS.

**The consequence that matters for this lab:** there is no SDR, no
antenna, no RF frontend, and nothing is ever transmitted over the air, at
any point in this stack. If you strip away the GSM terminology, Virtual
Um is a handful of Linux processes exchanging UDP multicast datagrams —
exactly the same category of thing the 5G tier already is (UDP sockets
standing in for a radio interface), just for an older generation of the
same problem.

**Confining it further, on this host specifically:** by default, Linux
routes an outbound multicast packet via whatever interface has the
default *unicast* route (this host's WiFi NIC) unless told otherwise —
this is still ordinary IP traffic over Ethernet/WiFi, not RF/cellular
transmission of any kind, and even the leaked packets carried TTL=1 (dead
at the first router hop, never able to leave the local LAN segment) — but
to avoid any unnecessary LAN exposure, both multicast groups are
explicitly confined to loopback: a static route
(`ip route add 239.193.23.1/32 dev lo`, and the same for `.2`) plus
`osmo-bts-virtual`'s own `virtual-um net-device lo` config directive and
`virtphy`'s `-D lo` flag. `scripts/2g-tier-start.sh` sets this up
automatically. See `NOTES.md` for the full debugging story — this took
two separate fixes (one per multicast group) to get right.

## Architecture

```
  MS (mobile)                                    BTS (osmo-bts-virtual)
  layer23 process, GSM RR/MM/CC                  L1 replaced by a
  L1CTL to virtphy over                          software scheduler
  /tmp/osmocom_l2 (unix socket)
        |                                                |
        v                                                v
  virtphy (virtual PHY)  <---- GSMTAP/UDP multicast ---->  osmo-bts-virtual
  239.193.23.2 (uplink, MS->BTS)   239.193.23.1 (downlink, BTS->MS)
  BOTH confined to loopback only (see above) - no LAN, no RF, ever
                                                           |
                                                     OML + RSL (Abis,
                                                     TCP 3002/3003)
                                                           v
                                                        osmo-bsc
                                                    (base station controller)
                                                           |
                                              SCCP/M3UA over osmo-stp
                                                    (A-interface)
                                                           v
                                                        osmo-msc
                                          (mobile switching center, VLR)
                                                   /              \
                                            GSUP (subscriber       MGCP
                                            auth data)          (unused,
                                                 |               no voice
                                                 v               calls here)
                                              osmo-hlr             osmo-mgw
                                        (subscriber DB / AuC)
```

Six daemons total, all plain host processes (no Docker, no systemd —
see "Starting and stopping" below), all bound to `127.0.0.1` only:
`osmo-stp` (SCCP/M3UA transfer point — the A-interface's signalling
transport), `osmo-hlr` (subscriber database and authentication centre),
`osmo-mgw` (media gateway — present because both BSC and MSC expect one
configured, even though this lab never places a voice call), `osmo-msc`
(mobile switching centre / VLR), `osmo-bsc` (base station controller),
and `osmo-bts-virtual` (the RF-free BTS itself). Plus two handset-side
processes started separately, `virtphy` and `mobile`, both built from
source (see "OsmocomBB" below).

## Synthetic test network and subscriber

Everything here uses the 3GPP-reserved test PLMN, exactly like the 5G
tier uses MCC 999 / MNC 70 for the same reason:

| Field | Value |
|-------|-------|
| PLMN (MCC/MNC) | 001/01 (3GPP test network) |
| LAC | 1 (`0x0001`) |
| Cell Identity | 1 |
| BSIC | 63 |
| ARFCN | 871 (DCS1800 band) |
| IMSI | `001010000000001` |
| Ki | all-zero, COMP128v1 (see `NOTES.md` for why COMP128v1 rather than the Osmocom wiki's own XOR-2G reference value — a real, spec-defined algorithm both `osmo-hlr` and OsmocomBB's software SIM agree on) |

No real IMSI, no real Ki, no real carrier, ever.

## Starting and stopping the 2G tier

```bash
cd /home/kali/director/projects/cellular-detection-lab

# Start the 6-daemon core network (default: encryption a5 1, baseline)
scripts/2g-tier-start.sh a51
# or, for the null-cipher demonstration:
scripts/2g-tier-start.sh a50

# Attach a virtual handset once the core is up (built separately, see below)
build/osmocom-bb/src/host/virt_phy/src/virtphy -D lo &
build/osmocom-bb/src/host/layer23/src/mobile/mobile -c config/osmocom/mobile.cfg &

# Check the BTS-to-BSC link (OML/RSL) came up:
echo -e 'enable\nshow bts' | nc 127.0.0.1 4242

# Stop everything (core + handset):
scripts/2g-tier-stop.sh
```

Both scripts touch only this tier's own processes and config — the 5G
tier's Docker containers, network, and host ports (3000/3001/9090/9091)
are never referenced.

VTY ports (all `127.0.0.1` only): `osmo-stp` 4239, `osmo-bts-virtual`
4241, `osmo-bsc` 4242, `osmo-msc` 4254, `osmo-hlr` 4258, `mobile` 4247.

## Building OsmocomBB (`virtphy` and `mobile`)

Not packaged in Kali — built from source. See `NOTES.md` for the full
build log, including two real dependency/config blockers found and
fixed. Summary:

```bash
cd build/  # gitignored — source trees and build artefacts, not committed
git clone https://gitea.osmocom.org/phone-side/osmocom-bb.git
git clone https://gitea.osmocom.org/osmocom/libosmo-gprs.git

# libosmo-gprs first (osmocom-bb's layer23/mobile links it unconditionally,
# even for pure 2G-CS use — not packaged anywhere in Kali/Debian)
cd libosmo-gprs && autoreconf -fi && ./configure && make -j$(nproc) && sudo make install && sudo ldconfig
cd ..

cd osmocom-bb/src/host/virt_phy && autoreconf -fi && ./configure && make -j$(nproc)
cd ../layer23 && autoreconf -fi && ./configure && make -j$(nproc)
```

Only `libosmocore-dev` (already the case for the whole 2G tier) is
needed beyond that. No ARM cross-toolchain, no phone firmware, is ever
built or needed — `virtphy` and `mobile` are both plain host-native
x86_64 binaries.

## The two signatures, in plain language

GSM's core design gap: **the network authenticates the handset, but the
handset has no way to authenticate the network.** A handset has no
cryptographic means to verify that whatever cell it's talking to is
really operated by its home network, or is honest about what it does
next. Two direct, observable consequences of that gap:

### Signal #11 — the network can turn off encryption, and the handset can't refuse

After authentication (which derives a session key, Kc), the network
sends a **Ciphering Mode Command** telling the handset which A5
algorithm to use from that point on — or, just as validly as far as the
handset can tell, that it should use **no algorithm at all (A5/0, the
null cipher)**. Nothing in the GSM protocol lets a legitimate-looking
handset detect that this choice is unusual, malicious, or contrary to
what "should" happen on this network — GSM specifies no minimum
acceptable cipher strength the handset can enforce, and most phones give
no visible warning at all when a call goes out unencrypted.

**What this lab demonstrates:** the exact same network, the exact same
subscriber, the exact same Location Update procedure — with a *single
config line* changed (`osmo-bsc-a50.cfg` vs `osmo-bsc-a51.cfg`'s
`encryption a5` setting) — produces a Ciphering Mode Command that either
starts real A5/1 encryption, or explicitly starts no ciphering at all.
That one-line diff, producing an encrypted-vs-plaintext contrast on the
wire, *is* the finding: A5/0 selection is not a hypothetical attacker
capability, it is a normal, always-available configuration knob on any
GSM network, legitimate or rogue.

### Signal #12 — the network can ask for your IMSI in the clear, any time

The permanent subscriber identity (IMSI) is only supposed to travel
unconcealed rarely — a handset's very first-ever attach (before it has
any TMSI to use instead), or in response to an explicit **Identity
Request** from the network. Identity Request is sent as *plain,
unprotected* Layer 3 signalling, because — like the Cipher Mode Command —
it can be sent before any security context exists. A network can send
this message at any time, to any handset, including one that already
holds a perfectly valid TMSI and has no legitimate reason to be re-asked.
This exact mechanism, "ask the phone for its own permanent identity",
predates 3G/4G/5G's own inherited versions of the same weakness (see
`docs/DETECTION-SIGNALS.md`) — GSM is where the technique originates.

**What this lab demonstrates:** because GSMTAP captures the Um interface
*before* whatever ciphering is in effect for a real over-the-air
transmission, the IMSI is directly readable in plaintext in this lab's
own captures, both in a first-ever attach's Location Updating Request and
in an Identity Request/Response pair triggered against a subscriber that
already holds a TMSI (forced here by clearing the network's own VLR
memory of that TMSI — see `NOTES.md` for exactly how, and the honest
caveat if this did not reproduce cleanly).

## Evidence

See `evidence/2g/` for pcaps, tshark text extracts, and
`detector/gsm_detector.py`'s JSON findings for both the encrypted (a51)
and null-cipher (a50) demonstrations, and `evidence/screenshots/` for
Wireshark GUI captures (or an honest statement of why GUI capture did
not work, if that was the outcome — see the final project report).
