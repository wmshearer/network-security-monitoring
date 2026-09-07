#!/bin/bash
# Start the 2G tier: OsmoSTP, OsmoHLR, OsmoMGW, OsmoMSC, OsmoBSC,
# osmo-bts-virtual, in dependency order, as plain background host
# processes (no Docker, no systemd - see docs/2G-TIER.md). Additive to
# the running 5G lab: does not touch any docker-compose service, any
# 172.22.0.0/24 container, or host ports 3000/3001/9090/9091.
#
# Usage:
#   scripts/2g-tier-start.sh [a50|a51]
#     a51 (default) - encryption a5 1 permitted (baseline, encrypted Um)
#     a50            - encryption a5 0 only (null-cipher IMSI-catcher demo)
#
# All daemon stdout/stderr goes to logs/osmocom/<daemon>.log. VTY ports:
# osmo-stp 4239, osmo-hlr 4258, osmo-mgw 4243, osmo-msc 4254, osmo-bsc
# 4242, osmo-bts-virtual 4241 (all bound to 127.0.0.1 only).

set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG_DIR="$LAB_DIR/config/osmocom"
LOG_DIR="$LAB_DIR/logs/osmocom"
BSC_VARIANT="${1:-a51}"

if [[ "$BSC_VARIANT" != "a50" && "$BSC_VARIANT" != "a51" ]]; then
  echo "Usage: $0 [a50|a51]" >&2
  exit 2
fi

mkdir -p "$LOG_DIR"

# The two Virtual Um multicast groups - 239.193.23.1 (BTS -> MS,
# downlink) and 239.193.23.2 (MS -> BTS, uplink; only relevant once
# virtphy/mobile are attached, but harmless to add now) - must resolve
# to a loopback-only route BEFORE osmo-bts-virtual (and, later, virtphy)
# open their multicast sockets (see docs/2G-TIER.md, "Keeping Virtual Um
# off the LAN"). Multicast group membership is joined at socket-setup
# time, not re-evaluated per-packet: adding these routes after
# osmo-bts-virtual has already started does NOT retroactively fix its
# socket - it must be restarted (this cost real debugging time once
# already, see NOTES.md - both groups need the route, missing the
# uplink one manifests as a virtual handset stuck retransmitting RACH
# Channel Request with no response, not an obvious error).
for grp in 239.193.23.1 239.193.23.2; do
  if ip route show | grep -q "^$grp dev lo"; then
    : # already routed via loopback
  else
    echo "Adding loopback-only multicast route for $grp (needs sudo)..."
    sudo ip route add "$grp/32" dev lo 2>/dev/null || true
  fi
done

start_daemon() {
  local name="$1"; shift
  if pgrep -f "^$*" >/dev/null 2>&1 || pgrep -af "$name -c" | grep -q "$CFG_DIR"; then
    echo "  $name: already running, skipping"
    return
  fi
  echo "  $name: starting..."
  nohup "$@" > "$LOG_DIR/$name.log" 2>&1 &
  disown
  sleep 2
}

echo "Starting 2G tier (BSC variant: $BSC_VARIANT)..."

echo "[1/6] osmo-stp (SCCP/M3UA transfer point)"
start_daemon osmo-stp osmo-stp -c "$CFG_DIR/osmo-stp.cfg"

echo "[2/6] osmo-hlr (subscriber database / auth)"
start_daemon osmo-hlr osmo-hlr -c "$CFG_DIR/osmo-hlr.cfg"

echo "[3/6] osmo-mgw (media gateway, unused RTP plane)"
start_daemon osmo-mgw osmo-mgw -c "$CFG_DIR/osmo-mgw.cfg"

echo "[4/6] osmo-msc (mobile switching center)"
start_daemon osmo-msc osmo-msc -c "$CFG_DIR/osmo-msc.cfg"

echo "[5/6] osmo-bsc (base station controller, encryption $BSC_VARIANT)"
pkill -f "osmo-bsc -c $CFG_DIR/osmo-bsc-" 2>/dev/null && sleep 2 || true
start_daemon osmo-bsc osmo-bsc -c "$CFG_DIR/osmo-bsc-$BSC_VARIANT.cfg"

echo "[6/6] osmo-bts-virtual (RF-free BTS, Virtual Um)"
start_daemon osmo-bts-virtual osmo-bts-virtual -c "$CFG_DIR/osmo-bts-virtual.cfg"

echo ""
echo "2G core network started. Check OML/RSL link with:"
echo "  echo -e 'enable\\nshow bts' | nc 127.0.0.1 4242"
echo "Logs: $LOG_DIR/"
echo ""
echo "To attach a virtual handset (OsmocomBB, built separately - see"
echo "NOTES.md/docs/2G-TIER.md), run in order once the core is up:"
echo "  $LAB_DIR/build/osmocom-bb/src/host/virt_phy/src/virtphy -D lo"
echo "  $LAB_DIR/build/osmocom-bb/src/host/layer23/src/mobile/mobile -c $CFG_DIR/mobile.cfg"
