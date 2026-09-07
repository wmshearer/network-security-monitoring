#!/bin/bash
# Stop the 2G tier: kill every osmo-{stp,hlr,mgw,msc,bsc,bts-virtual}
# process started from this lab's config/osmocom/ directory, plus any
# running virtphy/mobile (virtual handset). Does not touch the 5G tier
# (docker compose) or any other host process.

set -uo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG_DIR="$LAB_DIR/config/osmocom"

echo "Stopping virtual handset (if running)..."
for pat in "layer23/src/mobile/mobile -c" "virt_phy/src/virtphy"; do
  pids=$(pgrep -f "$pat" || true)
  if [[ -n "$pids" ]]; then
    echo "  $pat: stopping (pid(s): $pids)"
    kill $pids 2>/dev/null || true
  fi
done
sleep 1

echo "Stopping 2G tier..."
for daemon in osmo-bts-virtual osmo-bsc osmo-msc osmo-mgw osmo-hlr osmo-stp; do
  pids=$(pgrep -f "^$daemon -c $CFG_DIR" || true)
  if [[ -n "$pids" ]]; then
    echo "  $daemon: stopping (pid(s): $pids)"
    kill $pids
  else
    echo "  $daemon: not running"
  fi
done

echo "Waiting for clean shutdown..."
for i in $(seq 1 10); do
  remaining=$(pgrep -f "\-c $CFG_DIR/osmo-" || true)
  [[ -z "$remaining" ]] && break
  sleep 1
done
remaining=$(pgrep -af "\-c $CFG_DIR/osmo-" || true)
if [[ -n "$remaining" ]]; then
  echo "WARNING: still running after 10s, sending SIGKILL:"
  echo "$remaining"
  pkill -9 -f "\-c $CFG_DIR/osmo-" || true
fi

echo "2G tier stopped. (Note: the 239.193.23.1/239.193.23.2 loopback multicast"
echo "routes added by 2g-tier-start.sh are left in place - harmless with"
echo "nothing running, remove manually with 'sudo ip route del <addr>/32 dev lo'"
echo "if desired.)"
