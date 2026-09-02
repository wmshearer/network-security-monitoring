#!/usr/bin/env bash
# Start the local TLS server, capture loopback traffic with tshark while
# a client connects to it, then stop both. No sudo: dumpcap has
# cap_net_admin/cap_net_raw and this user is in the wireshark group.
#
# Usage: scripts/capture.sh <label> <client-command...>
#
# Example:
#   scripts/capture.sh curl curl -sk https://127.0.0.1:8443/
#
# Writes data/<label>.pcapng and prints the path when done.

set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <label> <client-command...>" >&2
    exit 1
fi

LABEL="$1"
shift

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="$ROOT/data"
mkdir -p "$DATA_DIR"

PORT="${TLS_LAB_PORT:-8443}"
IFACE="lo"
PCAP="$DATA_DIR/${LABEL}.pcapng"

# Start the server.
python3 "$ROOT/src/server.py" --port "$PORT" --cert "$ROOT/server.pem" --key "$ROOT/server.key" \
    > "$DATA_DIR/${LABEL}.server.log" 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true' EXIT

# Give it a moment to bind.
sleep 0.5

# Start the capture, filtered to the TLS port on loopback.
tshark -i "$IFACE" -f "tcp port $PORT" -w "$PCAP" > "$DATA_DIR/${LABEL}.tshark.log" 2>&1 &
TSHARK_PID=$!

# Give tshark a moment to actually start capturing.
sleep 1.5

echo "[capture] running client: $*" >&2
"$@" || echo "[capture] client command exited non-zero (may still have completed a handshake)" >&2

# Let the capture soak briefly in case the client is a browser doing
# background requests, then stop it.
sleep 1.5
kill -INT "$TSHARK_PID" 2>/dev/null || true
wait "$TSHARK_PID" 2>/dev/null || true

echo "[capture] wrote $PCAP" >&2
echo "$PCAP"
