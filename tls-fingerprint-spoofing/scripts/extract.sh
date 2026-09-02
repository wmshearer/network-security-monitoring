#!/usr/bin/env bash
# Pull JA3/JA4 fields out of a pcapng file for every ClientHello it
# contains, tab separated.
#
# Usage: scripts/extract.sh data/firefox.pcapng

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <pcapng file>" >&2
    exit 1
fi

PCAP="$1"

tshark -r "$PCAP" -Y "tls.handshake.type==1" -T fields \
    -e tls.handshake.ja3 \
    -e tls.handshake.ja3_full \
    -e tls.handshake.ja4 \
    -e tls.handshake.ja4_r \
    -E header=y -E separator=$'\t'
