"""Turn a packet capture into the connection records beacon analysis needs.

Zeek would normally do this (its conn.log is the canonical form), but Zeek is
not installable on this host: Kali ships 5.1.1, which depends on libc6 < 2.38
against an installed 2.42. That is a hard incompatibility, not a permissions
problem. tshark emits the same fields.

The unit of analysis is a CONNECTION, not a packet. A single TCP session is
hundreds of packets, and counting packets instead of sessions would make a
chatty file transfer look like a fast beacon. So the extractor collapses
packets into flows and keeps one record per flow: when it started, who talked
to whom, and how many bytes went each way.
"""

from __future__ import annotations

import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from .beacon import Connection

# Fields pulled from each packet. Deliberately minimal: timing analysis needs
# time, endpoints, and volume, and pulling payload would both slow the parse and
# invite handling data that should not be read.
TSHARK_FIELDS = (
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "frame.len",
    "tcp.flags.syn",
    "tcp.flags.ack",
)


@dataclass(frozen=True)
class ExtractResult:
    connections: list[Connection]
    packets_read: int
    flows_found: int
    parse_failures: int


def _run_tshark(pcap: Path, timeout: float) -> list[str]:
    cmd = ["tshark", "-r", str(pcap), "-T", "fields", "-E", "separator=\t"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0 and not proc.stdout:
        raise RuntimeError("tshark failed: %s" % proc.stderr[-500:])
    return proc.stdout.splitlines()


def extract(pcap: Path, timeout: float = 1800.0) -> ExtractResult:
    """Read a capture and return one Connection per flow.

    A flow is keyed on (src, dst, sport, dport). Its timestamp is the FIRST
    packet seen for that key, because a beacon's schedule is when it initiates,
    not when the conversation happens to end.

    Bytes are attributed by direction against the flow's own first-seen
    orientation rather than by port number. Guessing direction from a
    well-known port would mislabel anything on a non-standard port, which is
    exactly the traffic worth looking at here.
    """
    lines = _run_tshark(pcap, timeout)

    first_seen: dict[tuple, float] = {}
    bytes_fwd: dict[tuple, int] = defaultdict(int)
    bytes_rev: dict[tuple, int] = defaultdict(int)
    packets = 0
    failures = 0

    for line in lines:
        parts = line.split("\t")
        if len(parts) < len(TSHARK_FIELDS):
            failures += 1
            continue
        ts_s, src, dst, tsp, tdp, usp, udp_p, length = parts[:8]
        if not src or not dst:
            failures += 1
            continue
        try:
            ts = float(ts_s)
            size = int(length or 0)
        except ValueError:
            failures += 1
            continue

        sport = tsp or usp
        dport = tdp or udp_p
        if not dport:
            failures += 1
            continue
        try:
            sport_i = int(sport or 0)
            dport_i = int(dport)
        except ValueError:
            failures += 1
            continue

        packets += 1

        # Canonical key so both directions of one conversation collapse together.
        fwd = (src, dst, sport_i, dport_i)
        rev = (dst, src, dport_i, sport_i)
        if rev in first_seen:
            bytes_rev[rev] += size
            continue
        if fwd not in first_seen:
            first_seen[fwd] = ts
        bytes_fwd[fwd] += size

    connections = [
        Connection(
            timestamp=ts,
            src=key[0],
            dst=key[1],
            dport=key[3],
            bytes_out=bytes_fwd.get(key, 0),
            bytes_in=bytes_rev.get(key, 0),
        )
        for key, ts in first_seen.items()
    ]
    connections.sort(key=lambda c: c.timestamp)

    return ExtractResult(
        connections=connections,
        packets_read=packets,
        flows_found=len(connections),
        parse_failures=failures,
    )
