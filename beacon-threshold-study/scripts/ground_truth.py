#!/usr/bin/env python3
"""Find the beacon in a capture without being told where it is.

The publisher never states the lab addressing, so the beacon has to be
identified from the traffic. The 0% jitter capture is the way in: a beacon with
no jitter is perfectly periodic, so it identifies itself. Any host whose
intervals to one destination have a median absolute deviation of zero is running
on a timer.

Usage: ground_truth.py <log directory>
"""

from __future__ import annotations

import gzip
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def is_external_unicast(ip: str) -> bool:
    """True for a routable address outside this network.

    Multicast is excluded explicitly: the hosts here emit SSDP to
    239.255.255.250 and mDNS to 224.0.0.251 on flawless timers, and those are
    neither internal by RFC1918 nor anywhere a beacon would call.
    """
    if ":" in ip:
        return False
    if ip.startswith(("192.168.", "10.", "127.", "169.254.")):
        return False
    if ip.startswith(("224.", "225.", "226.", "239.", "255.")):
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    if parts[0] == "172" and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
        return False
    return True


def load_flows(log_dir: Path) -> dict[tuple[str, str, str], list[float]]:
    """Connection timestamps grouped by source, destination and port."""
    flows: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    for path in sorted(log_dir.glob("conn.*.log.gz")):
        with gzip.open(path, "rt", errors="replace") as fh:
            for line in fh:
                if line.startswith("#"):
                    continue
                f = line.split("\t")
                if len(f) < 7:
                    continue
                # Zeek conn.log here carries a leading _node_name field, so the
                # timestamp is field 1 rather than the usual field 0.
                flows[(f[3], f[5], f[6])].append(float(f[1]))
    return flows


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    flows = load_flows(Path(sys.argv[1]))

    scored = []
    for (src, dst, port), times in flows.items():
        if len(times) < 30:
            continue
        # Ranking on regularity alone puts NTP, SSDP and mDNS at the top with a
        # median absolute deviation of exactly zero, because those are timers
        # too. Restricting to external unicast is what separates "on a schedule"
        # from "calling out to somewhere", and it is the whole reason a regular
        # interval is a lead rather than a finding.
        if not is_external_unicast(dst):
            continue
        times.sort()
        intervals = [b - a for a, b in zip(times, times[1:])]
        median = statistics.median(intervals)
        if median <= 0:
            continue
        mad = statistics.median([abs(v - median) for v in intervals])
        scored.append((mad / median, src, dst, port, len(times), median, mad))

    scored.sort()
    print(f"{'src':>15} {'dst':>16} {'port':>5} {'conns':>6} {'median':>8} {'MAD':>7}")
    for ratio, src, dst, port, n, median, mad in scored[:6]:
        print(f"{src:>15} {dst:>16} {port:>5} {n:>6} {median:>7.1f}s {mad:>6.1f}s")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
