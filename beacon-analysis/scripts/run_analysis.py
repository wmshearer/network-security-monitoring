#!/usr/bin/env python3
"""Run beacon analysis over a capture and write a ranked candidate report.

Usage:
    python3 scripts/run_analysis.py data/pcaps/<file>.pcap [--top N]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.beacon import analyze  # noqa: E402
from src.extract import extract  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", type=Path)
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--min-connections", type=int, default=8)
    ap.add_argument("--out", type=Path, default=ROOT / "reports" / "beacon-candidates.json")
    args = ap.parse_args()

    if not args.pcap.exists():
        print("no such capture: %s" % args.pcap)
        return 2

    t0 = time.time()
    print("[1/2] extracting flows from %s" % args.pcap.name)
    res = extract(args.pcap)
    print("      %d packets -> %d flows (%d unparsed lines)"
          % (res.packets_read, res.flows_found, res.parse_failures))

    print("[2/2] scoring timing regularity")
    scores = analyze(res.connections, min_connections=args.min_connections)
    print("      %d candidate pairs with >= %d connections"
          % (len(scores), args.min_connections))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({
        "capture": args.pcap.name,
        "packets_read": res.packets_read,
        "flows_found": res.flows_found,
        "parse_failures": res.parse_failures,
        "min_connections": args.min_connections,
        "candidates_scored": len(scores),
        "elapsed_seconds": round(time.time() - t0, 1),
        "candidates": [s.as_row() for s in scores],
    }, indent=2))

    print()
    print("%-16s %-16s %6s %7s %9s %8s %8s" %
          ("SOURCE", "DESTINATION", "PORT", "CONNS", "INTERVAL", "JITTER", "SCORE"))
    for s in scores[:args.top]:
        print("%-16s %-16s %6d %7d %8.1fs %7.3f %8.4f"
              % (s.src[:16], s.dst[:16], s.dport, s.connections,
                 s.median_interval, s.jitter_ratio, s.interval_score))

    print()
    print("wrote %s" % args.out)
    print()
    print("This is a RANKING, not a verdict. Regular timing describes NTP, telemetry,")
    print("update checks and monitoring agents as readily as it describes malware.")
    print("Ruling those out is the analysis; this only decides what to look at first.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
