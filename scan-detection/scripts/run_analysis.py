#!/usr/bin/env python3
"""Profile hosts by connection-attempt outcomes."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from src.scan import classify, extract_attempts, profile, timeline  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("pcap", type=Path)
ap.add_argument("--port", type=int, default=None)
ap.add_argument("--out", type=Path, default=ROOT/"reports"/"scan-profiles.json")
a = ap.parse_args()

print("extracting connection attempts from %s" % a.pcap.name)
att, answered = extract_attempts(a.pcap, port=a.port)
if not att:
    print("no connection attempts found"); raise SystemExit(1)
profiles = profile(att, answered)
print("attempts %d | sources %d | answered pairs %d" % (len(att), len(profiles), len(answered)))
print()
print("%-17s %9s %9s %9s %9s %8s  %s" %
      ("SOURCE","ATTEMPTS","TARGETS","ANSWERED","RESP RATE","SUBNETS","SHAPE"))
for p in profiles[:12]:
    rr = "n/a" if p.response_rate is None else "%.3f%%" % (100*p.response_rate)
    print("%-17s %9d %9d %9d %9s %8d  %s" %
          (p.src[:17], p.attempts, len(p.targets), len(p.responded), rr,
           p.distinct_subnets, classify(p)))

top = profiles[0]
tl = timeline(att, top.src, buckets=20)
if tl:
    print()
    print("attempt rate over time for %s (20 buckets over %.0f min):" % (top.src, top.duration_s/60))
    peak = max(tl) or 1
    for i, n in enumerate(tl):
        print("  %2d %-42s %d" % (i+1, "#"*int(40*n/peak), n))

a.out.parent.mkdir(parents=True, exist_ok=True)
a.out.write_text(json.dumps({"capture": a.pcap.name, "total_attempts": len(att),
    "profiles":[{**p.as_row(), "shape": classify(p)} for p in profiles]}, indent=2))
print()
print("wrote %s" % a.out)
print()
print("Shape is not intent. A vulnerability scanner, an asset inventory tool and")
print("malware spreading itself all produce the same picture from the wire.")
