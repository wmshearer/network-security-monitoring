#!/usr/bin/env python3
"""Scan a capture for credentials sent in the clear."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from src.cleartext import scan  # noqa: E402

ap = argparse.ArgumentParser(); ap.add_argument("pcap", type=Path)
ap.add_argument("--out", type=Path, default=ROOT/"reports"/"cleartext-exposure.json")
a = ap.parse_args()
print("scanning %s for cleartext credentials" % a.pcap.name)
findings = scan(a.pcap)
if not findings:
    print("no cleartext credential exposure found"); raise SystemExit(0)
print()
print("%-10s %10s %8s  %s" % ("PROTOCOL","EXPOSURES","HOSTS","BREAKDOWN"))
for f in findings:
    r = f.as_row()
    print("%-10s %10d %8d  %s" % (r["protocol"], r["exposures"], r["hosts_involved"],
          ", ".join("%s=%d"%(k,v) for k,v in r["field_breakdown"].items())))
print()
for f in findings:
    r = f.as_row()
    print("%s:" % r["protocol"])
    for s in r["samples"][:4]:
        print("  %-15s -> %-15s %-20s %s" % (s["src"], s["dst"], s["field"], s["value"]))
a.out.parent.mkdir(parents=True, exist_ok=True)
a.out.write_text(json.dumps({"capture": a.pcap.name,
    "findings":[f.as_row() for f in findings]}, indent=2))
print(); print("wrote %s" % a.out)
print(); print("Passwords are redacted in all output. The finding is that credentials")
print("crossed this network unencrypted, which the username and endpoints establish.")
