#!/usr/bin/env python3
"""Profile every TLS client in a capture by its JA4 fingerprint."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.fingerprint import (  # noqa: E402
    extract_hellos,
    find_sni_mismatches,
    group_by_destination,
    profile_clients,
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", type=Path)
    ap.add_argument("--out", type=Path, default=ROOT / "reports" / "tls-profiles.json")
    args = ap.parse_args()

    if not args.pcap.exists():
        print("no such capture: %s" % args.pcap)
        return 2

    print("extracting ClientHellos from %s" % args.pcap.name)
    hellos = extract_hellos(args.pcap)
    if not hellos:
        print("no TLS handshakes found")
        return 1

    profiles = profile_clients(hellos)
    mismatches = find_sni_mismatches(hellos)
    by_dst = group_by_destination(hellos)

    no_sni = [p for p in profiles if not p.sends_sni]
    single_dst = [p for p in profiles if p.fanout == 1 and p.count >= 4]

    print()
    print("ClientHellos          %d" % len(hellos))
    print("distinct fingerprints %d" % len(profiles))
    print("fingerprints w/o SNI  %d" % len(no_sni))
    print("parse inconsistencies %d" % len(mismatches))
    print()
    print("%-40s %6s %5s %4s %5s  %s"
          % ("JA4 FINGERPRINT", "SEEN", "TLS", "SNI", "DESTS", "TOP SERVER NAME"))
    for p in profiles[:15]:
        top = p.server_names.most_common(1)
        print("%-40s %6d %5s %4s %5d  %s"
              % (p.ja4[:40], p.count, p.tls_version.replace("TLS ", ""),
                 "yes" if p.sends_sni else "NO", p.fanout,
                 top[0][0][:34] if top else "-"))

    if no_sni:
        print()
        print("Fingerprints sending NO server name:")
        for p in no_sni:
            print("  %-40s %4d hellos -> %d destination(s)"
                  % (p.ja4[:40], p.count, p.fanout))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({
        "capture": args.pcap.name,
        "client_hellos": len(hellos),
        "distinct_fingerprints": len(profiles),
        "fingerprints_without_sni": len(no_sni),
        "parse_inconsistencies": len(mismatches),
        "profiles": [p.as_row() for p in profiles],
        "destinations_by_client_count": sorted(
            ({"dst": d, "distinct_fingerprints": len(f)} for d, f in by_dst.items()),
            key=lambda x: -x["distinct_fingerprints"])[:25],
        "single_destination_clients": [p.as_row() for p in single_dst],
    }, indent=2, default=str))

    print()
    print("wrote %s" % args.out)
    print()
    print("A fingerprint is an identity, not a verdict. Absent SNI and low fanout")
    print("describe plenty of legitimate software: update clients, sync agents,")
    print("anything talking to a fixed endpoint. They narrow the question.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
