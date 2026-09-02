#!/usr/bin/env python3
"""Profile Modbus hosts and surface write operations."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.modbus import (  # noqa: E402
    FUNCTION_NAMES,
    WRITE_CODES,
    extract_ops,
    profile_hosts,
    unauthorised_writers,
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", type=Path)
    ap.add_argument("--allow-write", nargs="*", default=[],
                    help="hosts permitted to issue writes")
    ap.add_argument("--out", type=Path, default=ROOT / "reports" / "modbus-profiles.json")
    args = ap.parse_args()

    if not args.pcap.exists():
        print("no such capture: %s" % args.pcap)
        return 2

    print("extracting Modbus operations from %s" % args.pcap.name)
    ops = extract_ops(args.pcap)
    if not ops:
        print("no Modbus traffic found")
        return 1

    profiles = profile_hosts(ops)
    funcs = Counter(o.func_code for o in ops)
    writes = sum(v for k, v in funcs.items() if k in WRITE_CODES)

    print()
    print("Modbus operations   %d" % len(ops))
    print("write operations    %d (%.1f%%)" % (writes, 100.0 * writes / len(ops)))
    print("hosts observed      %d" % len(profiles))
    print()
    print("%-34s %8s %7s  %s" % ("FUNCTION", "COUNT", "PCT", "TYPE"))
    for code, n in funcs.most_common():
        print("%-34s %8d %6.1f%%  %s"
              % (FUNCTION_NAMES.get(code, "Function %d" % code)[:34], n,
                 100.0 * n / len(ops), "WRITE" if code in WRITE_CODES else "read"))

    print()
    print("%-17s %8s %8s %8s %7s  %s"
          % ("HOST", "TOTAL", "READS", "WRITES", "TARGETS", "INFERRED ROLE"))
    for p in profiles[:12]:
        print("%-17s %8d %8d %8d %7d  %s"
              % (p.host, p.total, p.reads, p.writes, len(p.targets), p.role))

    allowed = set(args.allow_write)
    rogue = unauthorised_writers(ops, allowed) if allowed else []
    if allowed:
        print()
        print("Write allow-list: %s" % ", ".join(sorted(allowed)))
        if rogue:
            print("UNAUTHORISED WRITERS:")
            for r in rogue:
                print("  %-17s %d writes to %d device(s)"
                      % (r.host, r.writes, len(r.targets)))
        else:
            print("No writes from hosts outside the allow-list.")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({
        "capture": args.pcap.name,
        "total_operations": len(ops),
        "write_operations": writes,
        "write_percentage": round(100.0 * writes / len(ops), 2),
        "function_distribution": [
            {"code": c, "name": FUNCTION_NAMES.get(c, str(c)), "count": n,
             "is_write": c in WRITE_CODES}
            for c, n in funcs.most_common()
        ],
        "hosts": [p.as_row() for p in profiles],
        "write_allow_list": sorted(allowed),
        "unauthorised_writers": [r.as_row() for r in rogue],
    }, indent=2))

    print()
    print("wrote %s" % args.out)
    print()
    print("Modbus has no authentication. Any host reaching port 502 can command a")
    print("PLC and it will comply. The allow-list is an operational fact that has")
    print("to come from the site, not something derivable from the traffic: deriving")
    print("it from what happened would define whatever happened as authorised.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
