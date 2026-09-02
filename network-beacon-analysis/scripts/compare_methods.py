#!/usr/bin/env python3
"""Compare behavioural timing detection against signature detection.

These are two different philosophies. Signatures match known-bad content and
catch things that have been seen before. Timing analysis matches behaviour and
does not care what is inside the packets, which matters because most traffic is
encrypted now.

The interesting question is not which is better. It is what each one finds that
the other does not, because that difference is the argument for running both.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_alerts(eve_path: Path) -> tuple[set[str], Counter]:
    """Destinations flagged by ET Open threat signatures, and signature counts.

    Only signatures prefixed "ET " are counted as threat detections. Suricata's
    own built-in signatures (prefixed "SURICATA ") report protocol anomalies
    like invalid checksums, which are diagnostics about the capture rather than
    statements about threat, and counting them would inflate the comparison.
    """
    dsts: set[str] = set()
    sigs: Counter = Counter()
    if not eve_path.exists():
        return dsts, sigs
    with eve_path.open() as fh:
        for line in fh:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("event_type") != "alert":
                continue
            sig = e.get("alert", {}).get("signature", "")
            sigs[sig] += 1
            if sig.startswith("ET ") and e.get("dest_ip"):
                dsts.add(e["dest_ip"])
    return dsts, sigs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", type=Path,
                    default=ROOT / "reports" / "beacon-candidates.json")
    ap.add_argument("--eve", type=Path,
                    default=ROOT / "data" / "out" / "ctu13-42-homenet" / "eve.json")
    ap.add_argument("--eve-default-homenet", type=Path,
                    default=ROOT / "data" / "out" / "ctu13-42" / "eve.json")
    ap.add_argument("--threshold", type=float, default=0.65,
                    help="minimum interval_score to treat as a beacon candidate")
    ap.add_argument("--out", type=Path, default=ROOT / "reports" / "method-comparison.json")
    args = ap.parse_args()

    cand = json.loads(args.candidates.read_text())
    candidates = cand["candidates"]
    flagged = [c for c in candidates if c["interval_score"] >= args.threshold]
    beacon_dsts = {c["dst"] for c in flagged}

    sig_dsts, sigs = load_alerts(args.eve)
    _, sigs_default = load_alerts(args.eve_default_homenet)

    et_default = {s: c for s, c in sigs_default.items() if s.startswith("ET ")}
    et_scoped = {s: c for s, c in sigs.items() if s.startswith("ET ")}

    both = sorted(beacon_dsts & sig_dsts)
    only_timing = sorted(beacon_dsts - sig_dsts)
    only_sigs = sorted(sig_dsts - beacon_dsts)

    payload = {
        "capture": cand["capture"],
        "beacon_threshold": args.threshold,
        "timing": {
            "candidates_scored": cand["candidates_scored"],
            "above_threshold": len(flagged),
            "destinations": len(beacon_dsts),
        },
        "signatures": {
            "rules_loaded": 52415,
            "et_signatures_default_homenet": len(et_default),
            "et_signatures_scoped_homenet": len(et_scoped),
            "destinations": len(sig_dsts),
            "top_signatures": sorted(et_scoped.items(), key=lambda x: -x[1])[:15],
        },
        "overlap": {
            "found_by_both": both,
            "only_timing_analysis": only_timing,
            "only_signatures": only_sigs,
        },
        "timing_only_detail": [
            c for c in flagged if c["dst"] in set(only_timing)
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2))

    print("=" * 70)
    print("HOME_NET scoping effect on signature detection")
    print("=" * 70)
    print("ET threat signatures firing, default HOME_NET : %d" % len(et_default))
    print("ET threat signatures firing, corrected        : %d" % len(et_scoped))
    print()
    print("=" * 70)
    print("Method overlap (destinations)")
    print("=" * 70)
    print("flagged by timing analysis : %d" % len(beacon_dsts))
    print("flagged by ET signatures   : %d" % len(sig_dsts))
    print("found by BOTH              : %d" % len(both))
    print("only timing analysis       : %d" % len(only_timing))
    print("only signatures            : %d" % len(only_sigs))
    print()
    print("Beacon candidates no signature flagged:")
    print("%-17s %6s %10s %8s %7s" % ("DESTINATION", "PORT", "INTERVAL", "JITTER", "SCORE"))
    for c in payload["timing_only_detail"][:10]:
        print("%-17s %6d %9.1fs %8.3f %7.3f"
              % (c["dst"], c["dport"], c["median_interval_s"],
                 c["jitter_ratio"], c["interval_score"]))
    print()
    print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
