#!/usr/bin/env python3
"""Score the readable rules against the IoT-23 ground-truth labels, per scenario."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from src.labels import read_connections, label_counts, detail_counts  # noqa: E402
from src.classify import score_all  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("labeled_logs", nargs="+", type=Path,
                help="one or more conn.log.labeled files")
ap.add_argument("--out", type=Path, default=ROOT / "reports" / "iot23-scores.json")
a = ap.parse_args()

report = {"scenarios": []}
for log in a.labeled_logs:
    if not log.exists():
        print("missing: %s" % log)
        continue
    conns = read_connections(log)
    name = log.parent.parent.name
    print("\n=== %s ===" % name)
    print("connections: %d   labels: %s" % (len(conns), dict(label_counts(conns))))
    print("%-10s %8s %8s %8s %10s %8s" %
          ("BEHAVIOUR", "TP", "FP", "FN", "PRECISION", "RECALL"))
    rows = []
    for s in score_all(conns):
        r = s.as_row()
        rows.append(r)
        prec = "n/a" if r["precision"] is None else "%.3f" % r["precision"]
        rec = "n/a" if r["recall"] is None else "%.3f" % r["recall"]
        print("%-10s %8d %8d %8d %10s %8s" %
              (s.behaviour, s.true_positives, s.false_positives,
               s.false_negatives, prec, rec))
    report["scenarios"].append({
        "scenario": name,
        "connections": len(conns),
        "labels": dict(label_counts(conns)),
        "detail": dict(detail_counts(conns)),
        "scores": rows,
    })

a.out.parent.mkdir(parents=True, exist_ok=True)
a.out.write_text(json.dumps(report, indent=2))
print("\nwrote %s" % a.out)
print()
print("Precision and recall are measured against the dataset's own labels. The rules")
print("key on the ports this malware family used in these captures. They describe what")
print("the traffic did here, not a signature that holds for every botnet everywhere.")
