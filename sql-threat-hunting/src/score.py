"""
Score the beaconing query against ground truth.

Ground truth here is which capture a row came from, not a label invented for
this project. One capture is the Torii botnet, the other is a Philips Hue
bridge recorded on a normal network. Both come from CTU's IoT-23 set and both
are labelled by CTU, not by me.

The scorer exists because the first version of the beaconing query looked
excellent and was half wrong. It ranked a light bulb above the botnet. Without
a benign control group in the corpus that would have shipped as a success.
"""

import sqlite3
import sys
from pathlib import Path

# Hosts, and what CTU says they are. Mapping a host to its capture is how a
# result gets a truth value; nothing here is hand-labelled.
MALICIOUS_CAPTURE = "192.168.100.103"   # CTU-IoT-Malware-Capture-20-1-Torii
BENIGN_CAPTURE = "192.168.1.132"        # CTU-Honeypot-Capture-4-1-PhilipsHue

BEACON_SQL = """
WITH gaps AS (
    SELECT source_ip AS src, destination_ip AS dst, destination_port AS dport,
           capture,
           ts - LAG(ts) OVER (
               PARTITION BY source_ip, destination_ip, destination_port
               ORDER BY ts) AS gap
    FROM events
    WHERE destination_ip IS NOT NULL
),
real_gaps AS (SELECT * FROM gaps WHERE gap IS NOT NULL AND gap > 0.5),
pair_stats AS (
    SELECT src, dst, dport, capture, COUNT(*) AS intervals, AVG(gap) AS mean_gap
    FROM real_gaps
    GROUP BY src, dst, dport
    HAVING COUNT(*) >= ?
)
SELECT s.src, s.dst, s.dport, s.capture, s.intervals,
       s.mean_gap,
       AVG(ABS(g.gap - s.mean_gap)) / s.mean_gap AS jitter
FROM pair_stats s
JOIN real_gaps g
  ON g.src = s.src AND g.dst = s.dst AND g.dport = s.dport
GROUP BY s.src, s.dst, s.dport
HAVING jitter < ?
ORDER BY jitter ASC
"""


def truth_of(capture: str) -> str:
    """A row is malicious or benign according to which capture holds it."""
    if MALICIOUS_CAPTURE in capture:
        return "malicious"
    if BENIGN_CAPTURE in capture:
        return "benign"
    return "unlabelled"


def score(db: Path, min_intervals: int, max_jitter: float, quiet: bool = False):
    conn = sqlite3.connect(db)
    rows = conn.execute(BEACON_SQL, (min_intervals, max_jitter)).fetchall()
    conn.close()

    tp = fp = 0
    detail = []
    for src, dst, dport, capture, intervals, mean_gap, jitter in rows:
        truth = truth_of(capture)
        # Only the two IoT-23 captures carry a benign/malicious label. The AD
        # and exploit captures are all attack traffic with no benign twin, so
        # scoring against them would flatter the result.
        if truth == "unlabelled":
            continue
        if truth == "malicious":
            tp += 1
        else:
            fp += 1
        detail.append((truth, src, dst, dport, intervals, round(mean_gap, 1), round(jitter, 4)))

    total = tp + fp
    precision = tp / total if total else 0.0

    if not quiet:
        print(f"min_intervals={min_intervals}  max_jitter={max_jitter}")
        print(f"  flagged: {total}   true: {tp}   false: {fp}   precision: {precision:.2%}")
        for truth, src, dst, dport, n, mg, j in detail:
            mark = "OK " if truth == "malicious" else "FP "
            print(f"    {mark} {src:>15} -> {dst:<15} :{dport:<6} n={n:<6} mean={mg:>8}s jitter={j}")

    return {"tp": tp, "fp": fp, "precision": precision, "detail": detail}


if __name__ == "__main__":
    db = Path(__file__).resolve().parent.parent / "data" / "events.db"

    print("=" * 70)
    print("The naive threshold: anything steadier than 15 percent jitter")
    print("=" * 70)
    score(db, 8, 0.15)

    print()
    print("=" * 70)
    print("Sweeping the threshold to see whether tightening it helps")
    print("=" * 70)
    print(f"{'max_jitter':>12} {'flagged':>8} {'true':>6} {'false':>6} {'precision':>10}")
    for j in (0.15, 0.10, 0.05, 0.03, 0.02, 0.01):
        r = score(db, 8, j, quiet=True)
        n = r["tp"] + r["fp"]
        print(f"{j:>12} {n:>8} {r['tp']:>6} {r['fp']:>6} {r['precision']:>9.1%}")
