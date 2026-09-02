#!/usr/bin/env python3
"""Track the beacon's score as RITA accumulates hours of data.

RITA stores one row per cumulative hour rather than one row per dataset, so a
single import leaves behind the whole history of what the detector thought at
each point as evidence arrived. That history is the interesting artifact here:
it separates "can the detector see the pattern" from "has the detector seen
enough of it to say so", which a single final score conflates.

Each row's `count` is the running connection total, so ordering by count
recovers the timeline.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "warmup.json"

# Ground truth, derived from the captures rather than supplied by the publisher,
# who never states the lab addressing. See docs/method.md.
BEACON_SRC = "::ffff:192.168.2.77"
BEACON_DSTS = ("143.198.3.13", "timeserversync.com", "weathersync.cloud")

# RITA's own alerting bands, from /etc/rita/config.hjson. Scores are stored 0-1
# and the config states thresholds as whole numbers, so compare after x100.
THRESHOLDS = {"base": 50, "low": 70, "medium": 90, "high": 100}

DATASETS = {
    "delay_d10_j25_24h": (10, 25),
    "delay_d30_j25_24h": (30, 25),
    "delay_d300_j25_24h": (300, 25),
    "jit_d30_j0_24h": (30, 0),
    "jit_d30_j10_24h": (30, 10),
    "jit_d30_j99_24h": (30, 99),
}


def query(sql: str) -> list[list[str]]:
    """Run one query against RITA's ClickHouse container."""
    proc = subprocess.run(
        ["sudo", "docker", "exec", "rita-clickhouse", "clickhouse-client", "-q", sql],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip()[:400])
    return [ln.split("\t") for ln in proc.stdout.splitlines() if ln.strip()]


def series(db: str) -> list[dict]:
    """The score history for the beacon in one dataset, earliest hour first."""
    # Addresses are stored IPv6-mapped, so a filter on the plain form silently
    # returns nothing. Hostname-resolved rows carry '::' in dst and the real
    # value in fqdn, so both columns have to be checked.
    names = ", ".join(f"'{d}'" for d in BEACON_DSTS)
    rows = query(
        f"""
        SELECT count, beacon_score, ts_score, ds_score, dur_score, hist_score
        FROM {db}.threat_mixtape
        WHERE toString(src) = '{BEACON_SRC}'
          AND (fqdn IN ({names}) OR toString(dst) IN ('::ffff:143.198.3.13'))
          AND count > 0
        ORDER BY count ASC
        FORMAT TSV
        """
    )
    out = []
    for i, r in enumerate(rows, start=1):
        out.append(
            {
                "hour": i,
                "connections": int(r[0]),
                "score": float(r[1]),
                "ts": float(r[2]),
                "ds": float(r[3]),
                "dur": float(r[4]),
                "hist": float(r[5]),
            }
        )
    return out


def first_hour_at_or_above(rows: list[dict], threshold: int) -> int | None:
    """First cumulative hour whose score reaches a band, or None if never."""
    for r in rows:
        if r["score"] * 100 >= threshold:
            return r["hour"]
    return None


def main() -> int:
    results = {}
    for db, (delay, jitter) in DATASETS.items():
        try:
            rows = series(db)
        except RuntimeError as exc:
            print(f"{db}: query failed: {exc}", file=sys.stderr)
            continue
        if not rows:
            print(f"{db}: no beacon rows", file=sys.stderr)
            continue
        results[db] = {
            "delay_s": delay,
            "jitter_pct": jitter,
            "hours": rows,
            "first_hour_base": first_hour_at_or_above(rows, THRESHOLDS["base"]),
            "first_hour_low": first_hour_at_or_above(rows, THRESHOLDS["low"]),
            "first_hour_medium": first_hour_at_or_above(rows, THRESHOLDS["medium"]),
        }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(results, indent=2))

    print("Hours of observation before the beacon reaches each alerting band")
    print("(RITA's own thresholds: base 50, low 70, medium 90)\n")
    print(f"{'delay':>6} {'jitter':>7} {'hr1':>6} {'>=50':>6} {'>=70':>6} {'>=90':>6}   timing subscore at hour 1")
    for db, d in sorted(results.items(), key=lambda kv: (kv[1]["delay_s"], kv[1]["jitter_pct"])):
        h = d["hours"][0]
        def fmt(v: int | None) -> str:
            return "never" if v is None else f"h{v}"
        print(
            f"{d['delay_s']:>5}s {d['jitter_pct']:>6}% {h['score']*100:>6.1f} "
            f"{fmt(d['first_hour_base']):>6} {fmt(d['first_hour_low']):>6} "
            f"{fmt(d['first_hour_medium']):>6}   {h['ts']:.3f}"
        )

    # The point of the whole exercise: timing is solved immediately, the
    # composite score is not.
    print("\nWhere the first-hour score is lost, by subscore:")
    print(f"{'delay':>6} {'jitter':>7} {'score':>7} {'timing':>7} {'size':>6} {'duration':>9} {'histogram':>10}")
    for db, d in sorted(results.items(), key=lambda kv: (kv[1]["delay_s"], kv[1]["jitter_pct"])):
        h = d["hours"][0]
        print(
            f"{d['delay_s']:>5}s {d['jitter_pct']:>6}% {h['score']:>7.3f} {h['ts']:>7.3f} "
            f"{h['ds']:>6.3f} {h['dur']:>9.3f} {h['hist']:>10.3f}"
        )

    print(f"\nwrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
