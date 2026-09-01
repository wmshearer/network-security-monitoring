#!/usr/bin/env python3
"""Pull the beacon's own score out of each RITA run and build the threshold table.

Every capture in this corpus was generated with a known delay and jitter, so the
question is not "is there a beacon" but "what score does the detector give the
beacon it was handed." That means finding the one row that corresponds to the
implant and reading its score, rather than looking at the top-ranked row.

Those are not the same thing, and conflating them is the easy way to get a
flattering result. If a benign host scores higher than the beacon, the top row is
the benign host, and reporting that number as "the beacon's score" would hide
exactly the failure this study is trying to measure.
"""

from __future__ import annotations

import csv
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSV_DIR = ROOT / "data" / "csv"

# Parsed out of the capture names the publisher used: d<delay>_j<jitter>.
CONFIG_RE = re.compile(r"d(\d+)_j(\d+)")

# RITA's severity bands, from /etc/rita/config.hjson. The CSV emits the score on
# a 0-1 scale while the config states thresholds as whole numbers, so scores are
# compared after multiplying by 100.
THRESHOLDS = {"base": 50, "low": 70, "medium": 90, "high": 100}

# Ground truth, derived from the captures rather than taken from the publisher,
# who never states the lab addressing. In the 0% jitter capture exactly one
# internal host has a periodic external flow, and its interval comes out at a
# median of 30.0s with a median absolute deviation of 0.0s across 2,868
# connections -- which is the configured delay, to the tenth of a second.
BEACON_SRC = "192.168.2.77"

# Destinations the implant uses, by address and by name. Both forms are needed:
# RITA reports some rows by IP and others by hostname, and which one it picks is
# not consistent across captures.
#
# The names are the redirector infrastructure, and they were chosen to read as
# ordinary infrastructure -- a time service and a weather service. DNS logs in
# the random-redirector captures resolve timeserversync.com to 143.198.73.116
# and weathersync.cloud to 24.199.110.233, both of which appear as beacon
# destinations in the raw conn logs.
#
# The same name does NOT always map to the same address: in the baseline capture
# RITA labels the 143.198.3.13 flow "timeserversync.com" with no DNS query in
# those logs resolving it, so the label comes from RITA's own enrichment rather
# than observed traffic. Matching on name alone would therefore be wrong, and
# matching on address alone misses the hostname-reported rows.
BEACON_DSTS = {
    "143.198.3.13",       # primary C2, direct captures
    "24.199.110.233",     # redirector leg
    "143.198.73.116",     # redirector leg
    "timeserversync.com",
    "weathersync.cloud",
}


def parse_config(name: str) -> tuple[int, int, str, str]:
    """Return (delay_s, jitter_pct, duration, family) for a capture directory name."""
    m = CONFIG_RE.search(name)
    if not m:
        raise ValueError(f"cannot parse delay/jitter from {name!r}")
    delay, jitter = int(m.group(1)), int(m.group(2))
    duration = "24H" if name.endswith("_24H") else "1H"
    if name.startswith("delay_var") or name.startswith("jit_var"):
        family = "direct"
    elif name.startswith("round_rob"):
        family = "round-robin redirector"
    elif name.startswith("random"):
        family = "random redirector"
    else:
        family = "unknown"
    return delay, jitter, duration, family


def load(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        return list(csv.DictReader(fh))


def to_float(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def is_internal(ip: str) -> bool:
    return ip.startswith(("192.168.", "10.")) or bool(
        re.match(r"172\.(1[6-9]|2\d|3[01])\.", ip)
    )


def is_routable_external(ip: str) -> bool:
    """External unicast only.

    The beacon host also emits SSDP to 239.255.255.250 and mDNS to 224.0.0.251,
    which are neither internal by RFC1918 nor a candidate for C2, so multicast
    and broadcast are excluded explicitly instead of surviving on a technicality.
    """
    if not ip or is_internal(ip):
        return False
    if ip.startswith(("224.", "239.", "255.", "127.", "169.254.")):
        return False
    return ":" not in ip  # skip IPv6/FQDN placeholder rows


def find_beacon_rows(rows: list[dict]) -> list[dict]:
    """The row for the known beacon pair, if RITA reported one at all.

    This matches on the ground-truth addresses rather than picking the
    highest-scoring row. If the beacon is absent from RITA's output entirely,
    that is a missed detection and has to be reported as one; taking the top row
    instead would quietly substitute whatever background host ranked first and
    turn a miss into a false pass.

    A redirector capture returns more than one row, since the implant is split
    across rotating destinations.
    """
    # RITA reports a destination either as an address in "Destination IP" or,
    # when it tied the connection to a hostname/SNI entry, as "::" there with
    # the real value in "FQDN". Both columns have to be checked against both
    # forms of the known destinations. Matching only on Destination IP silently
    # misses the beacon and falls through to whatever else the host was talking
    # to, which yields plausible-looking but wrong scores.
    return [
        r
        for r in rows
        if (r.get("Source IP") or "").strip() == BEACON_SRC
        and (
            (r.get("Destination IP") or "").strip() in BEACON_DSTS
            or (r.get("FQDN") or "").strip() in BEACON_DSTS
        )
    ]


def main() -> int:
    if not CSV_DIR.is_dir():
        print(f"no CSV directory at {CSV_DIR}", file=sys.stderr)
        return 1

    files = sorted(CSV_DIR.glob("*.csv"))
    if not files:
        print(f"no CSV files in {CSV_DIR}", file=sys.stderr)
        return 1

    results = []
    for path in files:
        name = path.stem
        try:
            delay, jitter, duration, family = parse_config(name)
        except ValueError as exc:
            print(f"skip: {exc}", file=sys.stderr)
            continue

        rows = load(path)
        candidates = find_beacon_rows(rows)
        candidates.sort(key=lambda r: to_float(r.get("Beacon Score", "")), reverse=True)

        top_overall = max(rows, key=lambda r: to_float(r.get("Beacon Score", "")), default=None)
        best = candidates[0] if candidates else None

        results.append(
            {
                "set": name,
                "delay": delay,
                "jitter": jitter,
                "duration": duration,
                "family": family,
                "rows": len(rows),
                # How many rows the beacon was split across. >1 means a
                # redirector spread it over several destinations, and the score
                # reported is the best any single leg achieved.
                "beacon_rows": len(candidates),
                "beacon_score": to_float(best.get("Beacon Score", "")) if best else None,
                # Prefer the FQDN column: RITA parks "::" in Destination IP for
                # any row it tied to a hostname/SNI entry, which is where the
                # beacon's own address ends up.
                "beacon_dst": (
                    (best.get("FQDN") or "").strip() or (best.get("Destination IP") or "").strip()
                )
                if best
                else "",
                "beacon_conns": best.get("Connection Count", "") if best else "",
                "beacon_severity": best.get("Severity", "") if best else "",
                "top_overall_score": to_float(top_overall.get("Beacon Score", "")) if top_overall else None,
                "top_overall_dst": (
                    (top_overall.get("FQDN") or top_overall.get("Destination IP") or "")
                    if top_overall
                    else ""
                ),
            }
        )

    # --- the threshold table -------------------------------------------------
    for duration in ("24H", "1H"):
        subset = [r for r in results if r["duration"] == duration and r["family"] == "direct"]
        if not subset:
            continue
        print(f"\n=== direct beacon, {duration} captures ===")
        print(f"{'delay':>6} {'jitter':>7} {'score':>7} {'x100':>6} {'band':>9} {'conns':>7}  dst")
        for r in sorted(subset, key=lambda r: (r["delay"], r["jitter"])):
            s = r["beacon_score"]
            if s is None:
                print(f"{r['delay']:>5}s {r['jitter']:>6}% {'NONE':>7}")
                continue
            print(
                f"{r['delay']:>5}s {r['jitter']:>6}% {s:>7.3f} {s*100:>6.1f} "
                f"{r['beacon_severity']:>9} {r['beacon_conns']:>7}  {r['beacon_dst']}"
            )

    # --- the comparison that actually matters --------------------------------
    # Same beacons, same detector, different observation window. Printed side by
    # side because the gap between the two columns is the result.
    by_config: dict[tuple[int, int], dict[str, dict]] = defaultdict(dict)
    for r in results:
        if r["family"] == "direct":
            by_config[(r["delay"], r["jitter"])][r["duration"]] = r

    print("\n=== observation window vs detection ===")
    print(f"{'delay':>6} {'jitter':>7} {'24H':>7} {'1H':>7} {'drop':>7}   crosses below 70?")
    for (delay, jitter) in sorted(by_config):
        pair = by_config[(delay, jitter)]
        long_run, short = pair.get("24H"), pair.get("1H")
        if not long_run or not short:
            continue
        a = long_run["beacon_score"]
        b = short["beacon_score"]
        if a is None or b is None:
            continue
        a100, b100 = a * 100, b * 100
        crossed = "1H MISSED" if b100 < THRESHOLDS["low"] <= a100 else ""
        print(
            f"{delay:>5}s {jitter:>6}% {a100:>7.1f} {b100:>7.1f} {a100 - b100:>7.1f}   {crossed}"
        )

    redirected = [r for r in results if r["family"] != "direct"]
    if redirected:
        print("\n=== redirector variants ===")
        for r in sorted(redirected, key=lambda r: (r["family"], r["duration"])):
            s = r["beacon_score"]
            score = f"{s:.3f}" if s is not None else "NONE"
            print(
                f"{r['family']:>22} {r['duration']:>4} {score:>7} "
                f"{r['beacon_severity']:>9}  split across {r['beacon_rows']} row(s)"
                f"  best={r['beacon_dst']}"
            )

    # --- what else scored as high as the beacon ------------------------------
    print("\n=== highest-scoring row overall, per capture ===")
    print("(if this is not the beacon, the detector ranked background traffic equally)")
    for r in sorted(results, key=lambda r: (r["duration"], r["delay"], r["jitter"])):
        t = r["top_overall_score"]
        print(
            f"{r['set']:>28} {r['duration']:>4} top={t if t is None else f'{t:.3f}'!s:>6}  {r['top_overall_dst']}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
