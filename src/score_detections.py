#!/usr/bin/env python3
"""Score every detection in detections/spl/*.yml against the already-ingested
cloud_lab index for two things at once, in a single search per detection:

  1. Recall: did the detection fire on host=<target_technique_id>, the
     technique it was built for.
  2. Off-target firing: did the detection fire on any OTHER host value
     (a different ATT&CK technique's labelled capture).

How: each detection's `search` field already ends its base filter logic
before any `| rename`/`| stats ... by <fields other than host>` cosmetic
pipe. This script takes the search UP TO (but not including) the filter
macro line, strips any trailing `| rename` / `| stats ... by <fields>` /
`| where` pipes that are cosmetic renaming rather than the actual matching
logic, and appends `| stats count by host` so one search reveals every
technique host the underlying match condition fires on -- both the target
technique (recall) and any other technique (off-target/overfitting signal).

This is NOT a re-interpretation of the detection logic: the base match
conditions (field equality, IN lists, bin/stats/where threshold pipes for
the four correlation-based detections) are preserved exactly as written in
each YAML's `search:` field. Only the final `rename`/`stats ... by
<non-host-field>` cosmetic grouping pipe (added for a human-readable alert
row) and the trailing filter-macro placeholder are replaced with
`stats count by host`, since a macro reference (backtick syntax) cannot be
run standalone by a oneshot search and this project has no site-specific
allowlist defined in it anyway (every macro is a documented no-op).

Usage:
    python3 src/score_detections.py [--detections-dir detections/spl] [--out evidence/detection_scoring.json]
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from splunk_search import run_search  # noqa: E402


def strip_to_matching_logic(search: str, detection_id: str) -> str:
    """Return a search that applies the SAME matching logic as the real
    detection (including, for the 4 correlation/threshold detections, the
    actual bin/stats/where threshold, not just the base event filter), and
    ends with a per-host breakdown so one search reveals recall (did it
    fire on the target host) and off-target firing (did it fire on any
    other host) at once.

    For a correlation detection (identified by `| bin _time span=`), the
    threshold's own `stats ... by _time <field>` line is REWRITTEN to add
    host to the group-by list, so the threshold (event_count/value_count
    > N) is evaluated separately per host, exactly as it would be in a
    real search scoped to more than one host. Getting this right matters:
    an earlier version of this script dropped the threshold pipeline
    entirely and substituted a raw `stats count by host`, which reported
    off-target hits for hosts that never actually crossed the detection's
    own threshold (caught by manually checking one flagged host,
    T1110.001, against the Azure password-spray detection's real
    dc(identity)>5 condition and finding only 1 distinct identity there,
    see README.md's Sigma/scoring section for the full account)."""
    lines = [l for l in search.strip().splitlines()]
    # Drop the trailing filter macro line (backtick-quoted macro reference).
    lines = [l for l in lines if not re.match(r"^\s*`\w+_filter`\s*$", l)]
    text = "\n".join(lines)

    if "| bin _time span=" in text:
        # Correlation detection: base selection, then bin, then the real
        # stats+where threshold, with `host` added to the group-by so the
        # threshold is evaluated per host.
        before_bin, after_bin = text.split("| bin _time span=", 1)
        span_value, rest = after_bin.split("\n", 1)
        # rest now starts with the `| stats ... by _time <field>` line
        # followed by `| where ... > N`, followed by the filter macro line
        # (already dropped above from `lines`, but the split happened
        # before that removal reached this branch, so drop it again here).
        stats_line, where_and_after = rest.split("\n", 1)
        where_line = [l for l in where_and_after.splitlines() if l.strip().startswith("|")][0]
        # stats_line looks like: "| stats <agg> as <alias> by _time <field>"
        stats_line = stats_line.rstrip() + ", host"
        agg_alias = stats_line.split(" as ")[1].split()[0]  # e.g. "value_count" or "event_count"
        return (
            before_bin.strip()
            + f"\n| bin _time span={span_value}\n"
            + stats_line
            + "\n"
            + where_line.strip()
            + f"\n| stats sum({agg_alias}) as total_matches by host"
        )

    # Non-correlation detections: strip the `| rename ...` and
    # `| stats ... by ...` cosmetic tail (added for alert readability),
    # keep the base field-filter selection, append stats by host.
    base = re.split(r"\n\s*\|\s*rename\b", text)[0].strip()
    return base + "\n| stats count by host"


def load_detections(detections_dir: Path) -> list[dict]:
    out = []
    for f in sorted(detections_dir.glob("*.yml")):
        with f.open() as fh:
            d = yaml.safe_load(fh)
        d["_file"] = f.name
        out.append(d)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--detections-dir", default=str(Path(__file__).resolve().parents[1] / "detections/spl"))
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "evidence/detection_scoring.json"))
    args = ap.parse_args()

    detections = load_detections(Path(args.detections_dir))
    results = []

    for d in detections:
        scoring_search = strip_to_matching_logic(d["search"], d["id"])
        full_search = f'search {scoring_search}'
        try:
            resp = run_search(full_search)
            rows = resp.get("results", [])
        except Exception as exc:  # noqa: BLE001
            rows = []
            print(f"ERROR running {d['name']}: {exc}", file=sys.stderr)

        count_field = "total_matches" if "total_matches" in (rows[0] if rows else {}) else "count"
        fires_by_host = {r["host"]: int(r[count_field]) for r in rows}
        target = d["target_technique_id"]
        recall_hit = target in fires_by_host
        off_target = {h: c for h, c in fires_by_host.items() if h != target}

        results.append({
            "id": d["id"],
            "name": d["name"],
            "file": d["_file"],
            "target_technique_id": target,
            "scoring_search": scoring_search,
            "recall_hit": recall_hit,
            "recall_count_on_target": fires_by_host.get(target, 0),
            "off_target_hosts_fired": off_target,
            "off_target_host_count": len(off_target),
            "off_target_total_events": sum(off_target.values()),
        })
        status = "RECALL HIT" if recall_hit else "RECALL MISS"
        print(f"{d['name']}: {status}, off-target hosts={len(off_target)}, off-target events={sum(off_target.values())}")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as fh:
        json.dump(results, fh, indent=2)
    print(f"\nwrote {out_path}")

    total = len(results)
    hits = sum(1 for r in results if r["recall_hit"])
    print(f"\nrecall: {hits}/{total}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
