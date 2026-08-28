#!/usr/bin/env python3
"""Parse Juice Shop's challenges.yml into a flat table of challenge, category,
difficulty, key. This table is the scoring target for every later step: a
scanner alert only counts as a "find" if it can be mapped to one of these
challenges by category.

Idempotent: reruns produce the same output file from the same input.
"""
import csv
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "data" / "challenges.yml"
OUT_DIR = ROOT / "evidence" / "manifest"
OUT_CSV = OUT_DIR / "challenges_table.csv"
OUT_SUMMARY = OUT_DIR / "category_counts.csv"


def parse_manifest(path: Path) -> list[dict]:
    with open(path) as f:
        raw = yaml.safe_load(f)
    rows = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        category = entry.get("category")
        difficulty = entry.get("difficulty")
        key = entry.get("key")
        if name is None or category is None:
            # Every real challenge in this manifest carries name and category.
            # If one is missing, something upstream changed shape; skip and
            # note it rather than guessing a value.
            print(f"WARNING: skipping entry missing name/category: {entry}", file=sys.stderr)
            continue
        rows.append(
            {
                "name": name,
                "category": category,
                "difficulty": difficulty,
                "key": key,
            }
        )
    return rows


def write_table(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "category", "difficulty", "key"])
        writer.writeheader()
        writer.writerows(rows)


def write_summary(rows: list[dict], path: Path) -> None:
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["category"]] = counts.get(r["category"], 0) + 1
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["category", "count"])
        for cat, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            writer.writerow([cat, n])


def main() -> int:
    if not MANIFEST.exists():
        print(f"ERROR: manifest not found at {MANIFEST}", file=sys.stderr)
        return 1
    rows = parse_manifest(MANIFEST)
    write_table(rows, OUT_CSV)
    write_summary(rows, OUT_SUMMARY)
    print(f"Parsed {len(rows)} challenges into {len(set(r['category'] for r in rows))} categories")
    print(f"Wrote {OUT_CSV}")
    print(f"Wrote {OUT_SUMMARY}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
