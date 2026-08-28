#!/usr/bin/env python3
"""Rank the 4 benign-touching Sigma rules by measured noise-to-value ratio.

This is the ranking module described in the project brief. It uses ONLY
measured counts already present in detection-rule-lab's scoring-run.json.
It makes no assumption about triage cost, analyst wage, or fleet size, so
it needs no disclosed input beyond the source file itself.

"Noise-to-value ratio" here means: benign_hits / max(malicious_hits, 1).
This is a ranking device, not a rate. A rule with 0 malicious hits and
56 benign hits is assigned a ratio using max(0, 1) = 1 in the denominator
specifically so it does not divide by zero; its true ratio is undefined
(infinite cost per true positive), and that is called out explicitly
rather than hidden behind an artificial finite number.

Read-only: opens detection-rule-lab/reports/scoring-run.json for reading
and never writes to that project.

Idempotent: running this script twice produces byte-identical output
(same input file, no randomness, no network).

Usage:
    python3 01_rank_by_noise.py
    python3 01_rank_by_noise.py --json   # emit machine-readable JSON instead of a table
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CAVEAT_BANNER, EVIDENCE_DIR, load_scoring_run, rules_touching_benign


def build_ranking(scoring_run: dict) -> list[dict]:
    touching = rules_touching_benign(scoring_run)
    ranked = []
    for r in touching:
        mal = r["malicious_hits"]
        ben = r["benign_hits"]
        precision = r["precision"]
        undefined_ratio = mal == 0
        ratio = ben / max(mal, 1)
        ranked.append(
            {
                "rule_id": r["rule_id"],
                "title": r["title"],
                "level": r["level"],
                "author": r["author"],
                "malicious_hits": mal,
                "benign_hits": ben,
                "precision": precision,
                "noise_to_value_ratio": ratio,
                "ratio_is_undefined_infinite": undefined_ratio,
            }
        )
    # Sort worst-first: undefined/infinite ratio rules first, then by ratio descending.
    ranked.sort(key=lambda x: (not x["ratio_is_undefined_infinite"], -x["noise_to_value_ratio"]))
    return ranked


def print_table(ranked: list[dict]) -> None:
    print(CAVEAT_BANNER)
    print()
    print(f"{'Rank':<5}{'Rule':<58}{'Attack':<8}{'Benign':<8}{'Precision':<11}{'Noise/Value':<14}")
    print("-" * 104)
    for i, r in enumerate(ranked, start=1):
        ratio_str = "undefined (inf)" if r["ratio_is_undefined_infinite"] else f"{r['noise_to_value_ratio']:.2f}"
        title = r["title"][:56]
        print(
            f"{i:<5}{title:<58}{r['malicious_hits']:<8}{r['benign_hits']:<8}"
            f"{r['precision']:<11.2f}{ratio_str:<14}"
        )
    print()
    print(
        "Total rules touching the benign baseline: "
        f"{len(ranked)} of 135 fired rules (2,691 loaded)."
    )
    total_benign = sum(r["benign_hits"] for r in ranked)
    print(f"Total benign hits across those {len(ranked)} rules: {total_benign}.")
    if total_benign:
        top = ranked[0]
        pct = top["benign_hits"] / total_benign * 100
        print(
            f"'{top['title']}' alone accounts for {top['benign_hits']} of {total_benign} "
            f"benign hits ({pct:.1f} percent)."
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    parser.add_argument(
        "--save",
        action="store_true",
        help="also write evidence/01_ranking.json",
    )
    args = parser.parse_args()

    scoring_run = load_scoring_run()
    ranked = build_ranking(scoring_run)

    if args.json:
        print(json.dumps(ranked, indent=2))
    else:
        print_table(ranked)

    if args.save:
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        out_path = EVIDENCE_DIR / "01_ranking.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(ranked, f, indent=2)
        print(f"\nSaved to {out_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
