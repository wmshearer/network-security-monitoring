#!/usr/bin/env python3
"""Break-even analysis: at what per-alert cost does a rule stop paying for itself?

Definitions used throughout this script:
  - false positive (FP): a benign event a rule matched, that a human then has
    to look at and rule out. Counted here as "benign_hits" from
    detection-rule-lab's scoring-run.json.
  - true positive (TP): an attack event the rule correctly matched. Counted
    here as "malicious_hits".
  - triage: the manual work an analyst does to look at one alert and decide
    whether it is real. Every alert, true or false, costs triage time.
  - SOC (Security Operations Center): the team of analysts who watch alerts
    and decide what to do about them.
  - break-even volume: the number of alerts at which cumulative triage cost
    equals the value assigned to catching the true positives the rule found.

MEASURED INPUTS (never assumed):
  - malicious_hits, benign_hits per rule, from detection-rule-lab's
    scoring-run.json. These are event counts on one benign host and one
    attack corpus, not alert rates. See the caveat banner.

ASSUMED INPUTS (swept across a labelled range, never a fixed constant):
  - triage_minutes_per_alert: minutes an analyst spends on ONE alert,
    true or false, before dismissing or escalating it. Swept 5/15/30/60.
  - analyst_hourly_cost: fully loaded hourly cost of an analyst's time
    (wage plus overhead). Swept $40/$75/$120 to span junior-tier through
    senior-tier SOC analyst cost bands. This is a labelled assumption,
    not a market survey result.
  - value_per_true_positive: the value assigned to catching one true
    attack event. This number is NOT measurable from the corpus and is
    NOT asserted; the break-even analysis instead asks "at what per-alert
    cost does the cumulative triage cost of ALL hits (TP+FP) equal a
    stated per-TP value", making the swept output the interesting part,
    not a claimed dollar total.

FORBIDDEN AND NOT DONE HERE: multiplying any of the above by a fleet size
to produce an absolute headline dollar figure. See README.md, "What this
project refuses to do."

Read-only: opens detection-rule-lab/reports/scoring-run.json for reading
and never writes to that project.

Idempotent: deterministic given its inputs; no randomness, no network.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CAVEAT_BANNER, EVIDENCE_DIR, load_scoring_run, rules_touching_benign

# Swept assumption ranges. Every one of these is an ASSUMPTION, labelled as such
# on every chart and in every table this script produces.
TRIAGE_MINUTES_SWEEP = [5, 15, 30, 60]
ANALYST_HOURLY_COST_SWEEP = [40, 75, 120]  # USD/hour, fully loaded
VALUE_PER_TP_SWEEP = [50, 200, 1000]  # USD, assumed value of catching one true attack event


def per_alert_cost(triage_minutes: float, hourly_cost: float) -> float:
    """Cost in USD of triaging ONE alert, given assumed minutes and hourly rate."""
    return (triage_minutes / 60.0) * hourly_cost


def cumulative_triage_cost(total_hits: int, triage_minutes: float, hourly_cost: float) -> float:
    """Total triage cost for ALL hits (TP + FP) a rule produced on this corpus."""
    return total_hits * per_alert_cost(triage_minutes, hourly_cost)


def value_captured(malicious_hits: int, value_per_tp: float) -> float:
    """Total value assigned to the true positives this rule actually caught."""
    return malicious_hits * value_per_tp


def breakeven_triage_minutes(malicious_hits: int, benign_hits: int, hourly_cost: float, value_per_tp: float) -> float | None:
    """Solve for the triage_minutes at which cumulative cost == value captured.

    cumulative_cost(m) = (malicious_hits + benign_hits) * (m/60) * hourly_cost
    value = malicious_hits * value_per_tp
    Set equal and solve for m:
      m = value * 60 / ((malicious_hits + benign_hits) * hourly_cost)

    Returns None if malicious_hits is 0: no finite triage-minutes assumption
    makes a 0-true-positive rule break even, because cumulative cost is
    strictly positive for any nonzero benign_hits and any nonzero triage
    minutes, while value captured is always exactly zero. This is the
    formal statement of "cost-negative at any nonzero assumption."
    """
    total_hits = malicious_hits + benign_hits
    if total_hits == 0:
        return None
    if malicious_hits == 0:
        return None
    value = value_captured(malicious_hits, value_per_tp)
    return value * 60.0 / (total_hits * hourly_cost)


def build_sweep_table(scoring_run: dict) -> list[dict]:
    touching = rules_touching_benign(scoring_run)
    rows = []
    for r in touching:
        mal, ben = r["malicious_hits"], r["benign_hits"]
        total = mal + ben
        row = {
            "rule_id": r["rule_id"],
            "title": r["title"],
            "malicious_hits": mal,
            "benign_hits": ben,
            "total_hits": total,
            "cost_negative_at_any_nonzero_assumption": mal == 0,
            "sweep": [],
        }
        for triage_min in TRIAGE_MINUTES_SWEEP:
            for hourly in ANALYST_HOURLY_COST_SWEEP:
                for value_tp in VALUE_PER_TP_SWEEP:
                    cost = cumulative_triage_cost(total, triage_min, hourly)
                    value = value_captured(mal, value_tp)
                    row["sweep"].append(
                        {
                            "triage_minutes": triage_min,
                            "analyst_hourly_cost": hourly,
                            "value_per_true_positive": value_tp,
                            "cumulative_triage_cost_usd": round(cost, 2),
                            "value_captured_usd": round(value, 2),
                            "net_usd": round(value - cost, 2),
                            "cost_justified": value >= cost,
                        }
                    )
        be_minutes = []
        for hourly in ANALYST_HOURLY_COST_SWEEP:
            for value_tp in VALUE_PER_TP_SWEEP:
                m = breakeven_triage_minutes(mal, ben, hourly, value_tp)
                be_minutes.append(
                    {
                        "analyst_hourly_cost": hourly,
                        "value_per_true_positive": value_tp,
                        "breakeven_triage_minutes": None if m is None else round(m, 2),
                    }
                )
        row["breakeven_triage_minutes_by_assumption"] = be_minutes
        rows.append(row)
    return rows


def print_summary(rows: list[dict]) -> None:
    print(CAVEAT_BANNER)
    print()
    print("ASSUMPTIONS SWEPT (none of these is measured; all are labelled inputs):")
    print(f"  triage_minutes_per_alert swept over: {TRIAGE_MINUTES_SWEEP}")
    print(f"  analyst_hourly_cost (USD) swept over: {ANALYST_HOURLY_COST_SWEEP}")
    print(f"  value_per_true_positive (USD) swept over: {VALUE_PER_TP_SWEEP}")
    print()
    for row in rows:
        print(f"--- {row['title']} ---")
        print(f"    malicious_hits={row['malicious_hits']}  benign_hits={row['benign_hits']}")
        if row["cost_negative_at_any_nonzero_assumption"]:
            print(
                "    malicious_hits == 0: this rule captured ZERO measured value on this "
                "corpus. Cumulative triage cost is positive for ANY nonzero triage-minutes "
                "assumption, so it is cost-negative at every point in the sweep with no "
                "exception. No break-even minute value exists; there is nothing to solve for."
            )
        else:
            finite = [b for b in row["breakeven_triage_minutes_by_assumption"] if b["breakeven_triage_minutes"] is not None]
            mins = [b["breakeven_triage_minutes"] for b in finite]
            if mins:
                print(
                    f"    break-even triage minutes across the swept assumption grid: "
                    f"min={min(mins):.2f}  max={max(mins):.2f}"
                )
        print()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit full JSON sweep instead of a summary")
    parser.add_argument("--save", action="store_true", help="also write evidence/02_breakeven.json")
    args = parser.parse_args()

    scoring_run = load_scoring_run()
    rows = build_sweep_table(scoring_run)

    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        print_summary(rows)

    if args.save:
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        out_path = EVIDENCE_DIR / "02_breakeven.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2)
        print(f"\nSaved to {out_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
