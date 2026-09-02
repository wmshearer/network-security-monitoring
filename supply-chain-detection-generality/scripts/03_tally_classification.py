#!/usr/bin/env python3
"""
Read the hand-classification rubric (rubric/calls.csv, one row per detection,
every call justified with the exact search fragment it rests on) and compute
the tally that answers the falsifiable claim:

  "Of Splunk's supply chain detection content, N of M detections are bound to
   indicators from one specific incident and would not fire on a different
   attack using the same technique."

This script does not re-derive the classification; it only counts what a
human reviewer already decided and wrote down in rubric/calls.csv. See
rubric/RUBRIC.md for why hand classification was chosen over a regex.

Read-only. Writes evidence/03_classification_tally.json.
"""
import csv
import json
import sys
from pathlib import Path

CALLS = Path(__file__).resolve().parent.parent / "rubric" / "calls.csv"
OUT = Path(__file__).resolve().parent.parent / "evidence" / "03_classification_tally.json"


def main():
    if not CALLS.exists():
        print(f"SKIP: {CALLS} not found", file=sys.stderr)
        sys.exit(0)

    rows = list(csv.DictReader(open(CALLS)))
    total = len(rows)
    counts = {}
    for r in rows:
        counts[r["class"]] = counts.get(r["class"], 0) + 1

    incident_bound = counts.get("incident-bound", 0)
    behavioral = counts.get("behavioral", 0)
    mixed = counts.get("mixed", 0)

    claim_holds = incident_bound > (total / 2)

    result = {
        "total_detections": total,
        "counts_by_class": counts,
        "incident_bound": incident_bound,
        "behavioral": behavioral,
        "mixed": mixed,
        "claim_as_originally_framed": (
            f"{incident_bound} of {total} detections are bound to indicators "
            f"from one specific incident"
        ),
        "claim_holds_majority_incident_bound": claim_holds,
        "verdict": (
            "CLAIM HOLDS: most detections are incident-bound"
            if claim_holds
            else "CLAIM REVERSES: most detections are behavioral, not incident-bound"
        ),
        "incident_bound_files": [r["file"] for r in rows if r["class"] == "incident-bound"],
        "behavioral_files": [r["file"] for r in rows if r["class"] == "behavioral"],
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2) + "\n")

    print(f"Wrote {OUT}")
    print(f"  total: {total}")
    print(f"  incident-bound: {incident_bound}")
    print(f"  behavioral: {behavioral}")
    print(f"  mixed: {mixed}")
    print(f"  {result['verdict']}")


if __name__ == "__main__":
    main()
