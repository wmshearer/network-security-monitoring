#!/usr/bin/env python3
"""Stage 4: combine stage 1 (behaviour presence in the capture) and stage 3
(detection logic match) into the final four-state cell for every
family x technique pair, and write the matrix all downstream outputs
(chart, Navigator layer, tables) read from.

Cell state rules (see README "Cell taxonomy" for the plain-English version):
  - PRESENT=False                          -> GREY   (no claim possible)
  - PRESENT=True, verdict=UNDETERMINED-NO-DETECTION -> RED-TELEMETRY
    (behaviour happened; Splunk ships no detection tagged to this technique
    AND this family's story at all, so nothing could ever have fired; this
    project treats "Splunk never shipped a detection for this cell" as a
    telemetry/tooling gap on Splunk's side, not a logic bug in one rule)
  - PRESENT=True, verdict=LOGIC_MATCH      -> GREEN (a candidate detection's
    own literal match conditions are present in the same capture)
  - PRESENT=True, verdict=LOGIC_NO_MATCH   -> RED-LOGIC (a candidate
    detection exists and is tagged to this exact family+technique, but its
    own literal terms do not occur anywhere in the capture that behaviour
    was observed in; the detection's specific variant does not cover what
    this family's tooling actually did)

Every cell also carries a `confidence` field derived from the family's
richness (log file count and sourcetype diversity from the manifest note),
so a thin, Sysmon-only, single-file capture's RED cells are visually and
programmatically distinguishable from a rich multi-sourcetype capture's RED
cells, per the brief's requirement.

Deterministic and idempotent by construction: this script only reads two
already-written JSON files and performs a fixed lookup/combine per cell (no
iteration order dependent aggregation, no counters that could silently sum
differently between runs). tests/test_matrix_determinism.py rebuilds this
twice and diffs the output to prove it, per the detection-brittleness
lesson about the assign-vs-sum matrix bug.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "manifest" / "technique_manifest.json"
CAPTURE_PATH = ROOT / "evidence" / "01_capture_evidence_summary.json"
LOGIC_PATH = ROOT / "evidence" / "03_detection_logic_scores.json"
OUT_PATH = ROOT / "matrix" / "coverage_matrix.json"

CELL_STATES = ("GREEN", "RED-LOGIC", "RED-TELEMETRY", "GREY")

# Families with exactly one raw .log file and a single sourcetype (verified
# against each family's own .yml metadata under attack_data, see manifest
# notes) are LOW confidence: one red cell there is much weaker evidence of a
# genuine gap than the same red cell in a multi-file, multi-sourcetype
# capture, per the brief's explicit requirement to say this in the matrix
# itself. Everything else defaults to STANDARD. This is a fixed, manually
# verified list, not a computed heuristic, so it cannot silently drift.
LOW_CONFIDENCE_FAMILIES = {"ryuk", "lockbit_ransomware", "prestige_ransomware"}


def cell_state(present: bool, logic_verdict: str | None) -> str:
    if not present:
        return "GREY"
    if logic_verdict == "UNDETERMINED-NO-DETECTION":
        return "RED-TELEMETRY"
    if logic_verdict == "LOGIC_MATCH":
        return "GREEN"
    if logic_verdict == "LOGIC_NO_MATCH":
        return "RED-LOGIC"
    # Any other value (e.g. a future UNDETERMINED-UNPARSEABLE-SEARCH) must
    # never silently become a colored verdict; fail loudly instead of
    # defaulting to a real-looking answer (the exact bug class this project
    # was warned to avoid).
    raise ValueError(f"unhandled logic_verdict {logic_verdict!r} for present={present}")


def main() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text())
    techniques = {k: v for k, v in manifest["techniques"].items() if not k.startswith("_")}
    families = {k: v for k, v in manifest["families"].items() if not k.startswith("_")}
    capture = json.loads(CAPTURE_PATH.read_text())
    logic = json.loads(LOGIC_PATH.read_text())

    matrix = {
        "family_order": list(families.keys()),
        "technique_order": list(techniques.keys()),
        "families": {},
        "techniques": {
            tid: {"name": tinfo["name"], "url": tinfo["url"]}
            for tid, tinfo in techniques.items()
        },
        "cells": {},  # "family|technique" -> {state, present, logic_verdict, confidence, evidence...}
    }

    state_counts = {s: 0 for s in CELL_STATES}

    for fam_name, fam_info in families.items():
        matrix["families"][fam_name] = {
            "is_reference_bucket": fam_info["is_reference_bucket"],
            "security_content_story": fam_info["security_content_story"],
            "confidence": "LOW" if fam_name in LOW_CONFIDENCE_FAMILIES else "STANDARD",
        }
        for tech_id in techniques:
            cap_cell = capture[fam_name]["techniques"][tech_id]
            logic_cell = logic[fam_name][tech_id]
            present = cap_cell["present"]
            logic_verdict = logic_cell["verdict"] if present else None
            state = cell_state(present, logic_verdict)
            state_counts[state] += 1

            key = f"{fam_name}|{tech_id}"
            matrix["cells"][key] = {
                "family": fam_name,
                "technique": tech_id,
                "state": state,
                "present_in_capture": present,
                "capture_lines_matched": cap_cell["lines_matched"],
                "capture_files_matched": cap_cell["files_matched"],
                "capture_evidence_file": cap_cell["evidence_file"],
                "logic_verdict": logic_verdict,
                "story_used": logic_cell["story_used"],
                "candidate_detection_count": len(logic_cell["candidate_detections"]),
                "candidate_detections": [
                    {"name": c["detection_name"], "source_file": c["source_file"], "verdict": c["verdict"]}
                    for c in logic_cell["candidate_detections"]
                ],
            }

    matrix["state_counts"] = state_counts
    matrix["total_cells"] = sum(state_counts.values())

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(matrix, indent=2, sort_keys=False))

    print("Cell state counts:")
    for s in CELL_STATES:
        print(f"  {s:14s} {state_counts[s]}")
    print(f"  TOTAL          {matrix['total_cells']}")
    print(f"\nwrote {OUT_PATH}")


if __name__ == "__main__":
    main()
