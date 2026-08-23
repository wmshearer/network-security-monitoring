#!/usr/bin/env python3
"""Score each SPL detection against ground truth and print/save a scoring table.

SCORING UNIT -- stated explicitly because it is a real methodological choice,
not an obvious default:

These are SPL detection rules (event-matching filters), not a per-event
classifier scored over every one of the corpus's 292,992 events. The right
unit of analysis for "did this detection do its job" is standard SOC
detection-engineering practice, not ai-triage-engine's per-alert-record
classifier framing (that project scores a triage verdict on EVERY event; this
project's detections only ever fire on a small subset by design, and most
events in an attack capture are session noise around the actual technique,
not instances of the technique itself -- see README.md's "what 'attack'
labels actually claim" section for why 40,569 events in one capture does NOT
mean 40,569 chances to detect T1547.001).

So scoring here is:
  - TRUE POSITIVE (detection-level): the detection's SPL matches >=1 event in
    the OTRF capture whose ground-truth technique_id equals the detection's
    mapped technique. One capture = one technique-execution instance = one
    TP/FN opportunity (5 atomic captures = 5 opportunities total across all
    detections combined; each detection targets exactly one capture except
    D6, scored as a hit against every capture it is intended to generalize
    across).
  - FALSE NEGATIVE (detection-level): the detection's target capture produced
    zero matching events.
  - FALSE POSITIVE (event-level): every BENIGN event (label=benign) that
    matches the detection's SPL. Reported as a raw count, not a rate against
    "all benign events" (292,992-event denominator would understate the
    per-alert relevance a SOC analyst actually experiences) -- see
    FINDINGS.md for the honest discussion of what this count does and does
    not represent (small, non-representative benign sample; see caveats).
  - CROSS-CONTAMINATION CHECK (event-level): does the detection also match
    attack events from OTHER techniques' captures? Reported separately from
    the FP count above because an attack-labeled-but-wrong-technique match is
    a different failure mode (technique misattribution) than a benign false
    alarm, and conflating them would hide which one actually occurred.

Precision/recall are computed at the DETECTION level (across the 5 atomic
captures + benign baseline), not pretending this is a 292,992-row confusion
matrix -- doing that would silently misrepresent what "recall" means for a
rule that was never designed to fire on background telemetry within its own
capture.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from splunk_search import run_search  # noqa: E402


DETECTIONS = [
    {
        "name": "D1_registry_run_key_setvalue",
        "technique_id": "T1547.001",
        "target_capture": "empire_persistence_registry_modification_run_keys_standard_user",
        "spl_file": "evidence/detection_dev/d1_registry_run_key.spl",
        "generalizes": False,
    },
    {
        "name": "D2_schtasks_encoded_powershell",
        "technique_id": "T1053.005",
        "target_capture": "empire_schtasks_creation_standard_user",
        "spl_file": "evidence/detection_dev/d2_schtasks_encoded_powershell.spl",
        "generalizes": False,
    },
    {
        "name": "D3_net_localgroup_administrators",
        "technique_id": "T1069.001",
        "target_capture": "empire_shell_net_localgroup_administrators",
        "spl_file": "evidence/detection_dev/d3_net_localgroup_admins.spl",
        "generalizes": False,
    },
    {
        "name": "D4_net_user_enumeration",
        "technique_id": "T1087.001",
        "target_capture": "empire_shell_net_local_users",
        "spl_file": "evidence/detection_dev/d4_net_user_enum.spl",
        "generalizes": False,
    },
    {
        "name": "D5_process_access_audiodg",
        "technique_id": "T1123",
        "target_capture": "msf_record_mic",
        "spl_file": "evidence/detection_dev/d5_process_access_audiodg.spl",
        "generalizes": False,
    },
    {
        "name": "D6_powershell_spawns_recon_tool",
        "technique_id": "T1059.001",
        # D6 is deliberately cross-cutting: it targets the PARENT-CHILD
        # PATTERN (PowerShell spawning net.exe/net1.exe/schtasks.exe), which
        # is present across 3 of the 5 atomic captures, not one specific
        # technique's telemetry. Scored against all 3 as separate detection
        # opportunities.
        "target_capture": [
            "empire_schtasks_creation_standard_user",
            "empire_shell_net_localgroup_administrators",
            "empire_shell_net_local_users",
        ],
        "spl_file": "evidence/detection_dev/d6_powershell_spawns_recon_tool.spl",
        "generalizes": True,
    },
]


def compute_scores(
    name: str,
    technique_id: str,
    target_capture: str | list[str],
    hits_by_capture: dict[str, int],
    benign_fp_event_count: int,
) -> dict:
    """Pure scoring logic: turn raw hit-counts into TP/FN/cross-contamination.

    Split out from `score_one` (which fetches `hits_by_capture` and
    `benign_fp_event_count` live from Splunk) specifically so
    tests/test_scoring.py can exercise the scoring rules -- TP/FN
    determination, cross-contamination detection, recall computation -- with
    hand-built inputs, without needing a live Splunk instance to run the test
    suite. See module docstring for the scoring-unit rationale this encodes.
    """
    targets = target_capture if isinstance(target_capture, list) else [target_capture]

    tp_captures = [c for c in targets if hits_by_capture.get(c, 0) > 0]
    fn_captures = [c for c in targets if hits_by_capture.get(c, 0) == 0]
    cross_contamination = {
        capture: count
        for capture, count in hits_by_capture.items()
        if capture not in targets
    }

    tp = len(tp_captures)
    fn = len(fn_captures)
    n_opportunities = len(targets)

    # NOTE: no single "precision" number is computed here deliberately --
    # capture-count TP/FN and event-count benign-FP are different units
    # (captures vs. events), and dividing one by the other would manufacture
    # a number that looks precise but isn't meaningful. See FINDINGS.md for
    # the two numbers reported side by side instead.
    recall = tp / n_opportunities if n_opportunities else None

    return {
        "detection": name,
        "technique_id": technique_id,
        "target_captures": targets,
        "hits_by_capture": hits_by_capture,
        "tp_captures": tp_captures,
        "fn_captures": fn_captures,
        "cross_contamination": cross_contamination,
        "benign_fp_event_count": benign_fp_event_count,
        "n_opportunities": n_opportunities,
        "tp": tp,
        "fn": fn,
        "recall": recall,
        "fired_on_any_benign": benign_fp_event_count > 0,
    }


def score_one(detection: dict, base_search: str) -> dict:
    # Per-capture hit counts (labeled attack events only) -- drives TP/FN and
    # the cross-contamination check.
    per_capture_search = f"{base_search} label=attack | stats count by source_capture"
    per_capture = run_search(per_capture_search)
    hits_by_capture: dict[str, int] = {
        row["source_capture"]: int(row["count"]) for row in per_capture.get("results", [])
    }

    # Benign false positives (event-level count).
    fp_search = f"{base_search} label=benign | stats count"
    fp_result = run_search(fp_search)
    fp_rows = fp_result.get("results", [])
    fp_count = int(fp_rows[0]["count"]) if fp_rows else 0

    return compute_scores(
        name=detection["name"],
        technique_id=detection["technique_id"],
        target_capture=detection["target_capture"],
        hits_by_capture=hits_by_capture,
        benign_fp_event_count=fp_count,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="evidence/scoring_results.json")
    args = ap.parse_args()

    results = []
    for detection in DETECTIONS:
        spl_path = Path(detection["spl_file"])
        base_search = spl_path.read_text().strip()
        result = score_one(detection, base_search)
        results.append(result)
        print(f"{result['detection']} ({result['technique_id']}): "
              f"TP={result['tp']}/{result['n_opportunities']} captures, "
              f"benign FPs={result['benign_fp_event_count']}, "
              f"cross-contamination={result['cross_contamination']}")

    total_tp = sum(r["tp"] for r in results)
    total_fn = sum(r["fn"] for r in results)
    total_opportunities = sum(r["n_opportunities"] for r in results)
    total_benign_fp_events = sum(r["benign_fp_event_count"] for r in results)
    detections_with_any_fp = sum(1 for r in results if r["fired_on_any_benign"])

    summary = {
        "per_detection": results,
        "totals": {
            "total_tp_captures": total_tp,
            "total_fn_captures": total_fn,
            "total_detection_opportunities": total_opportunities,
            "capture_level_recall": total_tp / total_opportunities if total_opportunities else None,
            "total_benign_fp_events": total_benign_fp_events,
            "detections_with_any_benign_fp": detections_with_any_fp,
            "detections_total": len(results),
        },
    }

    Path(args.out).write_text(json.dumps(summary, indent=2))
    print(f"\nwrote {args.out}")
    print(json.dumps(summary["totals"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
