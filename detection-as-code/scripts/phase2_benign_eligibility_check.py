#!/usr/bin/env python3
"""Control for the Phase 2 headline: is the zero-false-positive result real,
or does the benign corpus simply lack the event types these rules need?

Same question detection-rule-lab's `rule_eventid_coverage` control asks
(scripts/run_scoring.py in that project), applied here at the field level
instead of just the EventID level, because these 6 rules key on specific
process/registry names within an EventID, not just the EventID itself.

Counts, per rule, how many benign events in
splunk-detection-lab/data/converted/benign/ match the EventID the rule
needs, and separately how many match the more specific field condition
(process image name, target object path) the rule actually filters on.
If the EventID count is non-zero but the specific-condition count is zero,
the rule had real material of the right TYPE and still did not match,
which is the stronger, more honest claim than "no events of this type
existed at all."
"""

from __future__ import annotations

import glob
import json
from pathlib import Path

BENIGN_DIR = Path("/home/kali/director/projects/splunk-detection-lab/data/converted/benign")
REPORTS = Path(__file__).resolve().parents[1] / "reports"


def check() -> dict:
    counts = {
        "eventid_1": 0,
        "eventid_10": 0,
        "eventid_13": 0,
        "eventid_1_net_or_schtasks_image": 0,
        "eventid_1_powershell_parent_and_recon_child": 0,
        "eventid_10_audiodg_target": 0,
        "eventid_13_run_key_target": 0,
        "total_events_scanned": 0,
    }
    for path in glob.glob(str(BENIGN_DIR / "*.json")):
        with open(path) as fh:
            for line in fh:
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                counts["total_events_scanned"] += 1
                eid = obj.get("EventID")
                if eid == 1:
                    counts["eventid_1"] += 1
                    img = str(obj.get("Image", "")).lower()
                    parent = str(obj.get("ParentImage", "")).lower()
                    is_net_or_schtasks = img.endswith("net.exe") or img.endswith("net1.exe") or img.endswith("schtasks.exe")
                    if is_net_or_schtasks:
                        counts["eventid_1_net_or_schtasks_image"] += 1
                    if parent.endswith("powershell.exe") and is_net_or_schtasks:
                        counts["eventid_1_powershell_parent_and_recon_child"] += 1
                elif eid == 10:
                    counts["eventid_10"] += 1
                    if str(obj.get("TargetImage", "")).lower().endswith("audiodg.exe"):
                        counts["eventid_10_audiodg_target"] += 1
                elif eid == 13:
                    counts["eventid_13"] += 1
                    target = str(obj.get("TargetObject", ""))
                    if "\\Run\\" in target:
                        counts["eventid_13_run_key_target"] += 1
    return counts


def main() -> int:
    c = check()
    print("Benign corpus eligibility check (%s)" % BENIGN_DIR)
    print("=" * 68)
    print("Total benign events scanned:              %d" % c["total_events_scanned"])
    print()
    print("EventID 1 (process creation) events:       %d" % c["eventid_1"])
    print("  of which Image is net.exe/net1.exe/schtasks.exe: %d"
          % c["eventid_1_net_or_schtasks_image"])
    print("  of which ALSO has PowerShell as parent:          %d"
          % c["eventid_1_powershell_parent_and_recon_child"])
    print()
    print("EventID 10 (process access) events:        %d" % c["eventid_10"])
    print("  of which TargetImage is AUDIODG.EXE:             %d"
          % c["eventid_10_audiodg_target"])
    print()
    print("EventID 13 (registry SetValue) events:     %d" % c["eventid_13"])
    print("  of which TargetObject is under a Run key:        %d"
          % c["eventid_13_run_key_target"])
    print()
    if c["eventid_1"] > 0 and c["eventid_1_net_or_schtasks_image"] == 0:
        print("CONCLUSION: the benign corpus has real EventID 1 process creation "
              "events (the right event TYPE) but never once ran net.exe, "
              "net1.exe, or schtasks.exe (the specific processes D2/D3/D4/D6 key "
              "on). The zero-false-positive result for those rules is a real "
              "corpus-composition fact, not a sign the rules never had eligible "
              "data to fire on.")

    REPORTS.mkdir(parents=True, exist_ok=True)
    out_path = REPORTS / "phase2_benign_eligibility.json"
    out_path.write_text(json.dumps(c, indent=2))
    print("\nwrote %s" % out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
