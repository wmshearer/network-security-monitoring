#!/usr/bin/env python3
"""Build tests/rule_tests.json, the Zircolite --test-rules CI fixture.

Every true_positive and true_negative event in the fixture is a REAL event
pulled from splunk-detection-lab's real converted attack/benign JSON, not
invented. Only the fields relevant to each rule's condition are kept, plus
EventID, so the fixture stays readable; the full original event is not
needed because Zircolite's `--test-rules` mode matches on exactly the
columns the rule's SQL condition references.

This mirrors the real Zircolite CI pattern documented at
vendor/Zircolite/docs/Usage.md ("Rule testing" section): a JSON array,
matched by rule title or id, each carrying true_positive/true_negative
event arrays. Zircolite runs these with no --events input needed and exits
1 if any case fails, which is what tests/test_zircolite_rule_tests.py in
this project checks.
"""

from __future__ import annotations

import glob
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ATTACK_DIR = Path("/home/kali/director/projects/splunk-detection-lab/data/converted/attack")
BENIGN_DIR = Path("/home/kali/director/projects/splunk-detection-lab/data/converted/benign")
OUT_PATH = ROOT / "tests" / "rule_tests.json"


def find_first(files: list[str], pred) -> dict | None:
    for f in files:
        with open(f) as fh:
            for line in fh:
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if pred(obj):
                    return obj
    return None


def trim(event: dict, keep: list[str]) -> dict:
    return {k: event[k] for k in keep if k in event}


def main() -> int:
    attack_files = sorted(glob.glob(str(ATTACK_DIR / "*.json")))
    benign_files = sorted(glob.glob(str(BENIGN_DIR / "*.json")))

    cases = []

    # D1: registry Run key
    d1_tp = find_first(attack_files, lambda o: o.get("EventID") == 13 and "\\Run\\" in str(o.get("TargetObject", "")))
    d1_tn = find_first(benign_files, lambda o: o.get("EventID") == 13)
    cases.append({
        "id": "8f1a2b3c-0001-4d1e-9a11-1a2b3c4d5e01",
        "title": "Registry Run Key Value Set",
        "true_positive": [trim(d1_tp, ["EventID", "TargetObject"])],
        "true_negative": [trim(d1_tn, ["EventID", "TargetObject"])],
    })

    # D2: schtasks + powershell + hidden
    d2_tp = find_first(attack_files, lambda o: o.get("EventID") == 1 and str(o.get("Image", "")).lower().endswith("schtasks.exe") and "powershell" in str(o.get("CommandLine", "")).lower() and "hidden" in str(o.get("CommandLine", "")).lower())
    d2_tn = find_first(benign_files, lambda o: o.get("EventID") == 1 and str(o.get("CommandLine", "")))
    cases.append({
        "id": "8f1a2b3c-0002-4d1e-9a11-1a2b3c4d5e02",
        "title": "Schtasks Creates Task Running Hidden PowerShell",
        "true_positive": [trim(d2_tp, ["EventID", "Image", "CommandLine"])],
        "true_negative": [trim(d2_tn, ["EventID", "Image", "CommandLine"])],
    })

    # D3: net.exe localgroup admins
    d3_tp = find_first(attack_files, lambda o: o.get("EventID") == 1 and str(o.get("Image", "")).lower().endswith(("net.exe", "net1.exe")) and "localgroup" in str(o.get("CommandLine", "")).lower() and "administ" in str(o.get("CommandLine", "")).lower())
    d3_tn = find_first(benign_files, lambda o: o.get("EventID") == 1 and str(o.get("CommandLine", "")))
    cases.append({
        "id": "8f1a2b3c-0003-4d1e-9a11-1a2b3c4d5e03",
        "title": "Net.exe Localgroup Administrators Enumeration",
        "true_positive": [trim(d3_tp, ["EventID", "Image", "CommandLine"])],
        "true_negative": [trim(d3_tn, ["EventID", "Image", "CommandLine"])],
    })

    # D4: net.exe user enum, not localgroup
    d4_tp = find_first(attack_files, lambda o: o.get("EventID") == 1 and str(o.get("Image", "")).lower().endswith(("net.exe", "net1.exe")) and "user" in str(o.get("CommandLine", "")).lower() and "localgroup" not in str(o.get("CommandLine", "")).lower())
    cases.append({
        "id": "8f1a2b3c-0004-4d1e-9a11-1a2b3c4d5e04",
        "title": "Net.exe User Enumeration",
        "true_positive": [trim(d4_tp, ["EventID", "Image", "CommandLine"])],
        "true_negative": [trim(d3_tn, ["EventID", "Image", "CommandLine"])],
    })

    # D5: process access to AUDIODG.EXE
    d5_tp = find_first(attack_files, lambda o: o.get("EventID") == 10 and str(o.get("TargetImage", "")).lower().endswith("audiodg.exe"))
    d5_tn = find_first(benign_files, lambda o: o.get("EventID") == 10 and o.get("TargetImage"))
    cases.append({
        "id": "8f1a2b3c-0005-4d1e-9a11-1a2b3c4d5e05",
        "title": "Process Access to AUDIODG.EXE",
        "true_positive": [trim(d5_tp, ["EventID", "TargetImage"])],
        "true_negative": [trim(d5_tn, ["EventID", "TargetImage"])],
    })

    # D6: powershell parent spawns net/net1/schtasks
    d6_tp = find_first(attack_files, lambda o: o.get("EventID") == 1 and str(o.get("ParentImage", "")).lower().endswith("powershell.exe") and str(o.get("Image", "")).lower().endswith(("net.exe", "net1.exe", "schtasks.exe")))
    d6_tn = find_first(benign_files, lambda o: o.get("EventID") == 1 and o.get("ParentImage") and o.get("Image"))
    cases.append({
        "id": "8f1a2b3c-0006-4d1e-9a11-1a2b3c4d5e06",
        "title": "PowerShell Spawns Recon Tool",
        "true_positive": [trim(d6_tp, ["EventID", "ParentImage", "Image"])],
        "true_negative": [trim(d6_tn, ["EventID", "ParentImage", "Image"])],
    })

    missing = [c["title"] for c in cases if not c["true_positive"][0] or not c["true_negative"][0]]
    if missing:
        raise RuntimeError("could not find real true_positive/true_negative event for: %s" % missing)

    OUT_PATH.write_text(json.dumps(cases, indent=2))
    print("wrote %s (%d rule test cases, all events real, pulled from splunk-detection-lab data/converted/)"
          % (OUT_PATH, len(cases)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
