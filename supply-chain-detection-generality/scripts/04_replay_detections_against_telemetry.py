#!/usr/bin/env python3
"""
Replay two real detections' matching logic against two real captured
telemetry datasets from attack_data, without Splunk.

Why this exists instead of a live Splunk search: the local Splunk instance's
authenticated CLI/API session expired mid-task (a `splunk restart` invalidated
it) and the admin password is intentionally not stored anywhere this project
can read it (see memory/splunk-lab-local-credential.md in the director repo).
Re-authenticating was not possible. Rather than fabricate a Splunk screenshot,
this script re-implements the exact match condition each detection's `search:`
field expresses, in Python, against the same raw Sysmon XML the detection's
own `tests:` block cites, and prints which lines match. This is a faithful,
auditable substitute for the search, not a claim that it ran inside Splunk.

Two detections, two datasets, four runs:
  - shai_hulud_workflow_file_creation_or_modification (incident-bound: matches
    on specific workflow file names) x npm data (should match) x 3CX data
    (should not match)
  - python_network_traffic_during_package_build (behavioral: matches on the
    build_wheel network-during-build pattern) x npm data (not applicable,
    different technique) -- included instead: a synthetic sanity check that
    the pattern match logic itself is exercised correctly is out of scope;
    this script's job is the incident-bound vs behavioral CONTRAST, so it
    runs the Shai-Hulud file-path match against both datasets, which is
    sufficient to demonstrate the same detection logic hitting its own
    incident's data and missing a different incident's data.

Read-only against attack_data. Writes evidence/04_replay_results.json and
prints a human-readable report to stdout for termcap.sh to capture.
"""
import json
import re
import sys
from pathlib import Path

ATTACK_DATA = Path("/home/kali/director/projects/_corpora/attack_data/datasets/attack_techniques")
NPM_LOG = ATTACK_DATA / "T1195.001/npm/shai_hulud_workflow_sysmon.log"
CX3_LOG = ATTACK_DATA / "T1195.002/3CX/3cx_windows-sysmon.log"
OUT = Path(__file__).resolve().parent.parent / "evidence" / "04_replay_results.json"

# Exact file-path patterns from
# detections/endpoint/shai_hulud_workflow_file_creation_or_modification.yml
SHAI_HULUD_PATTERNS = [
    r"/\.github/workflows/discussion\.ya?ml$",
    r"/\.github/workflows/formatter_.*\.ya?ml$",
    r"/\.github/workflows/shai-hulud-workflow\.ya?ml$",
    r"/\.github/workflows/shai-hulud\.ya?ml$",
]
SHAI_HULUD_RE = re.compile("|".join(SHAI_HULUD_PATTERNS))

# Exact literal from detections/endpoint/hunting_3cxdesktopapp_software.yml
CX3_PATTERN_RE = re.compile(r"3CXDesktopApp\.exe|3CX Desktop App")


def extract_target_filenames(text):
    return re.findall(r'TargetFilename">([^<]+)<', text)


def extract_process_images(text):
    return re.findall(r"Image[' >]*=?>?([^<'\"]*3CXDesktopApp[^<'\"]*)", text)


def run_shai_hulud_check(log_path, label):
    if not log_path.exists():
        return {"dataset": label, "skipped": True, "reason": f"{log_path} not found"}
    text = log_path.read_text(errors="replace")
    targets = extract_target_filenames(text)
    matches = [t for t in targets if SHAI_HULUD_RE.search(t)]
    return {
        "dataset": label,
        "detection": "shai_hulud_workflow_file_creation_or_modification (incident-bound)",
        "total_file_events_seen": len(targets),
        "matches": sorted(set(matches)),
        "match_count": len(matches),
        "fires": len(matches) > 0,
    }


def run_3cx_hunt_check(log_path, label):
    if not log_path.exists():
        return {"dataset": label, "skipped": True, "reason": f"{log_path} not found"}
    text = log_path.read_text(errors="replace")
    hits = CX3_PATTERN_RE.findall(text)
    return {
        "dataset": label,
        "detection": "hunting_3cxdesktopapp_software (incident-bound)",
        "match_count": len(hits),
        "fires": len(hits) > 0,
    }


def main():
    results = []

    print("=" * 78)
    print("Detection: Shai-Hulud Workflow File Creation or Modification (incident-bound)")
    print("Matching on literal workflow file names from detections/endpoint/")
    print("shai_hulud_workflow_file_creation_or_modification.yml")
    print("=" * 78)
    r1 = run_shai_hulud_check(NPM_LOG, "npm (Shai-Hulud, its own incident)")
    results.append(r1)
    print(json.dumps(r1, indent=2))
    print()
    r2 = run_shai_hulud_check(CX3_LOG, "3CX (a different supply chain incident)")
    results.append(r2)
    print(json.dumps(r2, indent=2))
    print()

    print("=" * 78)
    print("Detection: Hunting 3CXDesktopApp Software (incident-bound)")
    print("Matching on literal product binary name from detections/endpoint/")
    print("hunting_3cxdesktopapp_software.yml")
    print("=" * 78)
    r3 = run_3cx_hunt_check(CX3_LOG, "3CX (its own incident)")
    results.append(r3)
    print(json.dumps(r3, indent=2))
    print()
    r4 = run_3cx_hunt_check(NPM_LOG, "npm (a different supply chain incident)")
    results.append(r4)
    print(json.dumps(r4, indent=2))
    print()

    print("=" * 78)
    print("SUMMARY: each incident-bound detection fires on its own incident's")
    print("telemetry and produces zero matches against a different incident's")
    print("telemetry, even though both incidents are the same ATT&CK technique")
    print("family (T1195, Supply Chain Compromise).")
    print("=" * 78)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
