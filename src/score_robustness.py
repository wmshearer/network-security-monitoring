#!/usr/bin/env python3
"""Score the 6 detections against MITRE CTID's "Summiting the Pyramid" (STP)
rubric and emit a CSV matching the real published column structure.

STP is a published methodology (Apache 2.0, MITRE Center for Threat-Informed
Defense) that scores a detection analytic's robustness: how much an
adversary has to change to evade it, not whether it currently fires. Levels
index (fetched directly, 2026-08-24):
https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/levels/

  Level 1  Ephemeral Values                          -- trivial for the
           adversary to change (a literal string, a file name).
  Level 2  Core to Adversary-Brought Tool /
           Outside [Network] Boundary                -- tied to a specific
           tool or implementation choice the adversary made; swap the tool,
           evade the analytic.
  Level 3  Core to Pre-Existing Tools /
           Inside [Network] Boundary                 -- tied to the adversary
           using a tool that is already present in the environment (a
           living-off-the-land binary), not to the literal arguments passed
           to it.
  Level 4  Core to Some Implementations of
           (Sub-)Technique                           -- an unavoidable fact
           of some, not all, ways of carrying out the (sub-)technique.
  Level 5  Core to Sub-Technique or Technique         -- invariant; evading
           it means abandoning the technique entirely.

The published scored-analytics CSV
(docs/analytics/ScoredAnalytics_12062024.csv in the STP GitHub repo, fetched
2026-08-24) has this exact header, used verbatim as this module's output
shape:
  Name,Analytic Robustness Score,Event Robustness Score,Filter Score,Final Score,Notes,Permalink

Event Robustness Score: for host telemetry, K (kernel-mode), U (user-mode),
or A (application), in ascending order of how easy the layer is to tamper
with from user space. All 6 detections here read Sysmon (a user-mode ETW
consumer, not a kernel driver), so every row in this project is "U" -- this
is stated, not left implicit, because it is itself a real limitation (see
FINDINGS.md): nothing here was scored at K or A, so this project only
exercises one third of the K/U/A axis.

Filter Score / Final Score: STP defines these for analytics whose match
logic includes a false-positive exclusion filter, scored separately because
a brittle filter can pull an otherwise-robust match down. None of these 6
detections' raw SPL (evidence/detection_dev/*.spl) has an exclusion filter
in that sense -- D4's "NOT CommandLine=*localgroup*" is part of its primary
match logic (distinguishing D4 from D3), not a false-positive suppression
filter bolted on after the fact. Filter Score is therefore "N/a" for all 6,
matching the published CSV's own use of "N/a" for analytics without a
filter component (e.g. its "Turla PNG Dropper Service" row), and Final
Score is left blank, also matching that CSV's own convention for rows with
no filter score to combine.

Scoring here is an analytic judgment against a published rubric, applied by
this project to its own detections -- not an independent measurement. See
FINDINGS.md's "What this cannot claim" section.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

ROBUSTNESS_SCORES = [
    {
        "name": "D1_registry_run_key_setvalue",
        "spl_file": "evidence/detection_dev/d1_registry_run_key.spl",
        "analytic_robustness_score": 4,
        "event_robustness_score": "U",
        "filter_score": "N/a",
        "final_score": "",
        "notes": (
            "Matches Sysmon EventID 13 (registry SetValue) where TargetObject "
            "falls under a CurrentVersion\\Run key. This is the OS-level "
            "mechanism Run-key persistence has to use: a named value has to be "
            "written under that key for the technique to work at all, "
            "regardless of value name or payload. Scored 4, not 5, because "
            "this covers only the Run-key variant of T1547.001, not every way "
            "T1547 (Boot or Logon Autostart Execution) can be implemented "
            "(Startup folder, Winlogon Helper DLL, and other subtechniques "
            "would not touch this TargetObject path at all)."
        ),
    },
    {
        "name": "D2_schtasks_encoded_powershell",
        "spl_file": "evidence/detection_dev/d2_schtasks_encoded_powershell.spl",
        "analytic_robustness_score": 1,
        "event_robustness_score": "U",
        "filter_score": "N/a",
        "final_score": "",
        "notes": (
            "Matches two literal substrings, \"powershell\" and \"hidden\", "
            "in a schtasks.exe command line. Both are attacker-chosen text "
            "with no relationship to the technique itself. Demonstrated "
            "evadable in this project: -WindowStyle 1 removes the word "
            "\"hidden\" while keeping identical behavior, and copying the "
            "interpreter to a neutral path removes the word \"powershell\" "
            "entirely. See evidence/robustness/evasion_results.json."
        ),
    },
    {
        "name": "D3_net_localgroup_administrators",
        "spl_file": "evidence/detection_dev/d3_net_localgroup_admins.spl",
        "analytic_robustness_score": 1,
        "event_robustness_score": "U",
        "filter_score": "N/a",
        "final_score": "",
        "notes": (
            "Image ends in net.exe/net1.exe AND CommandLine contains the "
            "literal keywords \"localgroup\"/\"administ\". net.exe is a "
            "pre-existing Windows tool, which would argue for a higher "
            "score, but the match logic itself keys on literal argument "
            "text, not on \"net.exe was used to touch group membership\" in "
            "general. A renamed copy of net.exe, an unusual invocation path, "
            "or the same enumeration done through Get-LocalGroupMember or an "
            "[ADSI] binding instead of shelling out never produces this "
            "CommandLine text, so the analytic scores at its weakest link: "
            "Level 1."
        ),
    },
    {
        "name": "D4_net_user_enumeration",
        "spl_file": "evidence/detection_dev/d4_net_user_enum.spl",
        "analytic_robustness_score": 1,
        "event_robustness_score": "U",
        "filter_score": "N/a",
        "final_score": "",
        "notes": (
            "Same class of match as D3 (net.exe/net1.exe, literal \"user\" "
            "keyword, and the absence of \"localgroup\" to separate it from "
            "D3). Same evasion path as D3: a renamed binary, a different "
            "invocation path, or native PowerShell/.NET enumeration instead "
            "of shelling out to net.exe all evade it without changing what "
            "the adversary is actually doing."
        ),
    },
    {
        "name": "D5_process_access_audiodg",
        "spl_file": "evidence/detection_dev/d5_process_access_audiodg.spl",
        "analytic_robustness_score": 2,
        "event_robustness_score": "U",
        "filter_score": "N/a",
        "final_score": "",
        "notes": (
            "Matches Sysmon EventID 10 (ProcessAccess) where TargetImage is "
            "AUDIODG.EXE. AUDIODG.EXE is itself a pre-existing Windows "
            "process (Windows Audio Device Graph Isolation), but the "
            "observable being matched is specific to how this Metasploit "
            "module happens to reach the microphone: it opens a handle to "
            "AUDIODG.EXE because that is the process that owns audio device "
            "handles on this Windows version. A different tool that captures "
            "audio through a different API path would not necessarily touch "
            "AUDIODG.EXE at all, so this is core to one adversary-brought "
            "tool's implementation choice, not to T1123 (Audio Capture) in "
            "general. Scored 2."
        ),
    },
    {
        "name": "D6_powershell_spawns_recon_tool",
        "spl_file": "evidence/detection_dev/d6_powershell_spawns_recon_tool.spl",
        "analytic_robustness_score": 2,
        "event_robustness_score": "U",
        "filter_score": "N/a",
        "final_score": "",
        "notes": (
            "Matches a process-relationship fact (ParentImage=powershell.exe "
            "spawning Image=net.exe/net1.exe/schtasks.exe), not command-line "
            "text, so it does not break under the same command-line edits "
            "that defeat D2-D4 -- demonstrated directly in "
            "evidence/robustness/evasion_results.json, where D6 keeps firing "
            "on the same edited events that stop D2 from firing. Still scored "
            "2, not higher, because it depends on two facts the adversary "
            "controls: that PowerShell specifically is the parent (a "
            ".NET-native or COM-based path spawns no visible child at all) "
            "and that the child is one of exactly three named binaries. "
            "Avoiding either one evades the analytic without abandoning the "
            "underlying technique, which is what keeps this at "
            "\"adversary-brought tool choice\" rather than Level 3+."
        ),
    },
]


def build_rows() -> list[dict]:
    rows = []
    for d in ROBUSTNESS_SCORES:
        spl = Path(d["spl_file"]).read_text().strip()
        rows.append(
            {
                "Name": d["name"],
                "Analytic Robustness Score": d["analytic_robustness_score"],
                "Event Robustness Score": d["event_robustness_score"],
                "Filter Score": d["filter_score"],
                "Final Score": d["final_score"],
                "Notes": d["notes"],
                "Permalink": f"{d['spl_file']} :: {spl}",
            }
        )
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="evidence/robustness/stp_scores.csv")
    args = ap.parse_args()

    rows = build_rows()
    fieldnames = [
        "Name",
        "Analytic Robustness Score",
        "Event Robustness Score",
        "Filter Score",
        "Final Score",
        "Notes",
        "Permalink",
    ]
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"wrote {out_path}")
    for r in rows:
        print(f"{r['Name']}: {r['Analytic Robustness Score']}{r['Event Robustness Score']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
