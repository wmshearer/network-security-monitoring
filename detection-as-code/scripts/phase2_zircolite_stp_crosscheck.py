#!/usr/bin/env python3
"""Phase 2: does an independent behavioural tool agree with the published
STP robustness scores?

splunk-detection-lab scored its 6 SPL detections against MITRE's Summiting
the Pyramid (STP) framework by hand
(/home/kali/director/projects/splunk-detection-lab/evidence/robustness/stp_scores.csv):
D1=4, D2=1, D3=1, D4=1, D5=2, D6=2. Those scores are about EVASION
robustness (how much of an adversary's freedom to change the observable
would break the rule), reasoned from the rule's logic, not measured from
running it against traffic.

This script asks a different, empirical question with Zircolite: does each
detection's Sigma-equivalent (sigma_rules/splunk_detection_lab/*.yml,
translated field-for-field from the original SPL, see each file's own
description) fire on splunk-detection-lab's real converted attack JSON
(true positive) and stay silent on its real converted benign JSON (false
positive check)? That is a DIFFERENT measurement: STP scores conceptual
evadability; Zircolite here measures observed hit/miss on one fixed corpus.
Agreement or disagreement between the two is reported as found, not forced.

splunk-detection-lab is read-only input. Nothing in it is modified.

Zircolite is vendored at vendor/Zircolite (git clone, not pip-installed:
it is not on PyPI and its flat layout is rejected by setuptools when
installed from a clone). It converts the Sigma rules in
sigma_rules/splunk_detection_lab/ at run time and executes them against the
JSON-lines event files, same pattern already proven working in
/home/kali/director/projects/detection-rule-lab.

cloud-detection-lab is NOT covered here. It has no local flat-file event
data: its Phase 1 data lives only in a live local Splunk index, so there is
nothing offline for Zircolite to replay against. That limit is structural,
not a shortcut taken in this script.
"""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ZIRCOLITE_PY = ROOT / "vendor" / "Zircolite" / "zircolite.py"
RULES_DIR = ROOT / "sigma_rules" / "splunk_detection_lab"
ATTACK_DIR = Path("/home/kali/director/projects/splunk-detection-lab/data/converted/attack")
BENIGN_DIR = Path("/home/kali/director/projects/splunk-detection-lab/data/converted/benign")
STP_CSV = Path("/home/kali/director/projects/splunk-detection-lab/evidence/robustness/stp_scores.csv")
REPORTS = ROOT / "reports"
DATA_OUT = ROOT / "data" / "out"

# Maps this project's Sigma rule id -> the STP scores.csv row Name, since
# the two do not share an identifier. Set by hand from reading both files.
RULE_ID_TO_STP_NAME = {
    "8f1a2b3c-0001-4d1e-9a11-1a2b3c4d5e01": "D1_registry_run_key_setvalue",
    "8f1a2b3c-0002-4d1e-9a11-1a2b3c4d5e02": "D2_schtasks_encoded_powershell",
    "8f1a2b3c-0003-4d1e-9a11-1a2b3c4d5e03": "D3_net_localgroup_administrators",
    "8f1a2b3c-0004-4d1e-9a11-1a2b3c4d5e04": "D4_net_user_enumeration",
    "8f1a2b3c-0005-4d1e-9a11-1a2b3c4d5e05": "D5_process_access_audiodg",
    "8f1a2b3c-0006-4d1e-9a11-1a2b3c4d5e06": "D6_powershell_spawns_recon_tool",
}


def run_zircolite(events_dir: Path, out_path: Path) -> tuple[list[dict], str]:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()
    cmd = [
        sys.executable, str(ZIRCOLITE_PY),
        "--events", str(events_dir),
        "--json-input",
        "--ruleset", str(RULES_DIR),
        "-o", str(out_path),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
    if not out_path.exists():
        raise RuntimeError(
            "Zircolite produced no output.\ncmd: %s\nstdout:\n%s\nstderr:\n%s"
            % (" ".join(cmd), proc.stdout[-3000:], proc.stderr[-3000:])
        )
    with out_path.open() as fh:
        data = json.load(fh)
    return data, proc.stdout


def load_stp_scores() -> dict[str, dict]:
    out = {}
    with STP_CSV.open() as fh:
        for row in csv.DictReader(fh):
            out[row["Name"]] = row
    return out


def main() -> int:
    rule_files = sorted(RULES_DIR.glob("*.yml"))
    print("Sigma-equivalent rules under test: %d" % len(rule_files))
    for f in rule_files:
        print("  - %s" % f.name)

    print("\n[1/2] Running Zircolite against real ATTACK data: %s" % ATTACK_DIR)
    attack_records, attack_stdout = run_zircolite(ATTACK_DIR, DATA_OUT / "zircolite_attack_raw.json")
    print(attack_stdout[-1500:])

    print("\n[2/2] Running Zircolite against real BENIGN data: %s" % BENIGN_DIR)
    benign_records, benign_stdout = run_zircolite(BENIGN_DIR, DATA_OUT / "zircolite_benign_raw.json")
    print(benign_stdout[-1500:])

    # Join by rule id, summing the `count` field across all per-file result
    # blocks Zircolite emits (one block per rule per source file it matched
    # in, when run over a directory of separate files).
    by_id: dict[str, dict] = {}

    def absorb(records: list[dict], key: str) -> None:
        for rec in records:
            rid = rec.get("id")
            slot = by_id.setdefault(rid, {
                "title": rec.get("title", ""),
                "level": rec.get("rule_level", ""),
                "attack_hits": 0,
                "benign_hits": 0,
            })
            slot[key] += int(rec.get("count") or len(rec.get("matches") or []))

    absorb(attack_records, "attack_hits")
    absorb(benign_records, "benign_hits")

    # Every rule file should appear even if it fired zero times in a run;
    # Zircolite only emits a record for rules that matched at least once,
    # so rules absent from both runs need to be added explicitly, or a
    # silent rule would be invisible in the report instead of scored zero.
    for f in rule_files:
        import yaml
        doc = next(yaml.safe_load_all(f.read_text()))
        rid = doc.get("id")
        by_id.setdefault(rid, {
            "title": doc.get("title", ""),
            "level": doc.get("level", ""),
            "attack_hits": 0,
            "benign_hits": 0,
        })

    stp = load_stp_scores()

    rows = []
    for rid, v in by_id.items():
        stp_name = RULE_ID_TO_STP_NAME.get(rid, "")
        stp_row = stp.get(stp_name, {})
        stp_score = stp_row.get("Analytic Robustness Score", "")
        rows.append({
            "rule_id": rid,
            "title": v["title"],
            "level": v["level"],
            "stp_name": stp_name,
            "stp_analytic_robustness_score": stp_score,
            "zircolite_attack_hits": v["attack_hits"],
            "zircolite_benign_hits": v["benign_hits"],
            "fired_on_attack": v["attack_hits"] > 0,
            "fired_on_benign": v["benign_hits"] > 0,
        })

    # Sort by STP score ascending (weakest-scored first), the order the
    # comparison is meant to be read in.
    rows.sort(key=lambda r: (r["stp_analytic_robustness_score"] or "9", r["title"]))

    print("\n" + "=" * 100)
    print("PHASE 2 RESULT: STP robustness score vs Zircolite behavioural result")
    print("=" * 100)
    print("%-45s %6s %14s %14s %10s" % ("RULE", "STP", "ATTACK HITS", "BENIGN HITS", "FALSE POS?"))
    for r in rows:
        print("%-45s %6s %14d %14d %10s" % (
            r["title"][:45], r["stp_analytic_robustness_score"],
            r["zircolite_attack_hits"], r["zircolite_benign_hits"],
            "YES" if r["fired_on_benign"] else "no",
        ))

    total_attack_events = sum(1 for _ in ATTACK_DIR.glob("*.json"))
    total_benign_files = sum(1 for _ in BENIGN_DIR.glob("*.json"))

    payload = {
        "attack_data_dir": str(ATTACK_DIR),
        "attack_files": total_attack_events,
        "benign_data_dir": str(BENIGN_DIR),
        "benign_files": total_benign_files,
        "rules": rows,
        "summary": {
            "rules_total": len(rows),
            "rules_fired_on_attack": sum(1 for r in rows if r["fired_on_attack"]),
            "rules_fired_on_benign": sum(1 for r in rows if r["fired_on_benign"]),
        },
    }
    REPORTS.mkdir(parents=True, exist_ok=True)
    out_path = REPORTS / "phase2_zircolite_stp_crosscheck.json"
    out_path.write_text(json.dumps(payload, indent=2))
    print("\nwrote %s" % out_path)

    print("\nHEADLINE: %d/%d rules fired on real attack data (true-positive "
          "coverage). %d/%d rules fired on the real benign baseline "
          "(false-positive count)." % (
              payload["summary"]["rules_fired_on_attack"], len(rows),
              payload["summary"]["rules_fired_on_benign"], len(rows),
          ))
    if payload["summary"]["rules_fired_on_benign"] == 0:
        print("\nEvery rule, including the STP-weakest (score 1: D2/D3/D4), stayed "
              "silent on the benign baseline. This does NOT confirm those rules are "
              "robust: it means this specific benign corpus (one Windows Server 2022 "
              "host) never ran net.exe, net1.exe, or schtasks.exe, and never wrote a "
              "registry Run-key value or touched AUDIODG.EXE, in the captured window. "
              "See reports/phase2_findings.md for the eligibility check that confirms "
              "this is a corpus-composition fact, not a Zircolite/field-mapping bug.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
