#!/usr/bin/env python3
"""Phase 1: run SigmaHQ's own strict semantic validator against
cloud-detection-lab's 12 Sigma rules, with zero exclusions.

This is `sigma check --fail-on-error --fail-on-issues`, the same command
SigmaHQ itself runs in its `sigma-test.yml` `sigma-check` job (see
/home/kali/director/projects/wshearer-site/research/detection-as-code-ci.md,
lines 105-115). SigmaHQ's own production config excludes a long list of
validators and per-rule-id exceptions even against its own 3,000+ rule
corpus. This script runs with NO exclusions, against 12 hand-written rules,
which is a fair strictness test precisely because it gives the ruleset no
help.

cloud-detection-lab is read-only input. Nothing in it is modified.

Output: reports/phase1_sigma_check.json (machine-readable) and stdout summary.
Exit code matches `sigma check`'s own exit code (0 pass, 1 fail).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SIGMA_BIN = ROOT / ".venv" / "bin" / "sigma"
REPORTS = ROOT / "reports"


def run_check(rules_dir: Path) -> tuple[int, str, str]:
    cmd = [
        str(SIGMA_BIN), "check",
        "--fail-on-error", "--fail-on-issues",
        str(rules_dir),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def run_check_per_file(rules_dir: Path) -> dict[str, dict]:
    """Run `sigma check` once per rule file so a per-file pass/fail count is
    real, not inferred from parsing the combined issue list.
    """
    per_file: dict[str, dict] = {}
    for path in sorted(rules_dir.glob("*.yml")):
        cmd = [
            str(SIGMA_BIN), "check",
            "--fail-on-error", "--fail-on-issues",
            str(path),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        per_file[path.name] = {
            "exit_code": proc.returncode,
            "passed": proc.returncode == 0,
            "stdout": proc.stdout,
        }
    return per_file


def check_one(label: str, rules_dir: Path, out_name: str) -> dict:
    print("Running: sigma check --fail-on-error --fail-on-issues <%s>" % label)
    print("Rules directory: %s" % rules_dir)
    print()

    combined_rc, combined_out, combined_err = run_check(rules_dir)
    print(combined_out)
    if combined_err:
        print(combined_err, file=sys.stderr)

    print("\nRunning per-file to get an honest per-rule pass count...")
    per_file = run_check_per_file(rules_dir)
    passed = [name for name, r in per_file.items() if r["passed"]]
    failed = [name for name, r in per_file.items() if not r["passed"]]

    total = len(per_file)
    pct = 100.0 * len(passed) / total if total else 0.0

    print("\n" + "=" * 68)
    print("RESULT (%s): %d/%d files pass sigma check with zero exclusions (%.1f%%)"
          % (label, len(passed), total, pct))
    print("=" * 68)
    for name in sorted(per_file):
        print("  %s  %s" % ("PASS" if per_file[name]["passed"] else "FAIL", name))

    REPORTS.mkdir(parents=True, exist_ok=True)
    payload = {
        "label": label,
        "command": "sigma check --fail-on-error --fail-on-issues <rules>",
        "rules_dir": str(rules_dir),
        "combined_exit_code": combined_rc,
        "combined_stdout": combined_out,
        "files_total": total,
        "files_passed": len(passed),
        "files_failed": len(failed),
        "pass_rate_pct": round(pct, 1),
        "passed_files": passed,
        "failed_files": failed,
        "per_file": per_file,
    }
    out_path = REPORTS / out_name
    out_path.write_text(json.dumps(payload, indent=2))
    print("\nwrote %s\n" % out_path)
    return payload


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-rules-only", action="store_true",
                     help="only check sigma_rules/splunk_detection_lab (this repo's own rules)")
    args = ap.parse_args()

    repo_rules = ROOT / "sigma_rules" / "splunk_detection_lab"
    repo_result = check_one(
        "this repo's translated rules (sigma_rules/splunk_detection_lab)",
        repo_rules, "phase1_repo_rules_sigma_check.json",
    )

    if args.repo_rules_only:
        return repo_result["combined_exit_code"]

    cloud_rules = Path("/home/kali/director/projects/cloud-detection-lab/detections/sigma")
    cloud_result = check_one(
        "cloud-detection-lab (headline finding)",
        cloud_rules, "phase1_sigma_check.json",
    )

    return cloud_result["combined_exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
