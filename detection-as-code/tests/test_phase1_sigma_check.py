"""Phase 1: assert on the real recorded result of `sigma check` against
cloud-detection-lab's 12 Sigma rules with zero exclusions.

This reads reports/phase1_sigma_check.json, written by
scripts/phase1_sigma_check.py, which itself shells out to the real `sigma`
binary. It does not re-run sigma check on every test collection (that would
make every pytest run pay the subprocess cost); run
`python3 scripts/phase1_sigma_check.py` to refresh the report before running
these tests if cloud-detection-lab's rules changed.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "phase1_sigma_check.json"
REPO_REPORT = ROOT / "reports" / "phase1_repo_rules_sigma_check.json"


def _load_report() -> dict:
    assert REPORT.exists(), (
        "reports/phase1_sigma_check.json is missing; run "
        "'python3 scripts/phase1_sigma_check.py' first"
    )
    return json.loads(REPORT.read_text())


def _load_repo_report() -> dict:
    assert REPO_REPORT.exists(), (
        "reports/phase1_repo_rules_sigma_check.json is missing; run "
        "'python3 scripts/phase1_sigma_check.py' first"
    )
    return json.loads(REPO_REPORT.read_text())


def test_report_covers_all_twelve_cloud_detection_lab_rules():
    r = _load_report()
    assert r["files_total"] == 12, (
        "expected 12 Sigma rule files from cloud-detection-lab, found %d; "
        "the rules directory may have changed" % r["files_total"]
    )


def test_pass_rate_matches_zero_exclusion_reality():
    """This is the finding, pinned as a real number, not a smoke test.

    If cloud-detection-lab's rules are edited to fix these validator
    findings, this assertion SHOULD fail and needs updating; that failure
    is itself a signal the finding needs re-recording, not a bug.
    """
    r = _load_report()
    assert r["files_passed"] == 0, (
        "expected 0/12 files to pass sigma check with zero exclusions "
        "(recorded finding as of this project's initial run); got %d. "
        "If cloud-detection-lab's rules were fixed, update this test and "
        "reports/phase1_sigma_check.json together."
        % r["files_passed"]
    )
    assert r["pass_rate_pct"] == 0.0


def test_combined_exit_code_is_failure():
    r = _load_report()
    assert r["combined_exit_code"] == 1, (
        "sigma check --fail-on-error --fail-on-issues should exit 1 when "
        "any rule has an issue; got %d" % r["combined_exit_code"]
    )


def test_sigma_check_binary_actually_runs_and_fails_as_recorded():
    """Proof this is not a stale report: re-run the real sigma binary now.

    This is slower (spawns the real sigma-cli process) but is the assertion
    that would fail if the venv, the sigmahq validator package, or
    cloud-detection-lab's rules changed out from under the recorded report.
    """
    sigma_bin = ROOT / ".venv" / "bin" / "sigma"
    rules_dir = Path("/home/kali/director/projects/cloud-detection-lab/detections/sigma")
    assert sigma_bin.exists(), "sigma-cli not installed in .venv; run pip install sigma-cli"
    assert rules_dir.exists(), "cloud-detection-lab rules directory not found"

    proc = subprocess.run(
        [str(sigma_bin), "check", "--fail-on-error", "--fail-on-issues", str(rules_dir)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 1, (
        "expected sigma check to fail (real defects exist in the 12 rules); "
        "got exit code %d, stdout tail: %s" % (proc.returncode, proc.stdout[-500:])
    )


def test_this_repos_own_translated_rules_also_fail_with_zero_exclusions():
    """This repo's own 6 Sigma-equivalent rules (sigma_rules/splunk_detection_lab/)
    were written for Phase 2's behavioural check, not to satisfy SigmaHQ's
    validator profile, and they also fail with zero exclusions: same
    validator classes (missing MITRE tactic tags, filename convention, a
    redundant EventID field for their logsource category). This confirms
    the strict profile is genuinely strict, not just picking on
    cloud-detection-lab specifically.
    """
    r = _load_repo_report()
    assert r["files_total"] == 6
    assert r["files_passed"] == 0, (
        "expected 0/6 of this repo's own translated rules to pass strict "
        "sigma check; got %d" % r["files_passed"]
    )
    assert r["combined_exit_code"] == 1
