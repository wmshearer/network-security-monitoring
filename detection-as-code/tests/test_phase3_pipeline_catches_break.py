"""Phase 3: prove the pipeline actually catches a broken rule.

This test copies D2 (schtasks_encoded_powershell) from
sigma_rules/splunk_detection_lab/ into a scratch directory, breaks its
CommandLine field name to a nonexistent field (CommandlineArgs), runs the
real Zircolite --test-rules pipeline against it, asserts it fails, restores
the rule, and asserts the pipeline passes again. Nothing in
sigma_rules/splunk_detection_lab/ (the real rules used by Phase 2) is
touched; the break happens on a copy in a tmp_path fixture.

Also asserts on `sigma check`, because the real finding from running this
live was that the strict SigmaHQ validator DOES catch this specific defect
class (wrong/nonexistent field name against the known process_creation
taxonomy) when run with --fail-on-issues, which corrects an assumption in
this project's own research brief (see README "Anything that contradicted
the research").
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ZIRCOLITE_PY = ROOT / "vendor" / "Zircolite" / "zircolite.py"
SIGMA_BIN = ROOT / ".venv" / "bin" / "sigma"
FIXTURE = ROOT / "tests" / "rule_tests.json"
GOOD_RULES = ROOT / "sigma_rules" / "splunk_detection_lab"

BROKEN_FIELD_MARKER = "CommandlineArgs"


def _run_test_rules(rules_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(ZIRCOLITE_PY), "--ruleset", str(rules_dir),
         "--test-rules", str(FIXTURE)],
        capture_output=True, text=True, cwd=str(ROOT),
    )


def _run_sigma_check_strict(rule_path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(SIGMA_BIN), "check", "--fail-on-error", "--fail-on-issues", str(rule_path)],
        capture_output=True, text=True,
    )


def test_pipeline_before_break_passes(tmp_path):
    scratch = tmp_path / "rules_copy"
    scratch.mkdir()
    for f in GOOD_RULES.glob("*.yml"):
        (scratch / f.name).write_text(f.read_text())

    proc = _run_test_rules(scratch)
    assert proc.returncode == 0, "unmodified copy should pass: %s" % proc.stdout[-1000:]
    assert "Passed: 6  Failed: 0" in proc.stdout


def test_pipeline_catches_deliberately_broken_rule(tmp_path):
    scratch = tmp_path / "rules_copy"
    scratch.mkdir()
    for f in GOOD_RULES.glob("*.yml"):
        (scratch / f.name).write_text(f.read_text())

    broken_path = scratch / "d2_schtasks_encoded_powershell.yml"
    original = broken_path.read_text()
    assert "CommandLine|contains|all:" in original, (
        "test assumption about D2's rule shape is stale; update the break"
    )
    broken = original.replace(
        "CommandLine|contains|all:", "%s|contains|all:" % BROKEN_FIELD_MARKER
    )
    assert broken != original
    broken_path.write_text(broken)

    zircolite_proc = _run_test_rules(scratch)
    assert zircolite_proc.returncode == 1, (
        "expected the broken rule to fail --test-rules; got exit %d\n%s"
        % (zircolite_proc.returncode, zircolite_proc.stdout[-1500:])
    )
    assert "Passed: 5  Failed: 1" in zircolite_proc.stdout, (
        "expected exactly 1 rule to fail: %s" % zircolite_proc.stdout[-1500:]
    )

    sigma_proc = _run_sigma_check_strict(broken_path)
    assert sigma_proc.returncode == 1, (
        "expected sigma check --fail-on-issues to also catch the invalid "
        "field name; got exit %d\n%s"
        % (sigma_proc.returncode, sigma_proc.stdout[-1500:])
    )
    assert "SigmahqInvalidFieldnameIssue" in sigma_proc.stdout, (
        "expected the invalid-fieldname validator to fire: %s"
        % sigma_proc.stdout[-1500:]
    )


def test_pipeline_passes_again_after_restore(tmp_path):
    scratch = tmp_path / "rules_copy"
    scratch.mkdir()
    for f in GOOD_RULES.glob("*.yml"):
        (scratch / f.name).write_text(f.read_text())

    broken_path = scratch / "d2_schtasks_encoded_powershell.yml"
    original = broken_path.read_text()
    broken_path.write_text(original.replace(
        "CommandLine|contains|all:", "%s|contains|all:" % BROKEN_FIELD_MARKER
    ))
    assert _run_test_rules(scratch).returncode == 1

    # restore
    broken_path.write_text(original)
    proc = _run_test_rules(scratch)
    assert proc.returncode == 0, (
        "expected the pipeline to pass again after restoring the rule; "
        "got exit %d\n%s" % (proc.returncode, proc.stdout[-1500:])
    )
    assert "Passed: 6  Failed: 0" in proc.stdout
