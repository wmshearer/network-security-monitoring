"""Runs Zircolite's own `--test-rules` CI mode for real, every test run.

This is the fast regression layer: no full attack/benign corpus replay, just
the true_positive/true_negative fixture in tests/rule_tests.json (every
event in it real, pulled from splunk-detection-lab's converted data by
scripts/build_rule_test_fixture.py). Exercises the exact command a GitHub
Actions job would run (see .github/workflows/detection-ci.yml).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ZIRCOLITE_PY = ROOT / "vendor" / "Zircolite" / "zircolite.py"
RULES_DIR = ROOT / "sigma_rules" / "splunk_detection_lab"
FIXTURE = ROOT / "tests" / "rule_tests.json"


def _run_test_rules(rules_dir: Path) -> subprocess.CompletedProcess:
    assert ZIRCOLITE_PY.exists(), (
        "vendor/Zircolite is not present; clone it with "
        "'git clone https://github.com/wagga40/Zircolite.git vendor/Zircolite'"
    )
    return subprocess.run(
        [sys.executable, str(ZIRCOLITE_PY),
         "--ruleset", str(rules_dir),
         "--test-rules", str(FIXTURE)],
        capture_output=True, text=True, cwd=str(ROOT),
    )


def test_fixture_file_exists_and_covers_all_six_rules():
    import json
    assert FIXTURE.exists(), (
        "tests/rule_tests.json missing; run "
        "'python3 scripts/build_rule_test_fixture.py' first"
    )
    cases = json.loads(FIXTURE.read_text())
    assert len(cases) == 6
    for case in cases:
        assert case["true_positive"], "%s has no true_positive event" % case["title"]
        assert case["true_negative"], "%s has no true_negative event" % case["title"]


def test_zircolite_test_rules_passes_against_correct_rules():
    """This is the real pipeline gate: exit 0 means every rule matched its
    true_positive event and stayed silent on its true_negative event.
    """
    proc = _run_test_rules(RULES_DIR)
    assert proc.returncode == 0, (
        "expected --test-rules to pass against the correct rules; "
        "got exit %d\nstdout:\n%s\nstderr:\n%s"
        % (proc.returncode, proc.stdout[-2000:], proc.stderr[-1000:])
    )
    assert "Passed: 6  Failed: 0" in proc.stdout, (
        "expected all 6 rules to pass; stdout:\n%s" % proc.stdout[-2000:]
    )
