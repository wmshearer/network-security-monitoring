"""Tests for src/lint_detection.py.

Uses only the standard library (unittest), matching the linter itself.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from src.lint_detection import (  # noqa: E402
    find_rule_files,
    lint_rule,
    main,
    parse_rule_file,
)

EXAMPLES = ROOT / "examples"


class TestParseRuleFile(unittest.TestCase):
    def test_parses_scalars_and_lists(self):
        fields = parse_rule_file(EXAMPLES / "experimental_new_login_anomaly.yml")
        self.assertEqual(fields["status"], "experimental")
        self.assertEqual(fields["title"], "Impossible Travel Login Within Short Window")
        self.assertIsInstance(fields["falsepositives"], list)
        self.assertEqual(len(fields["falsepositives"]), 2)

    def test_bare_scalar_falsepositives_stays_a_string(self):
        fields = parse_rule_file(EXAMPLES / "BAD_stable_missing_validation.yml")
        self.assertEqual(fields["falsepositives"], "unknown")
        self.assertNotIsInstance(fields["falsepositives"], list)

    def test_comments_and_blank_lines_ignored(self):
        fields = parse_rule_file(EXAMPLES / "stable_llm_persona_injection.yml")
        # The file has leading '#' comment lines; they must not become fields.
        self.assertNotIn("#", fields)
        self.assertIn("title", fields)


class TestLintRulePassing(unittest.TestCase):
    def test_experimental_rule_passes(self):
        fields = parse_rule_file(EXAMPLES / "experimental_new_login_anomaly.yml")
        self.assertEqual(lint_rule(fields), [])

    def test_well_formed_stable_rule_passes(self):
        fields = parse_rule_file(EXAMPLES / "stable_llm_persona_injection.yml")
        self.assertEqual(lint_rule(fields), [])

    def test_deprecated_rule_with_replaced_by_passes(self):
        fields = parse_rule_file(EXAMPLES / "deprecated_old_powershell_encoded_cmd.yml")
        self.assertEqual(lint_rule(fields), [])


class TestLintRuleFailing(unittest.TestCase):
    def test_bad_stable_rule_is_rejected(self):
        fields = parse_rule_file(EXAMPLES / "BAD_stable_missing_validation.yml")
        problems = lint_rule(fields)
        self.assertNotEqual(problems, [], "the bad-on-purpose example must fail the linter")
        joined = " ".join(problems)
        self.assertIn("validation_steps", joined)
        self.assertIn("falsepositives", joined)

    def test_missing_mandatory_field_is_rejected(self):
        fields = {
            "title": "No goal field",
            "id": "x",
            "status": "experimental",
            "logsource": "test",
            "detection": "test",
            "falsepositives": ["something"],
            "level": "low",
        }
        problems = lint_rule(fields)
        self.assertTrue(any("goal" in p for p in problems))

    def test_invalid_status_value_is_rejected(self):
        fields = {
            "title": "Bad status",
            "id": "x",
            "status": "in-review",  # not one of the five Sigma values
            "goal": "g",
            "logsource": "l",
            "detection": "d",
            "falsepositives": ["fp"],
            "level": "low",
        }
        problems = lint_rule(fields)
        self.assertTrue(any("not one of the five Sigma values" in p for p in problems))

    def test_deprecated_without_replaced_by_or_retired_is_rejected(self):
        fields = {
            "title": "Deprecated with nothing",
            "id": "x",
            "status": "deprecated",
            "goal": "g",
            "logsource": "l",
            "detection": "d",
            "falsepositives": ["fp"],
            "level": "low",
        }
        problems = lint_rule(fields)
        self.assertTrue(any("replaced_by" in p for p in problems))

    def test_deprecated_with_both_replaced_by_and_retired_is_rejected(self):
        fields = {
            "title": "Deprecated with both",
            "id": "x",
            "status": "deprecated",
            "goal": "g",
            "logsource": "l",
            "detection": "d",
            "falsepositives": ["fp"],
            "level": "low",
            "replaced_by": "other-id",
            "retired": "true",
            "retired_reason": "threat gone",
        }
        problems = lint_rule(fields)
        self.assertTrue(any("both replaced_by and retired" in p for p in problems))

    def test_retired_without_reason_is_rejected(self):
        fields = {
            "title": "Retired no reason",
            "id": "x",
            "status": "deprecated",
            "goal": "g",
            "logsource": "l",
            "detection": "d",
            "falsepositives": ["fp"],
            "level": "low",
            "retired": "true",
        }
        problems = lint_rule(fields)
        self.assertTrue(any("retired_reason" in p for p in problems))

    def test_muted_without_reason_is_rejected(self):
        fields = {
            "title": "Muted no reason",
            "id": "x",
            "status": "stable",
            "goal": "g",
            "logsource": "l",
            "detection": "d",
            "falsepositives": ["fp"],
            "level": "low",
            "validation_steps": ["step"],
            "muted": "true",
        }
        problems = lint_rule(fields)
        self.assertTrue(any("muted_reason" in p for p in problems))

    def test_muted_and_deprecated_together_is_rejected(self):
        fields = {
            "title": "Muted and deprecated",
            "id": "x",
            "status": "deprecated",
            "goal": "g",
            "logsource": "l",
            "detection": "d",
            "falsepositives": ["fp"],
            "level": "low",
            "replaced_by": "other-id",
            "muted": "true",
            "muted_reason": "noisy",
        }
        problems = lint_rule(fields)
        self.assertTrue(any("both muted: true and status: deprecated" in p for p in problems))


class TestFindRuleFiles(unittest.TestCase):
    def test_finds_all_examples_in_directory(self):
        files = find_rule_files([str(EXAMPLES)])
        names = {f.name for f in files}
        self.assertIn("experimental_new_login_anomaly.yml", names)
        self.assertIn("BAD_stable_missing_validation.yml", names)
        self.assertGreaterEqual(len(files), 4)

    def test_single_file_target(self):
        target = str(EXAMPLES / "experimental_new_login_anomaly.yml")
        files = find_rule_files([target])
        self.assertEqual(len(files), 1)


class TestMainExitCode(unittest.TestCase):
    def test_main_returns_1_when_any_rule_fails(self):
        rc = main([str(EXAMPLES)])
        self.assertEqual(rc, 1)

    def test_main_returns_0_when_all_pass(self):
        good_dir = ROOT / "tests" / "_all_good_fixture"
        good_dir.mkdir(exist_ok=True)
        try:
            fixture = good_dir / "ok.yml"
            fixture.write_text(
                "title: ok\n"
                "id: 1\n"
                "status: experimental\n"
                "goal: g\n"
                "logsource: l\n"
                "detection: d\n"
                "falsepositives:\n"
                "  - fp1\n"
                "level: low\n"
            )
            rc = main([str(good_dir)])
            self.assertEqual(rc, 0)
        finally:
            for f in good_dir.glob("*.yml"):
                f.unlink()
            good_dir.rmdir()

    def test_main_with_no_args_returns_1(self):
        rc = main([])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
