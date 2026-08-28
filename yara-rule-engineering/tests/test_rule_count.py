"""
Cross-checks scripts/rule_count.py's structural rule-declaration counter
against yara-python's authoritative len(list(yara.compile(...))) on every
file that DOES compile under yara-python. The two must agree everywhere in
the cloned rulesets, or the counter used for yara-x's rule counts (which has
no native rule-count API in 1.20.0) is not trustworthy.
"""
import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR / "scripts"))

from conftest import RULESETS_DIR, require_ruleset_cloned  # noqa: E402
from rule_count import count_rule_declarations  # noqa: E402


def test_maldoc_apt19_regression_file_counts_three_rules():
    """The specific file that exposed two real bugs in the counter (see
    scripts/rule_count.py docstring): a backslash-heavy string, then a
    regex pattern literal containing an escaped quote. Locks the fix in."""
    require_ruleset_cloned("yara-rules")
    path = RULESETS_DIR / "yara-rules" / "maldocs" / "Maldoc_APT19_CVE-2017-0199.yar"
    if not path.exists():
        pytest.skip("regression file not present in cloned ruleset")
    assert count_rule_declarations(path.read_text()) == 3


def test_rule_count_matches_yara_python_on_all_compiled_files(compile_results_yara_python):
    yara = pytest.importorskip("yara")
    mismatches = []
    checked = 0
    for ruleset_name, result in compile_results_yara_python.items():
        for f in result.get("compiled_files", []):
            path = RULESETS_DIR / f["path"]
            if not path.exists():
                continue
            src = path.read_text(errors="replace")
            n = count_rule_declarations(src)
            checked += 1
            if n != f["rule_count"]:
                mismatches.append((f["path"], n, f["rule_count"]))
    if checked == 0:
        pytest.skip("no cloned+compiled rule files available to check")
    assert mismatches == [], f"{len(mismatches)} of {checked} files disagree with yara-python's rule count"
