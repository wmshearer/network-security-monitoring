"""
Pins the Q3 compile-portability numbers: how many rule files/rules compile
under yara-python vs yara-x, and the specific failure-category counts cited
in FINDINGS.md.
"""
import re
from collections import Counter


def test_yara_rules_compile_counts_yara_python(compile_results_yara_python):
    r = compile_results_yara_python["yara-rules"]
    assert r["files_total"] == 444
    assert r["files_compiled"] == 426
    assert r["files_failed"] == 18
    assert r["rules_compiled_total"] == 12630


def test_yara_rules_compile_counts_yara_x(compile_results_yara_x):
    r = compile_results_yara_x["yara-rules"]
    assert r["files_total"] == 444
    assert r["files_compiled"] == 433
    assert r["files_failed"] == 11


def test_reversinglabs_blocklist_compiles_only_under_yara_x(compile_results_yara_python, compile_results_yara_x):
    py_failed = {f["path"] for f in compile_results_yara_python["reversinglabs"]["failed_files"]}
    x_compiled = {f["path"] for f in compile_results_yara_x["reversinglabs"]["compiled_files"]}
    target = "reversinglabs/yara/certificate/blocklist.yara"
    assert target in py_failed
    assert target in x_compiled


def test_reversinglabs_blocklist_failure_is_number_of_signatures(compile_results_yara_python):
    failed = {f["path"]: f["error"] for f in compile_results_yara_python["reversinglabs"]["failed_files"]}
    target = "reversinglabs/yara/certificate/blocklist.yara"
    assert target in failed
    assert "number_of_signatures" in failed[target]


def test_yara_python_failure_categories(compile_results_yara_python):
    """85 of 144 total yara-python failures across all rulesets are the
    single 'invalid field name imphash' category (pe module used without
    import). Locks in the category breakdown, not just the total. The 144
    total counts yara-rules AND yara-rules-official-index separately (they
    share the same 18 broken files, since excluding utils/mobile_malware
    does not touch any of them), which is why this is not simply "18 x 4
    rulesets" -- it is the real sum across all five compiled ruleset
    variants recorded in evidence/02_compile_results_yara_python.json."""
    cat = Counter()
    total = 0
    for result in compile_results_yara_python.values():
        for f in result.get("failed_files", []):
            total += 1
            m = re.search(r'invalid field name "(\w+)"', f["error"])
            if m:
                cat[f"field:{m.group(1)}"] += 1
    assert total == 144
    assert cat["field:imphash"] == 85


def test_yara_x_requires_declared_external_variables(compile_results_yara_x):
    """yara-x rejects filename/filepath/extension as undeclared identifiers
    where yara-python treats them as external variables that compile fine
    without a value (and only matter at scan time)."""
    found_filename_or_filepath_error = False
    for result in compile_results_yara_x.values():
        for f in result.get("failed_files", []):
            if "unknown identifier `filepath`" in f["error"] or "unknown identifier `filename`" in f["error"]:
                found_filename_or_filepath_error = True
    assert found_filename_or_filepath_error


def test_protections_artifacts_compiles_cleanly_in_both_engines(compile_results_yara_python, compile_results_yara_x):
    assert compile_results_yara_python["protections-artifacts"]["files_failed"] == 0
    assert compile_results_yara_x["protections-artifacts"]["files_failed"] == 0
