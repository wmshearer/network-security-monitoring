"""Tests for the rule-scoring join.

These exist because the join is where a silent error would be invisible in the
output: counts would still look plausible, just wrong. Every test here asserts on
a property that would produce a believable-but-false number if it broke.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.score import RuleResult, _attack_techniques, score  # noqa: E402


def zrec(rid, title, count, level="high", tags=None, author="A. Author"):
    """Build a Zircolite-shaped rule record."""
    return {
        "id": rid,
        "title": title,
        "count": count,
        "rule_level": level,
        "tags": tags or [],
        "author": author,
        "sigmafile": "rules/windows/%s.yml" % rid,
        "matches": [{"x": i} for i in range(count)],
    }


def test_counts_are_attributed_to_the_correct_class():
    run = score(
        malicious_records=[zrec("r1", "Rule One", 5)],
        benign_records=[zrec("r1", "Rule One", 3)],
        rules_loaded=1, malicious_events=100, benign_events=100,
    )
    assert len(run.results) == 1
    r = run.results[0]
    assert r.malicious_hits == 5
    assert r.benign_hits == 3


def test_rule_present_in_only_one_class_keeps_a_zero_on_the_other():
    """A rule that never touches benign data must read 0, not go missing.

    If absence were dropped rather than zeroed, the cleanest rules in the whole
    ruleset would silently vanish from the report.
    """
    run = score(
        malicious_records=[zrec("r1", "Only Malicious", 7)],
        benign_records=[],
        rules_loaded=1, malicious_events=10, benign_events=10,
    )
    assert run.results[0].malicious_hits == 7
    assert run.results[0].benign_hits == 0


def test_join_is_by_rule_id_not_title():
    """Two distinct rules sharing a title must stay separate.

    Sigma titles are neither unique nor stable. Joining on title would merge
    unrelated rules and inflate one of them.
    """
    run = score(
        malicious_records=[zrec("id-a", "Same Title", 2), zrec("id-b", "Same Title", 4)],
        benign_records=[],
        rules_loaded=2, malicious_events=10, benign_events=10,
    )
    assert len(run.results) == 2
    assert {r.malicious_hits for r in run.results} == {2, 4}


def test_precision_is_none_when_a_rule_never_fires():
    """0/0 must not be reported as 0.0.

    A silent rule and an always-wrong rule are different findings; collapsing
    both to 0.0 would rank them together.
    """
    r = RuleResult("id", "t", "high", "a", "f.yml", (), 0, 0)
    assert r.precision is None
    assert r.fired is False


def test_precision_computes_over_both_classes():
    r = RuleResult("id", "t", "high", "a", "f.yml", (), 3, 1)
    assert r.precision == pytest.approx(0.75)


def test_results_are_sorted_noisiest_first():
    run = score(
        malicious_records=[zrec("quiet", "Quiet", 1)],
        benign_records=[zrec("loud", "Loud", 900)],
        rules_loaded=2, malicious_events=10, benign_events=1000,
    )
    assert run.results[0].title == "Loud"


def test_attack_technique_extraction_keeps_techniques_and_drops_tactics():
    tags = ["attack.execution", "attack.t1059.001", "attack.T1086", "cve.2021-1234"]
    assert _attack_techniques(tags) == ("T1059.001", "T1086")


def test_attack_extraction_handles_missing_tags():
    assert _attack_techniques([]) == ()
    assert _attack_techniques(None) == ()


def test_summary_separates_clean_rules_from_noisy_ones():
    run = score(
        malicious_records=[zrec("clean", "Clean", 4), zrec("both", "Both", 2)],
        benign_records=[zrec("both", "Both", 6), zrec("fp", "FP Only", 9)],
        rules_loaded=10, malicious_events=50, benign_events=50,
    )
    s = run.summary()
    assert s["rules_fired"] == 3
    assert s["rules_silent"] == 7
    assert s["rules_malicious_only"] == 1     # only "clean"
    assert s["rules_touching_benign"] == 2    # "both" and "fp"


def test_count_falls_back_to_match_length_when_count_absent():
    rec = zrec("r", "R", 3)
    del rec["count"]
    run = score([rec], [], rules_loaded=1, malicious_events=5, benign_events=5)
    assert run.results[0].malicious_hits == 3
