"""Phase 2: assert on the real recorded Zircolite behavioural result against
splunk-detection-lab's real converted attack/benign JSON.

Reads reports/phase2_zircolite_stp_crosscheck.json, written by
scripts/phase2_zircolite_stp_crosscheck.py. Run that script first if
splunk-detection-lab's data or this project's Sigma-equivalent rules
changed.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "phase2_zircolite_stp_crosscheck.json"
ELIGIBILITY = ROOT / "reports" / "phase2_benign_eligibility.json"


def _load_report() -> dict:
    assert REPORT.exists(), (
        "reports/phase2_zircolite_stp_crosscheck.json is missing; run "
        "'python3 scripts/phase2_zircolite_stp_crosscheck.py' first"
    )
    return json.loads(REPORT.read_text())


def test_all_six_rules_present():
    r = _load_report()
    assert r["summary"]["rules_total"] == 6


def test_all_six_rules_fire_on_real_attack_data():
    """The true-positive coverage claim: every Sigma-equivalent rule has at
    least one real match against splunk-detection-lab's real converted
    attack captures.
    """
    r = _load_report()
    assert r["summary"]["rules_fired_on_attack"] == 6, (
        "expected all 6 rules to fire on real attack data; got %d. A rule "
        "that never fires on its own technique's attack data is broken."
        % r["summary"]["rules_fired_on_attack"]
    )
    for row in r["rules"]:
        assert row["zircolite_attack_hits"] > 0, (
            "%s recorded zero attack hits" % row["title"]
        )


def test_zero_rules_fire_on_benign_baseline():
    """The headline non-finding: on THIS corpus, no rule produced a false
    positive, at any STP score. See test_benign_eligibility_confirms_real_gap
    for why that is a corpus-composition fact, not a robustness claim.
    """
    r = _load_report()
    assert r["summary"]["rules_fired_on_benign"] == 0
    for row in r["rules"]:
        assert row["zircolite_benign_hits"] == 0, (
            "%s recorded %d benign hits; the headline finding text needs "
            "updating if this is no longer zero"
            % (row["title"], row["zircolite_benign_hits"])
        )


def test_stp_scores_are_attached_to_every_row():
    """Every rule in the Zircolite result must be traceable back to its
    published STP score; a missing mapping would silently drop a rule from
    the comparison instead of failing loud.
    """
    r = _load_report()
    for row in r["rules"]:
        assert row["stp_name"], "no STP name mapped for rule %s" % row["title"]
        assert row["stp_analytic_robustness_score"] in ("1", "2", "3", "4", "5"), (
            "%s has no valid STP Analytic Robustness Score: %r"
            % (row["title"], row["stp_analytic_robustness_score"])
        )


def test_benign_eligibility_confirms_real_gap():
    """Proves the zero-false-positive result is a corpus-composition fact:
    the benign corpus has real events of the right EventID types, but zero
    of them touch the specific processes/paths these rules key on.
    """
    assert ELIGIBILITY.exists(), (
        "reports/phase2_benign_eligibility.json missing; run "
        "'python3 scripts/phase2_benign_eligibility_check.py' first"
    )
    c = json.loads(ELIGIBILITY.read_text())
    assert c["eventid_1"] > 0, "benign corpus should contain real EventID 1 events"
    assert c["eventid_1_net_or_schtasks_image"] == 0, (
        "expected zero net.exe/net1.exe/schtasks.exe process creations in "
        "the benign baseline; found %d, which would change the Phase 2 "
        "headline" % c["eventid_1_net_or_schtasks_image"]
    )
