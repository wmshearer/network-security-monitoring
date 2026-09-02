"""Pin the coverage findings and the assumptions behind them.

One test here exists because of a mistake I made while writing this analysis.

38 cloud rules carry no technique-level ATT&CK tag. Looking at the first one, it
was tagged `attack.stealth`, and I was ready to report that as a malformed tag,
since "stealth" was not a tactic name I recognised. Checking the tactic list in
the v19.2 bundle before writing it down showed `stealth` IS a current tactic.
The matrix changed; the rule was fine; my expectation was stale.

So `test_stealth_is_a_real_tactic` is not testing the code. It is pinning the
correction, so that nobody (including me, later) re-reports a valid tag as a
defect.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from coverage import (  # noqa: E402
    CLOUD_PLATFORMS,
    analyse,
    load_cloud_techniques,
    parent_of,
    parse_rule_tags,
)

STIX = ROOT / "data" / "enterprise-attack.json"


@pytest.fixture(scope="module")
def result() -> dict:
    return analyse()


def test_attack_bundle_is_the_expected_version(result):
    """If the bundle is refreshed, every number on the page moves. Pinning the
    version means a silent data change fails here rather than quietly
    invalidating the write-up."""
    bundle = json.loads(STIX.read_text(encoding="utf-8"))
    collection = [o for o in bundle["objects"] if o["type"] == "x-mitre-collection"]
    assert collection[0]["x_mitre_version"] == "19.2"


def test_cloud_platform_set_excludes_containers():
    """Containers is deliberately not treated as cloud. Kubernetes runs on
    plenty of things that are not a cloud provider, and including it would
    inflate the denominator with on-prem workloads."""
    assert "Containers" not in CLOUD_PLATFORMS
    assert CLOUD_PLATFORMS == {"IaaS", "SaaS", "Identity Provider", "Office Suite"}


def test_cloud_technique_count(result):
    assert result["cloud_techniques"] == 152


def test_rule_count(result):
    assert result["rules"] == 225


def test_coverage_is_about_a_third(result):
    covered = len(result["covered"])
    total = result["cloud_techniques"]
    assert covered == 52
    assert total - covered == 100
    assert 0.33 < covered / total < 0.35


def test_claims_concentrate_on_valid_accounts(result):
    """The headline finding. If a corpus refresh spreads the rules out, this
    fails and the write-up needs revisiting."""
    rpt = result["rules_per_technique"]
    total_claims = sum(rpt.values())
    top_family = rpt["T1078"] + rpt["T1078.004"]
    assert top_family == 65
    assert top_family / total_claims > 0.25


def test_stealth_is_a_real_attack_tactic():
    """The correction. `attack.stealth` looked like a malformed tag and is not.
    ATT&CK v19.2 lists stealth as a tactic, alongside defense-impairment, where
    older material would have said defense-evasion."""
    bundle = json.loads(STIX.read_text(encoding="utf-8"))
    tactics = {
        phase["phase_name"]
        for obj in bundle["objects"]
        if obj.get("type") == "attack-pattern"
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack"
    }
    assert "stealth" in tactics
    assert "defense-impairment" in tactics


def test_untagged_rules_carry_tactic_tags_not_broken_ones(result):
    """The 38 unmappable rules are tagged at tactic level, which is valid Sigma
    and simply too coarse to map to a technique. They are not malformed."""
    assert len(result["untagged_rules"]) == 38
    for rel in result["untagged_rules"]:
        text = (ROOT / "data" / "sigma" / rel).read_text(encoding="utf-8")
        assert "attack." in text, f"{rel} claims no ATT&CK alignment at all"


def test_subtechnique_credits_its_parent():
    assert parent_of("T1078.004") == "T1078"
    assert parent_of("T1078") == "T1078"


def test_tag_parser_reads_technique_ids(tmp_path):
    rule = tmp_path / "r.yml"
    rule.write_text(
        "title: Example\ntags:\n    - attack.persistence\n"
        "    - attack.t1098.001\nlogsource:\n    product: aws\n",
        encoding="utf-8",
    )
    tags, title = parse_rule_tags(rule)
    assert tags == {"T1098.001"}
    assert title == "Example"


def test_tag_parser_ignores_tactic_only_tags(tmp_path):
    rule = tmp_path / "r.yml"
    rule.write_text(
        "title: Tactic only\ntags:\n    - attack.stealth\nlogsource:\n    product: aws\n",
        encoding="utf-8",
    )
    tags, _ = parse_rule_tags(rule)
    assert tags == set()


def test_every_cloud_technique_has_a_platform(result):
    techniques = load_cloud_techniques()
    for tech in techniques.values():
        assert tech.platforms & CLOUD_PLATFORMS
