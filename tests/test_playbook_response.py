import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from models import Verdict
from playbook_response import recommend


def unresolved_verdict():
    return Verdict(label="unresolved", confidence="none", rule="rule 2", evidence=[])


def malicious_verdict():
    return Verdict(label="malicious", confidence="high", rule="rule 1", evidence=["hit"])


def test_persistence_detection_recommends_isolate():
    action = recommend("D1_registry_run_key_setvalue", "T1547.001", unresolved_verdict(), "HOST-1")
    assert action.action == "isolate_host"
    assert action.label == "SIMULATED_ACTION"


def test_discovery_detection_recommends_escalate_not_isolate():
    action = recommend("D3_net_localgroup_administrators", "T1069.001", unresolved_verdict(), "HOST-1")
    assert action.action == "escalate_to_analyst"


def test_malicious_verdict_upgrades_any_detection_to_isolate():
    action = recommend("D4_net_user_enumeration", "T1087.001", malicious_verdict(), "HOST-1")
    assert action.action == "isolate_host"
    assert "Upgraded" in action.reasoning


def test_simulated_action_never_claims_a_real_action_verb():
    # The whole point of this playbook is that it recommends, it does not
    # execute. Guard against ever emitting language that implies the host
    # was actually touched.
    action = recommend("D1_registry_run_key_setvalue", "T1547.001", unresolved_verdict(), "HOST-1")
    forbidden = ["isolated host", "disabled account", "blocked ip", "successfully executed"]
    reasoning_lower = action.reasoning.lower()
    for phrase in forbidden:
        assert phrase not in reasoning_lower
    assert action.label == "SIMULATED_ACTION"
