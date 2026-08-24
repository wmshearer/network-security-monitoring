"""Playbook 2: response recommendation, logged as SIMULATED_ACTION.

This playbook decides what a real SOC would do about an alert given its
detection type and Playbook 1's verdict, and logs that decision as a
discrete, clearly labeled SIMULATED_ACTION record.

It does not isolate a host. It does not disable an account. It does not
block an IP. There is no EDR agent, no identity provider, and no firewall
API reachable from this lab that a playbook could call to do any of those
things for real, and this project does not pretend otherwise. Every record
this playbook produces is labeled SIMULATED_ACTION and states plainly what
it is: a logged decision with reasoning, not an executed response. A
playbook that claimed to isolate a host in a home lab would not survive
one interview question about how, and it would be lying about what
happened.

Response mapping, one rule per detection family, applied uniformly:

- D1 (registry run key persistence), D2 (scheduled task + encoded
  PowerShell): persistence techniques. Recommended action:
  isolate_host, because persistence on an endpoint is the class of finding
  that most directly justifies pulling a host off the network pending
  investigation.
- D3 (local admin group enumeration), D4 (local user enumeration):
  discovery techniques. Recommended action: escalate_to_analyst, not
  isolate_host, because enumeration alone is common in benign admin
  activity too and isolating on discovery-only evidence would be an
  overreaction few SOCs would take automatically.
- D5 (process access to AUDIODG, audio capture): collection technique.
  Recommended action: isolate_host, because live audio capture by an
  unexpected process is a high-confidence, low-false-positive signal (see
  splunk-detection-lab FINDINGS.md: 0 false positives against the full
  benign baseline for this specific detection).
- D6 (PowerShell spawning a recon tool): cross-cutting execution/discovery
  technique. Recommended action: escalate_to_analyst, same reasoning as
  D3/D4: this is enabling behavior, not itself confirmed malicious action.

If Playbook 1's verdict is 'malicious' (a real enrichment source returned
a positive classification), the recommended action for ANY detection is
upgraded to isolate_host regardless of the table above, since a positive
threat-intel hit outweighs the base rate reasoning for that alert type.
"""

from __future__ import annotations

from models import SimulatedAction, Verdict

BASE_ACTION = {
    "D1_registry_run_key_setvalue": "isolate_host",
    "D2_schtasks_encoded_powershell": "isolate_host",
    "D3_net_localgroup_administrators": "escalate_to_analyst",
    "D4_net_user_enumeration": "escalate_to_analyst",
    "D5_process_access_audiodg": "isolate_host",
    "D6_powershell_spawns_recon_tool": "escalate_to_analyst",
}

REASONING = {
    "D1_registry_run_key_setvalue": "persistence via registry Run key; isolate pending investigation",
    "D2_schtasks_encoded_powershell": "persistence via scheduled task with encoded PowerShell payload; isolate pending investigation",
    "D3_net_localgroup_administrators": "local admin group enumeration; discovery-only, common in benign admin activity, escalate for analyst review rather than auto-isolate",
    "D4_net_user_enumeration": "local user enumeration; discovery-only, escalate for analyst review rather than auto-isolate",
    "D5_process_access_audiodg": "process access to AUDIODG.EXE (audio capture); 0 false positives against this portfolio's benign baseline for this detection, high-confidence isolate",
    "D6_powershell_spawns_recon_tool": "PowerShell spawning a recon tool; enabling behavior for other techniques, escalate for analyst review rather than auto-isolate",
}


def recommend(detection: str, technique: str, verdict: Verdict, target_hint: str) -> SimulatedAction:
    action = BASE_ACTION.get(detection, "escalate_to_analyst")
    reasoning = REASONING.get(detection, "unrecognized detection id, defaulting to escalate_to_analyst")

    if verdict.label == "malicious":
        action = "isolate_host"
        reasoning = (
            f"{reasoning}. Upgraded to isolate_host: enrichment verdict was 'malicious' "
            f"({verdict.rule})"
        )

    return SimulatedAction(
        alert_detection=detection,
        technique=technique,
        action=action,
        target=target_hint,
        reasoning=reasoning,
    )


def record_to_dict(action: SimulatedAction) -> dict:
    return {
        "label": action.label,
        "detection": action.alert_detection,
        "technique": action.technique,
        "action": action.action,
        "target": action.target,
        "reasoning": action.reasoning,
    }
