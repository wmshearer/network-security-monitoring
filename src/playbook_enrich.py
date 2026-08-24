"""Playbook 1: IOC enrichment and verdict.

For each alert: fetch the raw Sysmon event(s) that produced it (via the
alert's own sid where the search job cache still holds results, falling
back to re-running the detection's exact SPL by name), extract whatever
indicators are actually present, enrich against the sources configured in
enrichment.py, apply a documented decision rule, and return a structured
verdict record. Every step here makes a real call against real data; there
is no mocked response anywhere in this file.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from enrichment import attack_technique_context, enrich_indicators, extract_indicators, which_kinds_absent
from models import Alert, EnrichmentRecord, Verdict
from splunk_client import SplunkClient

# The exact SPL for each detection, copied from splunk-detection-lab's
# savedsearches.conf (read only, not modified). Used as a fallback to
# re-fetch the matching raw events when the original search job's sid has
# aged out of Splunk's job cache (Splunk expires oneshot/job artifacts
# after a TTL; alerts observed well after they fired will usually hit this
# path, not the sid path).
DETECTION_SPL = {
    "D1_registry_run_key_setvalue": 'index=detection_lab EventID=13 TargetObject="*\\Run\\*"',
    "D2_schtasks_encoded_powershell": 'index=detection_lab EventID=1 Image="*schtasks.exe" CommandLine="*powershell*" CommandLine="*hidden*"',
    "D3_net_localgroup_administrators": 'index=detection_lab EventID=1 Image="*net.exe" CommandLine="*localgroup*administrators*"',
    "D4_net_user_enumeration": 'index=detection_lab EventID=1 Image="*net.exe" CommandLine="*user*"',
    "D5_process_access_audiodg": 'index=detection_lab EventID=10 TargetImage="*AUDIODG.EXE"',
    "D6_powershell_spawns_recon_tool": 'index=detection_lab EventID=1 ParentImage="*powershell.exe" (Image="*\\\\net.exe" OR Image="*\\\\net1.exe" OR Image="*\\\\schtasks.exe")',
}


def fetch_matching_events(client: SplunkClient, alert: Alert, limit: int = 5) -> list:
    """Return up to `limit` raw events that matched this alert's detection.
    Tries the alert's own search job (sid) first since that is the exact
    run that fired; falls back to re-running the detection's SPL fresh
    against the same index if the sid's job artifacts have expired.
    """
    if alert.sid:
        try:
            data = client_get_job_results(client, alert.sid, limit)
            if data.get("results"):
                return data["results"]
        except Exception:
            pass  # fall through to SPL re-run

    spl = DETECTION_SPL.get(alert.detection)
    if not spl:
        return []
    data = client.search(f"{spl} | head {limit}")
    return data.get("results", [])


def client_get_job_results(client: SplunkClient, sid: str, limit: int) -> dict:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    resp = requests.get(
        f"{client.url}/services/search/jobs/{sid}/results",
        params={"output_mode": "json", "count": limit},
        auth=(client.user, client.password),
        verify=False,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def decide_verdict(alert: Alert, indicators: list, source_calls: list, attack_ctx: dict | None) -> Verdict:
    """Documented decision rule, applied the same way to every alert:

    1. If any enrichment source that was actually CALLED (not skipped)
       returned a positive/malicious classification, label 'malicious',
       confidence 'high'.
    2. Else if no enrichment source was callable at all (everything
       skipped, e.g. no key and no applicable indicator kind), label
       'unresolved' -- this is the honest outcome for this portfolio's
       detections most of the time, since they carry process/registry
       indicators, not IPs or hashes, and no key is configured.
    3. Else (sources were called and returned clean/negative results),
       label 'benign', confidence 'low' (a clean lookup on a narrow set of
       free-tier sources is evidence, not proof).

    This rule is intentionally simple and stated in full here rather than
    hidden in branching logic, because the point of this playbook is the
    decision being visible and auditable, not clever.
    """
    called = [c for c in source_calls if c.called]
    evidence = []
    malicious_hit = False

    for c in called:
        if c.source == "greynoise_community" and c.result and c.result.get("noise"):
            malicious_hit = True
            evidence.append(f"{c.source}: flagged noisy/scanning IP")
        if c.source == "abuseipdb" and c.result:
            score = c.result.get("data", {}).get("abuseConfidenceScore", 0)
            if score and score >= 50:
                malicious_hit = True
                evidence.append(f"{c.source}: abuseConfidenceScore={score}")
        if c.source == "virustotal" and c.result:
            stats = c.result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if stats.get("malicious", 0) > 0:
                malicious_hit = True
                evidence.append(f"{c.source}: {stats.get('malicious')} engines flagged malicious")

    if malicious_hit:
        rule = "rule 1: at least one called enrichment source returned a positive/malicious classification"
        return Verdict(label="malicious", confidence="high", rule=rule, evidence=evidence)

    if not called:
        rule = (
            "rule 2: no enrichment source was callable for this alert's indicators "
            "(process/registry indicators are not IP or hash shaped, and/or no API key configured)"
        )
        evidence.append(f"indicators extracted: {[i.kind for i in indicators]}")
        if attack_ctx:
            evidence.append(f"technique context (local ATT&CK lookup): {attack_ctx['name']}")
        return Verdict(label="unresolved", confidence="none", rule=rule, evidence=evidence)

    rule = "rule 3: enrichment sources were called and returned no positive/malicious classification"
    evidence.append(f"sources called cleanly: {[c.source for c in called]}")
    return Verdict(label="benign", confidence="low", rule=rule, evidence=evidence)


def run_playbook(client: SplunkClient, alert: Alert) -> tuple:
    """Returns (EnrichmentRecord, events) so callers that also need the raw
    matching event (e.g. run_pipeline.py picking a SIMULATED_ACTION target)
    do not have to issue a second, redundant Splunk query for the same
    alert.
    """
    events = fetch_matching_events(client, alert, limit=3)
    indicators = []
    absent = {"ip": False, "hash": False}
    if events:
        indicators = extract_indicators(events[0])
        absent = which_kinds_absent(events[0])

    source_calls = enrich_indicators(indicators, absent)
    attack_ctx = attack_technique_context(alert.technique)
    verdict = decide_verdict(alert, indicators, source_calls, attack_ctx)

    record = EnrichmentRecord(
        alert=alert,
        indicators=indicators,
        source_calls=source_calls,
        verdict=verdict,
    )
    return record, events


def record_to_dict(rec: EnrichmentRecord) -> dict:
    return {
        "detection": rec.alert.detection,
        "technique": rec.alert.technique,
        "alert_time": rec.alert.time,
        "indicators_extracted": [{"kind": i.kind, "value": i.value} for i in rec.indicators],
        "source_calls": [
            {"source": c.source, "called": c.called, "reason": c.reason}
            for c in rec.source_calls
        ],
        "verdict": {
            "label": rec.verdict.label,
            "confidence": rec.verdict.confidence,
            "rule": rec.verdict.rule,
            "evidence": rec.verdict.evidence,
        },
    }


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sid", help="run against a single alert by sid (for manual testing)")
    args = ap.parse_args()

    client = SplunkClient()
    print(json.dumps({"note": "run via run_pipeline.py for the full trigger-to-verdict flow"}))
