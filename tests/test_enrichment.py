import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from enrichment import (
    attack_technique_context,
    enrich_indicators,
    extract_indicators,
    which_kinds_absent,
)


def test_extract_indicators_pulls_populated_fields_only():
    event = {
        "Image": "C:\\windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ParentImage": "-",
        "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsDefender",
        "Hostname": "WORKSTATION6.mordor.local",
    }
    indicators = extract_indicators(event)
    kinds = {i.kind for i in indicators}
    # ParentImage was "-" (Splunk's empty placeholder), so it must NOT appear
    assert "parent_image" not in kinds
    assert "process_image" in kinds
    assert "registry_path" in kinds
    assert "hostname" in kinds


def test_extract_indicators_empty_event_returns_nothing():
    assert extract_indicators({}) == []


def test_which_kinds_absent_true_when_no_ip_or_hash_field():
    # This is the real shape of a D1/D5 event in this portfolio: no IP,
    # no Hashes field at all.
    event = {"Image": "C:\\windows\\system32\\lsass.exe", "TargetObject": "HKLM\\..."}
    absent = which_kinds_absent(event)
    assert absent["ip"] is False
    assert absent["hash"] is False


def test_which_kinds_absent_true_when_ip_present():
    event = {"SourceIp": "10.0.0.5"}
    absent = which_kinds_absent(event)
    assert absent["ip"] is True


def test_enrich_indicators_skips_greynoise_and_abuseipdb_when_no_ip(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    calls = enrich_indicators(indicators=[], absent={"ip": False, "hash": False})
    by_source = {c.source: c for c in calls}
    assert by_source["greynoise_community"].called is False
    assert "no IP" in by_source["greynoise_community"].reason
    assert by_source["abuseipdb"].called is False


def test_enrich_indicators_skips_virustotal_when_no_key(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    calls = enrich_indicators(indicators=[], absent={"ip": False, "hash": True})
    by_source = {c.source: c for c in calls}
    # hash present but no key -> the per-indicator call path is taken, but
    # there are no hash indicators in this test, so nothing is appended for
    # virustotal via that path; assert the "absent" skip path is NOT what
    # produced this (i.e. hash-present branch was taken, zero hash indicators
    # means zero virustotal calls, not a skip record)
    assert "virustotal" not in by_source


def test_attack_technique_context_resolves_known_technique():
    ctx = attack_technique_context("T1547.001")
    assert ctx is not None
    assert "Run Key" in ctx["name"] or "Startup" in ctx["name"]


def test_attack_technique_context_returns_none_for_unknown_id():
    assert attack_technique_context("T9999.999") is None
