import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from models import Alert, SourceCall
from playbook_enrich import decide_verdict


def make_alert(detection="D1_registry_run_key_setvalue", technique="T1547.001"):
    return Alert(
        detection=detection,
        technique=technique,
        search_name="test",
        result_count=1,
        sid="test-sid",
        time="2026-08-24T00:00:00Z",
        raw="",
    )


def test_verdict_unresolved_when_all_sources_skipped():
    alert = make_alert()
    calls = [
        SourceCall(source="greynoise_community", called=False, reason="skipped: no IP"),
        SourceCall(source="abuseipdb", called=False, reason="skipped: no IP"),
        SourceCall(source="virustotal", called=False, reason="skipped: no hash"),
    ]
    v = decide_verdict(alert, indicators=[], source_calls=calls, attack_ctx=None)
    assert v.label == "unresolved"
    assert v.confidence == "none"


def test_verdict_malicious_when_greynoise_flags_noise():
    alert = make_alert()
    calls = [
        SourceCall(source="greynoise_community", called=True, reason="200 OK", result={"noise": True, "ip": "1.2.3.4"}),
    ]
    v = decide_verdict(alert, indicators=[], source_calls=calls, attack_ctx=None)
    assert v.label == "malicious"
    assert v.confidence == "high"
    assert any("greynoise" in e for e in v.evidence)


def test_verdict_malicious_when_abuseipdb_score_high():
    alert = make_alert()
    calls = [
        SourceCall(
            source="abuseipdb",
            called=True,
            reason="HTTP 200",
            result={"data": {"abuseConfidenceScore": 87}},
        ),
    ]
    v = decide_verdict(alert, indicators=[], source_calls=calls, attack_ctx=None)
    assert v.label == "malicious"


def test_verdict_benign_when_called_but_clean():
    alert = make_alert()
    calls = [
        SourceCall(source="greynoise_community", called=True, reason="200 OK", result={"noise": False, "riot": False}),
    ]
    v = decide_verdict(alert, indicators=[], source_calls=calls, attack_ctx=None)
    assert v.label == "benign"
    assert v.confidence == "low"


def test_verdict_low_abuseipdb_score_does_not_flag_malicious():
    alert = make_alert()
    calls = [
        SourceCall(
            source="abuseipdb",
            called=True,
            reason="HTTP 200",
            result={"data": {"abuseConfidenceScore": 10}},
        ),
    ]
    v = decide_verdict(alert, indicators=[], source_calls=calls, attack_ctx=None)
    assert v.label == "benign"
