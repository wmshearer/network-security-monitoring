"""Pin the YARA findings: it correctly matches the true-positive event, and
it produces a real false positive on an unrelated event because it cannot
bind a string match to a specific field.
"""
from __future__ import annotations

import subprocess

from conftest import ROOT, T1558, requires_corpus, requires_yara

YARA_RULE = ROOT / "rules" / "yara" / "kerberoasting_rc4_stringmatch.yar"


def _yara(rule, target) -> str:
    proc = subprocess.run(
        ["yara", "-s", str(rule), str(target)], capture_output=True, text=True
    )
    return proc.stdout


@requires_yara
@requires_corpus
def test_yara_matches_real_kerberoasting_event():
    target = T1558 / "kerberoasting_spn_request_with_rc4_encryption" / "windows-xml.log"
    out = _yara(YARA_RULE, target)
    assert "Kerberoasting_RC4_TGS_Request_StringMatch" in out
    assert "Kerberoasting_RC4_Encryption_Type_Substring_Only" in out


@requires_yara
@requires_corpus
def test_yara_weak_rule_false_positives_on_unrelated_process_creation_event(tmp_path):
    """event_00139 in rubeus/windows-security.log is EventCode=4688
    (process creation of splunk-netmon.exe, New Process ID 0x177c), nothing
    to do with Kerberos. The substring-only rule matches it anyway because
    "0x177c" contains "0x17". The anchored rule correctly rejects it.
    """
    rubeus_log = T1558 / "rubeus" / "windows-security.log"
    text = rubeus_log.read_text(errors="replace")
    assert "New Process ID:\t\t0x177c" in text
    assert "splunk-netmon.exe" in text

    fixture = tmp_path / "event_00139.txt"
    # Extract the same event block used in evidence/14_yara_false_positive.txt
    idx = text.index("New Process ID:\t\t0x177c")
    start = text.rfind("02/11/2022", 0, idx)
    end = text.find("02/11/2022", idx)
    fixture.write_text(text[start:end])

    out = _yara(YARA_RULE, fixture)
    assert "Kerberoasting_RC4_Encryption_Type_Substring_Only" in out
    assert "Kerberoasting_RC4_TGS_Request_StringMatch" not in out
