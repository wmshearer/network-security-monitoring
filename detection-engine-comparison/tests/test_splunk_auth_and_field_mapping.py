"""Splunk-related tests. Live SPL execution is SKIPPED (not failed) because
Splunk authentication was unavailable in this project (SPLUNK_PASS unset,
no stored credential; see evidence/05_splunk_auth_attempt.txt). The
field-mapping claim itself is pinned statically against the installed
pySigma Splunk pipeline source and the corpus's own published macro/test
fixture, which does not require a live Splunk connection.
"""
from __future__ import annotations

import os
import subprocess

import pytest

from conftest import CORPORA, requires_corpus


def _splunk_authenticated() -> bool:
    if not os.environ.get("SPLUNK_PASS"):
        return False
    proc = subprocess.run(
        [
            "curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
            "-u", f"admin:{os.environ['SPLUNK_PASS']}",
            "https://localhost:8089/services/server/info",
        ],
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip() == "200"


requires_splunk_auth = pytest.mark.skipif(
    not _splunk_authenticated(),
    reason="Splunk auth unavailable: SPLUNK_PASS unset or rejected (see evidence/05_splunk_auth_attempt.txt)",
)


@requires_splunk_auth
def test_live_spl_field_mapping_mismatch_reproduces():
    """Left as a SKIPPED placeholder for the live confirmation described in
    evidence/17_field_mapping_silent_mismatch.txt's final paragraph: ingest
    windows-xml.log as sourcetype=XmlWinEventLog, then compare hit counts
    between the pySigma-compiled query (source="WinEventLog:Security") and
    the macro-based reference query. Not implemented because it was never
    reachable in this project; SPLUNK_PASS was never set. If this ever runs
    for real, it should assert the pySigma-compiled query returns 0 and
    the macro-based query returns >= 1 on the same ingested data.
    """
    pytest.skip("Not implemented: no session in this project ever had Splunk auth to develop this against.")


@requires_corpus
def test_reference_macro_definition_ors_both_source_conventions():
    macro_path = CORPORA / "security_content" / "macros" / "wineventlog_security.yml"
    text = macro_path.read_text()
    assert 'source="XmlWinEventLog:Security"' in text
    assert 'source="WinEventLog:Security"' in text


@requires_corpus
def test_corpus_test_fixture_declares_xmlwineventlog_sourcetype():
    yml_path = (
        CORPORA
        / "security_content"
        / "detections"
        / "endpoint"
        / "kerberoasting_spn_request_with_rc4_encryption.yml"
    )
    text = yml_path.read_text()
    assert "source: XmlWinEventLog:Security" in text
    assert "sourcetype: XmlWinEventLog" in text


def test_pysigma_splunk_pipeline_hardcodes_wineventlog_prefix_only():
    from pathlib import Path

    pipeline_path = Path(
        "/home/kali/director/projects/detection-as-code/.venv/lib/python3.13/"
        "site-packages/sigma/pipelines/splunk/splunk.py"
    )
    if not pipeline_path.exists():
        pytest.skip("pySigma Splunk pipeline source not found at the expected venv path")
    text = pipeline_path.read_text()
    assert '"WinEventLog:{source}"' in text
    assert "XmlWinEventLog" not in text
