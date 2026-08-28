"""Pin what Zircolite actually does: silently truncates a multi-root XML
file to 1 event via -x/--xml-input, correctly processes all events via
--json-input, silently folds a base+correlation rule pair into ONE loaded
rule, and correctly evaluates the correlation's aggregate SQL end to end.
"""
from __future__ import annotations

import json
import subprocess
import sys

from conftest import (
    ROOT,
    T1558,
    ZIRCOLITE_PY,
    ZIRCOLITE_SCRIPT,
    requires_corpus,
    requires_zircolite,
)

RULES_DIR = ROOT / "rules" / "sigma"
BASE_ONLY_DIR = ROOT / "rules" / "sigma_base_only"
CONVERTER = ROOT / "scripts" / "02_convert_xml_to_jsonl.py"


def _run_zircolite(events_arg: list[str], rules_dir, out_path, extra=None):
    cmd = [str(ZIRCOLITE_PY), str(ZIRCOLITE_SCRIPT), *events_arg, "-r", str(rules_dir), "-o", str(out_path)]
    if extra:
        cmd += extra
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
    return proc


@requires_zircolite
@requires_corpus
def test_native_xml_input_silently_truncates_multiroot_file_to_one_event(tmp_path):
    volumetric_log = (
        T1558 / "unusual_number_of_kerberos_service_tickets_requested" / "windows-xml.log"
    )
    out_path = tmp_path / "out.json"
    proc = _run_zircolite(
        ["-e", str(volumetric_log), "-x", "-f", "log"],
        BASE_ONLY_DIR,
        out_path,
    )
    assert "Total events processed: 1" in proc.stdout
    # Ground truth: the file actually has 159 events (see
    # test_corpus_ground_truth.py). Zircolite's own stdout claims 1, with
    # no warning that anything was truncated -- that gap IS the finding.
    assert "Total events processed: 159" not in proc.stdout


@requires_zircolite
@requires_corpus
def test_json_input_correctly_processes_all_159_events(tmp_path):
    volumetric_log = (
        T1558 / "unusual_number_of_kerberos_service_tickets_requested" / "windows-xml.log"
    )
    jsonl_path = tmp_path / "volumetric.jsonl"
    conv = subprocess.run(
        [str(ZIRCOLITE_PY), str(CONVERTER), str(volumetric_log), str(jsonl_path)],
        capture_output=True,
        text=True,
    )
    assert conv.returncode == 0, conv.stderr
    assert jsonl_path.exists()
    lines = jsonl_path.read_text().strip().splitlines()
    assert len(lines) == 159

    out_path = tmp_path / "out.json"
    proc = _run_zircolite(["-e", str(jsonl_path), "-j"], BASE_ONLY_DIR, out_path)
    assert "Total events processed: 159" in proc.stdout


@requires_zircolite
@requires_corpus
def test_base_rule_alone_fires_zero_times_on_volumetric_data(tmp_path):
    """Confirms the field-value mismatch: this dataset's TicketOptions
    (0x60810010) never matches the base rule's filter
    (0x40810000/0x40800000/0x40810010), so a plain per-event rule reports
    zero detections on the very file meant to demonstrate the volumetric
    case.
    """
    volumetric_log = (
        T1558 / "unusual_number_of_kerberos_service_tickets_requested" / "windows-xml.log"
    )
    jsonl_path = tmp_path / "volumetric.jsonl"
    subprocess.run(
        [str(ZIRCOLITE_PY), str(CONVERTER), str(volumetric_log), str(jsonl_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    out_path = tmp_path / "out.json"
    _run_zircolite(["-e", str(jsonl_path), "-j"], BASE_ONLY_DIR, out_path)
    if out_path.exists():
        data = json.loads(out_path.read_text())
        assert data == []


@requires_zircolite
def test_correlation_directory_loads_only_one_rule_not_two(tmp_path):
    """Zircolite loaded BOTH kerberoasting_rc4_base.yml and
    kerberoasting_rc4_volumetric_correlation.yml from rules/sigma/, but
    reports "Converted 1 rules" / "1 rules loaded": pySigma's correlation
    compiler folds the base rule's filter into the correlation's own SQL
    subquery, so the base rule never runs as a second, separate,
    row-returning rule alongside it.
    """
    synthetic = tmp_path / "synthetic.jsonl"
    synthetic.write_text(
        "\n".join(
            json.dumps(
                {
                    "EventID": 4769,
                    "TicketEncryptionType": "0x17",
                    "TicketOptions": "0x40810000",
                    "ServiceName": f"svc{i}",
                    "TargetUserName": "testuser@ATTACKRANGE.LOCAL",
                    "SystemTime": "2024-04-08T23:56:00.000000000Z",
                }
            )
            for i in range(12)
        )
        + "\n"
    )
    out_path = tmp_path / "out.json"
    proc = _run_zircolite(["-e", str(synthetic), "-j"], RULES_DIR, out_path)
    assert "Converted 1 rules" in proc.stdout
    assert "1 rules loaded" in proc.stdout

    data = json.loads(out_path.read_text())
    assert len(data) == 1
    assert data[0]["matches"] == [
        {"TargetUserName": "testuser@ATTACKRANGE.LOCAL", "event_count": 12}
    ]
    # The match is an aggregate row, not a raw event: no EventRecordID,
    # ServiceName, or SystemTime of any individual ticket request survives.
    match = data[0]["matches"][0]
    assert "EventRecordID" not in match
    assert "ServiceName" not in match
    assert set(match.keys()) == {"TargetUserName", "event_count"}
