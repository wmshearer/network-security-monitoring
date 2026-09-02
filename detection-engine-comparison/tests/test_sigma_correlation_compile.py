"""Pin what sigma-cli actually emits for the base rule and the correlation
rule: a correlation rule compiles to an AGGREGATE query (GROUP BY / HAVING),
structurally different from the row-returning base rule. This is the
central claim of the project (see evidence/06-08 and 07_sigma_correlation_sqlite.txt).
"""
from __future__ import annotations

import subprocess

from conftest import ROOT, SIGMA_CLI, requires_sigma_cli

RULES_DIR = ROOT / "rules" / "sigma"


def _convert(target: str, pipeline: str | None, *rule_paths) -> str:
    cmd = [str(SIGMA_CLI), "convert", "-t", target]
    if pipeline:
        cmd += ["-p", pipeline]
    cmd += [str(p) for p in rule_paths]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, f"sigma convert failed: {proc.stderr}"
    return proc.stdout.strip()


@requires_sigma_cli
def test_base_rule_alone_compiles_to_row_returning_select():
    out = _convert("sqlite", "sysmon", RULES_DIR / "kerberoasting_rc4_base.yml")
    assert out.startswith("SELECT * FROM")
    assert "GROUP BY" not in out
    assert "HAVING" not in out


@requires_sigma_cli
def test_correlation_rule_compiles_to_aggregate_not_events():
    """Confirms the ground-truth claim handed into this project: the
    compiled correlation query returns (TargetUserName, event_count) rows,
    not matching event rows.
    """
    out = _convert("sqlite", "sysmon", RULES_DIR)
    assert "GROUP BY TargetUserName" in out
    assert "HAVING event_count >= 10" in out
    assert "COUNT(*) AS event_count" in out
    # It must NOT be a bare SELECT * (that would mean it returned events)
    assert not out.strip().startswith("SELECT * FROM logs")


@requires_sigma_cli
def test_correlation_rule_compiles_to_splunk_stats_pipeline():
    out = _convert("splunk", "splunk_windows", RULES_DIR)
    assert "| bin _time span=5m" in out
    assert "| stats count as event_count by _time TargetUserName" in out
    assert "| search event_count >= 10" in out


@requires_sigma_cli
def test_splunk_windows_pipeline_hardcodes_supported_wineventlog_prefix_only():
    """Pins the field-mapping finding: the compiled Splunk query only ever
    contains source="WinEventLog:Security", never XmlWinEventLog. See
    evidence/17_field_mapping_silent_mismatch.txt.
    """
    out = _convert(
        "splunk", "splunk_windows", RULES_DIR / "kerberoasting_rc4_base.yml"
    )
    assert 'source="WinEventLog:Security"' in out
    assert "XmlWinEventLog" not in out
