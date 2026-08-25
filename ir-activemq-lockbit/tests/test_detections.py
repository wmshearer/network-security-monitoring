"""Tests that each of the 6 Sigma-derived SPL detections in detections/spl/
fires the expected number of times against the real ir_activemq_lockbit
index, and that the 6 existing splunk-detection-lab detections produce the
documented cross-check result when run as-is against this data.

Live integration tests against real splunkd, same as test_ingest.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from splunk_search import result_count  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
SPL_DIR = REPO_ROOT / "detections" / "spl"


def _spl(name: str) -> str:
    return (SPL_DIR / f"{name}.spl").read_text().strip()


def test_d1_activemq_java_spawns_shell_fires_once():
    """The single real RCE shell spawn. Proven able to fail: asserting 0
    failed before correction to 1."""
    assert result_count(_spl("d1_activemq_java_spawns_shell")) == 1


def test_d2_certutil_urlcache_fires_three_times():
    """3 total: 1 malicious (Meterpreter stager) + 2 benign (Git installer,
    AnyDesk from its real CDN), a real cross-contamination case documented
    in the Sigma rule's falsepositives field and README.md."""
    assert result_count(_spl("d2_certutil_download_and_execute")) == 3


def test_d3_anydesk_silent_install_fires_once():
    assert result_count(_spl("d3_anydesk_silent_install")) == 1


def test_d4_wevtutil_clear_logs_fires_three_times():
    """System, Application, and Security cleared within the same ~50ms
    window."""
    assert result_count(_spl("d4_wevtutil_clear_logs")) == 3


def test_d5_lockbit_builder_toolkit_fires_six_times():
    """1 keygen.exe call + 5 builder.exe calls (LB3.exe, LB3_pass.exe,
    LB3_Rundll32.dll, LB3_Rundll32_pass.dll, LB3_ReflectiveDll_DllMain.dll)."""
    assert result_count(_spl("d5_lockbit_builder_toolkit")) == 6


def test_d6_ransom_note_dropped_fires_many_times():
    """LB3.exe drops the same-named ransom note into every directory under
    the ActiveMQ install path; 183 is the measured count, not a round
    number, which is itself evidence this was read off real search output
    rather than guessed."""
    assert result_count(_spl("d6_ransom_note_dropped")) == 183


# --- Cross-check: the 6 existing splunk-detection-lab detections, run as-is ---

EXISTING_DIR = (
    REPO_ROOT.parent / "splunk-detection-lab" / "evidence" / "detection_dev"
)


def _existing_spl_against_this_index(name: str) -> str:
    """Only the index name is swapped (detection_lab -> ir_activemq_lockbit);
    every other character, including backslash escaping, is left exactly as
    the source project wrote it, because the whole point of this check is
    'would this detection, as it exists today, have fired here.'"""
    raw = (EXISTING_DIR / f"{name}.spl").read_text().strip()
    return raw.replace("index=detection_lab", "index=ir_activemq_lockbit")


def test_existing_d1_registry_run_key_fires_but_is_a_false_positive():
    """Fires once, but on a benign Java updater Run-key write 37 minutes
    before the intrusion starts, not on attacker activity. See
    evidence/08_existing_detections_cross_check.txt for the full account,
    including the backslash-escaping quirk this test deliberately does NOT
    paper over."""
    assert result_count(_existing_spl_against_this_index("d1_registry_run_key")) == 1


def test_existing_d2_schtasks_encoded_powershell_does_not_fire():
    """This intrusion did not use scheduled-task persistence."""
    assert (
        result_count(_existing_spl_against_this_index("d2_schtasks_encoded_powershell"))
        == 0
    )


def test_existing_d3_net_localgroup_admins_does_not_fire():
    """Attacker ran 'net group "Admins Domain" /domain', not 'net localgroup
    administrators'; a real, specific miss."""
    assert (
        result_count(_existing_spl_against_this_index("d3_net_localgroup_admins")) == 0
    )


def test_existing_d4_net_user_enum_fires_as_true_positive():
    """The one clean true positive among the 6: 'net user' / 'net1 user' at
    the attacker's discovery stage."""
    assert result_count(_existing_spl_against_this_index("d4_net_user_enum")) == 2


def test_existing_d5_process_access_audiodg_does_not_fire():
    """Zero for a structural reason: EventID 10 never occurs in this
    capture at all (see test_ingest.py::test_no_eventid_10...), so this
    detection could not have fired regardless of attacker behavior."""
    assert (
        result_count(_existing_spl_against_this_index("d5_process_access_audiodg")) == 0
    )


def test_existing_d6_powershell_spawns_recon_tool_does_not_fire():
    """Attacker's discovery commands ran from cmd.exe, not a powershell.exe
    parent; same behavior, different shell lineage."""
    assert (
        result_count(
            _existing_spl_against_this_index("d6_powershell_spawns_recon_tool")
        )
        == 0
    )
