"""Tests for src/score_detections.py's pure scoring logic (compute_scores).

Deliberately does NOT hit the live Splunk REST API (score_one/run_search) --
these tests exercise the TP/FN/cross-contamination/recall RULES against
hand-built hit-count inputs, so the scoring logic itself is verified
independently of whether a Splunk instance happens to be running.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from score_detections import compute_scores  # noqa: E402


def test_single_capture_true_positive_no_fp():
    result = compute_scores(
        name="D1_registry_run_key_setvalue",
        technique_id="T1547.001",
        target_capture="empire_persistence_registry_modification_run_keys_standard_user",
        hits_by_capture={"empire_persistence_registry_modification_run_keys_standard_user": 2},
        benign_fp_event_count=0,
    )
    assert result["tp"] == 1
    assert result["fn"] == 0
    assert result["recall"] == 1.0
    assert result["benign_fp_event_count"] == 0
    assert result["fired_on_any_benign"] is False
    assert result["cross_contamination"] == {}


def test_false_negative_when_target_capture_has_zero_hits():
    result = compute_scores(
        name="D_never_fires",
        technique_id="T9999",
        target_capture="some_capture",
        hits_by_capture={},  # target capture absent entirely -> 0 hits
        benign_fp_event_count=0,
    )
    assert result["tp"] == 0
    assert result["fn"] == 1
    assert result["recall"] == 0.0
    assert result["fn_captures"] == ["some_capture"]


def test_benign_false_positive_is_reported_but_does_not_change_recall():
    """A detection that both catches its target AND fires on benign data --
    recall (a capture-level, attack-only concept) must stay 1.0; the benign
    FP is a separate number, never silently blended into a lower recall."""
    result = compute_scores(
        name="D_noisy",
        technique_id="T1000",
        target_capture="cap_a",
        hits_by_capture={"cap_a": 5},
        benign_fp_event_count=112,
    )
    assert result["tp"] == 1
    assert result["recall"] == 1.0
    assert result["benign_fp_event_count"] == 112
    assert result["fired_on_any_benign"] is True


def test_cross_contamination_detected_when_detection_fires_on_other_captures():
    """A detection fires on its target capture AND on a different attack
    capture's events -- this must show up as cross_contamination, distinct
    from the benign-FP count (different failure mode: technique
    misattribution vs. a false alarm on entirely benign data)."""
    result = compute_scores(
        name="D_overbroad",
        technique_id="T1069.001",
        target_capture="empire_shell_net_localgroup_administrators",
        hits_by_capture={
            "empire_shell_net_localgroup_administrators": 2,
            "empire_shell_net_local_users": 3,  # wrong capture/technique
        },
        benign_fp_event_count=0,
    )
    assert result["tp"] == 1
    assert result["cross_contamination"] == {"empire_shell_net_local_users": 3}


def test_multi_capture_detection_partial_recall():
    """D6-shaped detection: targets 3 captures, only 2 actually fire ->
    recall must reflect the partial hit rate (2/3), not round up or down."""
    result = compute_scores(
        name="D6_powershell_spawns_recon_tool",
        technique_id="T1059.001",
        target_capture=["cap_a", "cap_b", "cap_c"],
        hits_by_capture={"cap_a": 1, "cap_b": 1},  # cap_c missing -> FN
        benign_fp_event_count=0,
    )
    assert result["tp"] == 2
    assert result["fn"] == 1
    assert result["fn_captures"] == ["cap_c"]
    assert result["recall"] == 2 / 3


def test_recall_is_none_when_there_are_zero_opportunities():
    """A detection with an empty target list is a config error, not a
    div-by-zero -- recall must come back as an explicit None, never a
    silently-substituted 0 or 1 (mirrors ai-triage-engine's own
    metrics.py convention of returning None for undefined ratios)."""
    result = compute_scores(
        name="D_misconfigured",
        technique_id="T0000",
        target_capture=[],
        hits_by_capture={},
        benign_fp_event_count=0,
    )
    assert result["n_opportunities"] == 0
    assert result["recall"] is None


def test_string_target_capture_is_normalized_to_a_list():
    """target_capture may be passed as a bare string (single-technique
    detections D1-D5) or a list (D6) -- both must produce the same shape of
    result so downstream code (score_detections.main, FINDINGS.md
    generation) never has to special-case the type."""
    result = compute_scores(
        name="D1",
        technique_id="T1547.001",
        target_capture="only_one_capture",
        hits_by_capture={"only_one_capture": 2},
        benign_fp_event_count=0,
    )
    assert result["target_captures"] == ["only_one_capture"]
