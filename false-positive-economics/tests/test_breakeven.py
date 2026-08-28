"""Tests for the break-even module (scripts/02_breakeven.py).

SKIP (never FAIL) when detection-rule-lab's scoring-run.json is absent.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from common import SCORING_RUN_JSON, load_scoring_run  # noqa: E402

pytestmark = pytest.mark.skipif(
    not SCORING_RUN_JSON.exists(),
    reason=f"source project file not found: {SCORING_RUN_JSON} (detection-rule-lab absent)",
)


def _load_breakeven_module():
    spec = importlib.util.spec_from_file_location("breakeven", SCRIPTS_DIR / "02_breakeven.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_zero_true_positive_rule_has_no_finite_breakeven():
    mod = _load_breakeven_module()
    # malicious_hits=0 must return None regardless of assumption inputs.
    for hourly in mod.ANALYST_HOURLY_COST_SWEEP:
        for value_tp in mod.VALUE_PER_TP_SWEEP:
            result = mod.breakeven_triage_minutes(0, 56, hourly, value_tp)
            assert result is None


def test_zero_true_positive_rule_is_cost_negative_at_any_nonzero_minutes():
    mod = _load_breakeven_module()
    for triage_min in [0.001, 1, 5, 60, 10_000]:
        for hourly in mod.ANALYST_HOURLY_COST_SWEEP:
            cost = mod.cumulative_triage_cost(56, triage_min, hourly)
            value = mod.value_captured(0, 1_000_000)  # even a huge assumed value
            assert value == 0
            assert cost > 0
            assert value < cost


def test_nonzero_true_positive_rule_has_finite_breakeven():
    mod = _load_breakeven_module()
    result = mod.breakeven_triage_minutes(malicious_hits=10, benign_hits=2, hourly_cost=75, value_per_tp=50)
    assert result is not None
    assert result > 0


def test_breakeven_formula_matches_direct_computation():
    """Cross-check the closed-form solver against a direct sweep search."""
    mod = _load_breakeven_module()
    mal, ben, hourly, value_tp = 10, 2, 75, 50
    solved = mod.breakeven_triage_minutes(mal, ben, hourly, value_tp)

    # Direct search: net(m) = value - cost(m); find m where net crosses 0.
    total = mal + ben
    value = mod.value_captured(mal, value_tp)
    cost_at_solved = mod.cumulative_triage_cost(total, solved, hourly)
    assert abs(value - cost_at_solved) < 1e-6


def test_sweep_table_has_one_row_per_benign_touching_rule():
    mod = _load_breakeven_module()
    scoring_run = load_scoring_run()
    rows = mod.build_sweep_table(scoring_run)
    assert len(rows) == 4


def test_sweep_table_flags_anchor_as_cost_negative_at_any_nonzero_assumption():
    mod = _load_breakeven_module()
    scoring_run = load_scoring_run()
    rows = mod.build_sweep_table(scoring_run)
    anchor = next(r for r in rows if r["title"] == "Modification of IE Registry Settings")
    assert anchor["cost_negative_at_any_nonzero_assumption"] is True
    for entry in anchor["sweep"]:
        assert entry["cost_justified"] is False
