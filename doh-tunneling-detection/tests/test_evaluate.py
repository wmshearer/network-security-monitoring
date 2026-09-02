"""Tests for src/evaluate.py: the group-split logic and its guard.

Uses a small synthetic dataset with an intentionally easy-to-separate
behavioral signal, so a correctly-implemented split should show near-perfect
accuracy on both random-split and leave-one-tool-out. The point of these
tests is not to reproduce the real dataset's numbers (see
scripts/run_analysis.py and reports/findings.md for those); it's to prove
the split mechanics themselves are correct: no tool leaks across the
train/test boundary, and the fold accounting is right.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from src.data import BENIGN_TOOL_LABEL
from src.evaluate import (
    assert_no_tool_overlap,
    leave_one_tool_out_eval,
    random_split_eval,
    summarize_leave_one_tool_out,
)
from src.model import make_logistic_regression


def _synthetic_dataset(n_per_tool: int = 40, seed: int = 0) -> tuple[pd.DataFrame, pd.Series, pd.Series]:
    """Benign rows clustered near 0, malicious rows (three tools) clustered
    near 1 on a single informative feature, plus a second pure-noise
    feature. Easy enough that both eval paths should score well, which is
    what lets the tests assert on `> some high bar` without depending on
    fragile exact numbers.
    """
    rng = np.random.default_rng(seed)
    rows = []
    tools = []
    labels = []

    n_benign = n_per_tool * 3
    for _ in range(n_benign):
        rows.append({"signal": rng.normal(0, 0.2), "noise": rng.normal(0, 1)})
        tools.append(BENIGN_TOOL_LABEL)
        labels.append(0)

    for tool in ("toolA", "toolB", "toolC"):
        for _ in range(n_per_tool):
            rows.append({"signal": rng.normal(1, 0.2), "noise": rng.normal(0, 1)})
            tools.append(tool)
            labels.append(1)

    X = pd.DataFrame(rows)
    y = pd.Series(labels, name="label")
    tools_s = pd.Series(tools, name="tool")
    return X, y, tools_s


# --- assert_no_tool_overlap, the guard ----------------------------------


def test_assert_no_tool_overlap_passes_when_disjoint():
    train = pd.Series(["toolA", "toolB", BENIGN_TOOL_LABEL])
    test = pd.Series(["toolC", BENIGN_TOOL_LABEL])
    assert_no_tool_overlap(train, test)  # must not raise


def test_assert_no_tool_overlap_raises_when_tool_leaks_across_split():
    train = pd.Series(["toolA", "toolB"])
    test = pd.Series(["toolB", "toolC"])
    with pytest.raises(AssertionError, match="toolB"):
        assert_no_tool_overlap(train, test)


def test_assert_no_tool_overlap_ignores_shared_benign_label():
    # Benign has no tool to hold out from; it legitimately appears on both
    # sides of every fold, and that must not trip the guard.
    train = pd.Series(["toolA", BENIGN_TOOL_LABEL])
    test = pd.Series(["toolB", BENIGN_TOOL_LABEL])
    assert_no_tool_overlap(train, test)  # must not raise


# --- leave_one_tool_out_eval ---------------------------------------------


def test_leave_one_tool_out_produces_one_fold_per_tool():
    X, y, tools = _synthetic_dataset()
    results = leave_one_tool_out_eval(make_logistic_regression, X, y, tools)
    assert {r.name for r in results} == {
        "leave_out=toolA",
        "leave_out=toolB",
        "leave_out=toolC",
    }


def test_leave_one_tool_out_never_trains_on_the_held_out_tool():
    """The mechanical guarantee the whole methodology rests on: for every
    fold, reconstruct which tool rows went into train vs test and assert
    no overlap, the same way the harness itself must.
    """
    X, y, tools = _synthetic_dataset()
    tool_names = sorted(t for t in tools.unique() if t != BENIGN_TOOL_LABEL)

    for held_out in tool_names:
        test_mask = (tools == held_out) | (tools == BENIGN_TOOL_LABEL)
        train_mask = ~test_mask
        assert_no_tool_overlap(tools[train_mask], tools[test_mask])
        assert held_out not in tools[train_mask].unique()
        assert held_out in tools[test_mask].unique()


def test_leave_one_tool_out_test_set_contains_only_held_out_tool_and_benign():
    X, y, tools = _synthetic_dataset()
    tool_names = sorted(t for t in tools.unique() if t != BENIGN_TOOL_LABEL)
    for held_out in tool_names:
        test_mask = (tools == held_out) | (tools == BENIGN_TOOL_LABEL)
        seen = set(tools[test_mask].unique())
        assert seen == {held_out, BENIGN_TOOL_LABEL}


def test_leave_one_tool_out_raises_on_no_tools():
    X, y, _ = _synthetic_dataset()
    all_benign = pd.Series([BENIGN_TOOL_LABEL] * len(X))
    with pytest.raises(ValueError, match="no non-benign tools"):
        leave_one_tool_out_eval(make_logistic_regression, X, y, all_benign)


def test_leave_one_tool_out_scores_well_on_easy_synthetic_signal():
    X, y, tools = _synthetic_dataset()
    results = leave_one_tool_out_eval(make_logistic_regression, X, y, tools)
    for r in results:
        assert r.accuracy > 0.8, f"{r.name} scored {r.accuracy} on an easy synthetic signal"


def test_summarize_leave_one_tool_out_shape():
    X, y, tools = _synthetic_dataset()
    results = leave_one_tool_out_eval(make_logistic_regression, X, y, tools)
    summary = summarize_leave_one_tool_out(results)
    assert summary["n_folds"] == 3
    assert 0.0 <= summary["min_accuracy"] <= summary["mean_accuracy"] <= summary["max_accuracy"] <= 1.0


# --- random_split_eval ----------------------------------------------------


def test_random_split_eval_returns_named_leaky_result():
    X, y, tools = _synthetic_dataset()
    result = random_split_eval(make_logistic_regression, X, y)
    assert "leaky" in result.name
    assert result.n_train + result.n_test == len(X)


def test_random_split_eval_scores_well_on_easy_synthetic_signal():
    X, y, tools = _synthetic_dataset()
    result = random_split_eval(make_logistic_regression, X, y)
    assert result.accuracy > 0.8


# --- FoldResult -------------------------------------------------------


def test_fold_result_as_row_rounds_metrics():
    X, y, tools = _synthetic_dataset()
    result = random_split_eval(make_logistic_regression, X, y)
    row = result.as_row()
    assert isinstance(row["accuracy"], float)
    assert row["n_train"] == result.n_train
