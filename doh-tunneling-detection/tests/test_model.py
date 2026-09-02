"""Tests for src/model.py: fitting and feature-importance extraction."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from src.model import (
    RANDOM_STATE,
    feature_importances,
    fit,
    make_logistic_regression,
    make_random_forest,
)


def _separable_frame(seed: int = 0, n: int = 200) -> tuple[pd.DataFrame, pd.Series]:
    rng = np.random.default_rng(seed)
    n0, n1 = n // 2, n - n // 2
    signal = np.concatenate([rng.normal(0, 0.3, n0), rng.normal(3, 0.3, n1)])
    noise = rng.normal(0, 1, n)
    X = pd.DataFrame({"signal": signal, "noise": noise})
    y = pd.Series([0] * n0 + [1] * n1)
    return X, y


@pytest.mark.parametrize("model_fn", [make_logistic_regression, make_random_forest])
def test_fit_returns_model_with_matching_feature_names(model_fn):
    X, y = _separable_frame()
    model = fit(model_fn, X, y)
    assert model.feature_names == ("signal", "noise")


@pytest.mark.parametrize("model_fn", [make_logistic_regression, make_random_forest])
def test_predict_separates_an_easy_signal(model_fn):
    X, y = _separable_frame()
    model = fit(model_fn, X, y)
    preds = model.predict(X)
    accuracy = (preds == y.to_numpy()).mean()
    assert accuracy > 0.9


@pytest.mark.parametrize("model_fn", [make_logistic_regression, make_random_forest])
def test_predict_proba_is_between_zero_and_one(model_fn):
    X, y = _separable_frame()
    model = fit(model_fn, X, y)
    proba = model.predict_proba(X)
    assert proba.min() >= 0.0
    assert proba.max() <= 1.0


@pytest.mark.parametrize("model_fn", [make_logistic_regression, make_random_forest])
def test_feature_importances_ranks_the_informative_feature_first(model_fn):
    X, y = _separable_frame()
    model = fit(model_fn, X, y)
    importances = feature_importances(model)
    assert importances.index[0] == "signal"


def test_feature_importances_covers_every_feature_exactly_once():
    X, y = _separable_frame()
    model = fit(make_logistic_regression, X, y)
    importances = feature_importances(model)
    assert set(importances.index) == {"signal", "noise"}
    assert len(importances) == 2


def test_fit_is_deterministic_given_fixed_random_state():
    X, y = _separable_frame()
    model_a = fit(make_logistic_regression, X, y)
    model_b = fit(make_logistic_regression, X, y)
    proba_a = model_a.predict_proba(X)
    proba_b = model_b.predict_proba(X)
    assert np.allclose(proba_a, proba_b)


def test_random_state_constant_is_fixed_not_left_to_default():
    # Documents the design intent: reruns and tests must be reproducible.
    assert isinstance(RANDOM_STATE, int)
