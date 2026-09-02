"""A small, explainable classifier for benign-vs-tunneled DoH traffic.

The detection question is deliberately simple: given only the behavioral
shape of a DoH flow (packet-size stats, timing stats, byte rates), does it
look like ordinary DNS-over-HTTPS or a tunnel wrapped inside it? This is
not a place for a black-box model. A logistic regression (or a shallow
random forest, used here for the feature-importance view) lets every
result be traced back to which features actually carried the signal,
which matters more than squeezing out another point of accuracy.

Uses scikit-learn, installed into a project-local virtualenv
(`.venv/`) because scikit-learn is not available in the system Python on
this host. See data/README.md for how to recreate the environment.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# Fixed so every run (and every test) sees the same splits and the same
# random forest. Not tuned for a better number; tuned would defeat the
# point of a fixed, auditable seed.
RANDOM_STATE = 42

# Trees kept modest on purpose. This is a feature-importance tool sitting
# next to an explainable linear model, not a competition entry: a forest
# this size is still fast to retrain per fold and gives stable importances.
RANDOM_FOREST_TREES = 200


@dataclass(frozen=True)
class TrainedModel:
    """A fitted classifier plus the feature names it was trained on, so
    predictions and importances can always be traced back to a column name.
    """

    pipeline: Pipeline
    feature_names: tuple[str, ...]

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        return self.pipeline.predict(X[list(self.feature_names)])

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        return self.pipeline.predict_proba(X[list(self.feature_names)])[:, 1]


def make_logistic_regression() -> Pipeline:
    """Standardize then fit logistic regression.

    Standardization matters here specifically because the behavioral
    features are on wildly different scales (byte counts in the tens of
    thousands next to skew values near 0), and an unscaled logistic
    regression would let the raw magnitude of a feature stand in for its
    actual importance.
    """
    return Pipeline(
        [
            ("scale", StandardScaler()),
            (
                "clf",
                LogisticRegression(
                    max_iter=2000,
                    class_weight="balanced",
                    random_state=RANDOM_STATE,
                ),
            ),
        ]
    )


def make_random_forest() -> Pipeline:
    """A shallow-ish random forest, used for its feature_importances_.

    class_weight="balanced" because malicious rows outnumber benign rows
    roughly 18 to 1 in this dataset; without it the forest could get a high
    accuracy number by mostly predicting malicious.
    """
    return Pipeline(
        [
            (
                "clf",
                RandomForestClassifier(
                    n_estimators=RANDOM_FOREST_TREES,
                    max_depth=12,
                    class_weight="balanced",
                    random_state=RANDOM_STATE,
                    n_jobs=-1,
                ),
            )
        ]
    )


def fit(model_fn, X: pd.DataFrame, y: pd.Series) -> TrainedModel:
    pipeline = model_fn()
    pipeline.fit(X, y)
    return TrainedModel(pipeline=pipeline, feature_names=tuple(X.columns))


def feature_importances(model: TrainedModel) -> pd.Series:
    """Per-feature importance, regardless of whether the underlying model
    is the logistic regression or the random forest.

    Logistic regression: absolute value of the standardized coefficient.
    Since features were standardized before fitting, coefficient magnitude
    is directly comparable across features and reflects how much moving a
    feature by one standard deviation shifts the decision, not how large
    the feature's raw units happen to be.

    Random forest: sklearn's built-in impurity-based `feature_importances_`.
    """
    clf = model.pipeline.named_steps["clf"]
    if hasattr(clf, "feature_importances_"):
        values = clf.feature_importances_
    elif hasattr(clf, "coef_"):
        values = np.abs(clf.coef_[0])
    else:
        raise TypeError(f"don't know how to extract importances from {type(clf)}")
    return pd.Series(values, index=model.feature_names).sort_values(ascending=False)
