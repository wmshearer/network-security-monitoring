"""Two ways to measure the same classifier, one honest and one not.

RANDOM SPLIT (the leaky number)
-------------------------------------------------------------------------------
A standard train/test split drawn uniformly at random from all rows. This
is the default almost everyone reaches for, and it is the wrong tool for
this dataset: because each capture session used its own fixed client IPs
(see src/data.py's module docstring, and the disjoint-IP check in
src/leak_audit.py), a random split puts rows from every session into both
train and test. Even with SourceIP/DestinationIP/SourcePort/
DestinationPort/TimeStamp dropped before training, the model still trains
and tests on flows from the SAME capture sessions, so any session-specific
artifact that survives in the behavioral features (a particular router's
MTU, a particular server's response-time floor, anything tied to "this
capture" rather than "this tool") can leak across the split. The random
split number is reported here for contrast only, explicitly labeled as
inflated, never as the headline result.

LEAVE-ONE-TOOL-OUT (the honest number)
-------------------------------------------------------------------------------
Train on flows from two tunneling tools, test on flows from the third,
which the model has never seen a single example of. This is the real-world
question a detector actually has to answer: not "can you recognize a tool
you were trained on", but "does whatever you learned about tunneling
generalize to a tool you haven't seen." There is only one benign class, so
there's no tool axis to hold it out by; instead a fixed 30% of benign rows
is set aside for testing in every fold (same split every time), and the
rest is available for training. Only the malicious side changes fold to
fold, which is what isolates generalization-to-an-unseen-tool as the one
variable. Accuracy on a held-out tool is expected to be lower than the
random-split number, and a large drop is not a bug in the evaluation, it
is the finding: it means the random-split number was measuring session
memorization, not tunneling detection.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from src.data import BENIGN_TOOL_LABEL
from src.model import RANDOM_STATE, TrainedModel, fit

# Fraction of rows held out for the random-split contrast number.
RANDOM_SPLIT_TEST_SIZE = 0.3

# There is only one benign class, so leave-one-tool-out has nothing to hold
# it out BY: every fold needs some benign rows on the train side (or the
# model never sees what normal DoH looks like) and some on the test side
# (or precision/recall on the held-out tool can't be scored against a
# negative class). This is the fraction of benign rows put in each fold's
# test set; the rest go to train. It has no relationship to the tool split
# itself, and it's the same 30% used for the random-split contrast so the
# two numbers aren't being computed on differently-sized benign pools.
BENIGN_TEST_FRACTION = 0.3


@dataclass(frozen=True)
class FoldResult:
    """Metrics from one evaluation split (either the random split, or one
    leave-one-tool-out fold).
    """

    name: str
    n_train: int
    n_test: int
    accuracy: float
    precision: float
    recall: float
    f1: float

    def as_row(self) -> dict:
        return {
            "name": self.name,
            "n_train": self.n_train,
            "n_test": self.n_test,
            "accuracy": round(self.accuracy, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


def _score(model: TrainedModel, X_test: pd.DataFrame, y_test: pd.Series) -> tuple[float, float, float, float]:
    y_pred = model.predict(X_test)
    return (
        accuracy_score(y_test, y_pred),
        precision_score(y_test, y_pred, zero_division=0),
        recall_score(y_test, y_pred, zero_division=0),
        f1_score(y_test, y_pred, zero_division=0),
    )


def random_split_eval(model_fn, X: pd.DataFrame, y: pd.Series) -> FoldResult:
    """The leaky number: a uniformly random train/test split.

    Stratified on the label so both splits keep the same (heavily
    imbalanced) class ratio; stratification affects only how the split is
    drawn, not the leakage problem described in the module docstring.
    """
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=RANDOM_SPLIT_TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    model = fit(model_fn, X_train, y_train)
    acc, prec, rec, f1 = _score(model, X_test, y_test)
    return FoldResult(
        name="random_split (leaky)",
        n_train=len(X_train),
        n_test=len(X_test),
        accuracy=acc,
        precision=prec,
        recall=rec,
        f1=f1,
    )


def leave_one_tool_out_eval(
    model_fn, X: pd.DataFrame, y: pd.Series, tools: pd.Series
) -> list[FoldResult]:
    """One fold per malicious tool: train on the other tools plus most
    benign rows, test on the held-out tool plus a benign sample the model
    never trained on.

    Benign rows are split BENIGN_TEST_FRACTION/rest between test and train
    for every fold, using the same fixed random state each time so every
    fold sees the same benign train/test partition. Only the malicious
    side changes fold to fold, which is what isolates "does this
    generalize to an unseen tool" as the one thing varying between folds.
    """
    tool_names = sorted(t for t in tools.unique() if t != BENIGN_TOOL_LABEL)
    if not tool_names:
        raise ValueError("no non-benign tools found in `tools`; cannot run leave-one-tool-out")

    benign_idx = tools.index[tools == BENIGN_TOOL_LABEL]
    if len(benign_idx) == 0:
        raise ValueError("no benign rows found in `tools`; cannot score against a negative class")
    benign_train_idx, benign_test_idx = train_test_split(
        benign_idx, test_size=BENIGN_TEST_FRACTION, random_state=RANDOM_STATE
    )
    benign_train_idx = set(benign_train_idx)
    benign_test_idx = set(benign_test_idx)

    results = []
    for held_out in tool_names:
        held_out_idx = set(tools.index[tools == held_out])
        other_tool_idx = set(tools.index[(tools != held_out) & (tools != BENIGN_TOOL_LABEL)])

        train_idx = sorted(other_tool_idx | benign_train_idx)
        test_idx = sorted(held_out_idx | benign_test_idx)

        X_train, y_train = X.loc[train_idx], y.loc[train_idx]
        X_test, y_test = X.loc[test_idx], y.loc[test_idx]

        assert_no_tool_overlap(tools.loc[train_idx], tools.loc[test_idx])

        model = fit(model_fn, X_train, y_train)
        acc, prec, rec, f1 = _score(model, X_test, y_test)
        results.append(
            FoldResult(
                name=f"leave_out={held_out}",
                n_train=len(X_train),
                n_test=len(X_test),
                accuracy=acc,
                precision=prec,
                recall=rec,
                f1=f1,
            )
        )
    return results


def summarize_leave_one_tool_out(results: list[FoldResult]) -> dict:
    """Mean and range across folds, the numbers that belong in a headline."""
    accuracies = np.array([r.accuracy for r in results])
    return {
        "mean_accuracy": round(float(accuracies.mean()), 4),
        "min_accuracy": round(float(accuracies.min()), 4),
        "max_accuracy": round(float(accuracies.max()), 4),
        "n_folds": len(results),
    }


def assert_no_tool_overlap(train_tools: pd.Series, test_tools: pd.Series) -> None:
    """Guard used by both the harness and the tests: a held-out tool must
    never also appear in the training set.

    Benign rows are exempt (BENIGN_TOOL_LABEL is expected on both sides,
    since there is only one benign class and nothing to hold it out from).
    """
    train_set = set(train_tools.unique()) - {BENIGN_TOOL_LABEL}
    test_set = set(test_tools.unique()) - {BENIGN_TOOL_LABEL}
    overlap = train_set & test_set
    if overlap:
        raise AssertionError(
            f"leave-one-tool-out violated: tool(s) {overlap} appear in both train and test"
        )
