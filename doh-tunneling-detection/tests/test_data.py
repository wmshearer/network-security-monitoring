"""Tests for src/data.py: the anti-leak guard, and dataset assembly.

Uses small hand-built DataFrames rather than the real CSVs so these run in
under a second and don't depend on the ~800MB dataset being downloaded.
Real-data tests live in test_leak_audit.py and are skipped when the data
isn't present.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from src.data import (
    BEHAVIORAL_FEATURES,
    BENIGN_TOOL_LABEL,
    DROPPED_LEAKY_FEATURES,
    DoHDataset,
)

ALL_COLUMNS = list(DROPPED_LEAKY_FEATURES) + list(BEHAVIORAL_FEATURES)


def _row(label: str, tool: str, **overrides) -> dict:
    row = {c: 1.0 for c in BEHAVIORAL_FEATURES}
    row.update(
        {
            "SourceIP": "192.168.20.1",
            "DestinationIP": "1.1.1.1",
            "SourcePort": 51000,
            "DestinationPort": 443,
            "TimeStamp": "2020/1/1 00:00",
            "label": label,
            "tool": tool,
        }
    )
    row.update(overrides)
    return row


def _dataset(rows: list[dict]) -> DoHDataset:
    return DoHDataset(frame=pd.DataFrame(rows))


# --- the guard the whole methodology depends on ----------------------------


def test_feature_matrix_never_contains_identity_columns():
    """The load-bearing test. If this fails, the anti-leak methodology is
    not actually being enforced in code, only documented.
    """
    ds = _dataset([_row("Benign", BENIGN_TOOL_LABEL), _row("Malicious", "dns2tcp")])
    matrix = ds.feature_matrix()
    for leaky_col in DROPPED_LEAKY_FEATURES:
        assert leaky_col not in matrix.columns, (
            f"LEAK: '{leaky_col}' is present in the training feature matrix. "
            "This column must never reach a model; see src/data.py DROPPED_LEAKY_FEATURES."
        )


def test_feature_matrix_contains_exactly_the_behavioral_columns():
    ds = _dataset([_row("Benign", BENIGN_TOOL_LABEL), _row("Malicious", "iodine")])
    matrix = ds.feature_matrix()
    assert set(matrix.columns) == set(BEHAVIORAL_FEATURES)


def test_dropped_and_behavioral_features_do_not_overlap():
    assert set(DROPPED_LEAKY_FEATURES).isdisjoint(set(BEHAVIORAL_FEATURES))


def test_dropped_leaky_features_is_exactly_the_five_identity_columns():
    # Pinned exactly, not just "contains", so an accidental removal from the
    # constant silently weakening the guard would fail this test.
    assert set(DROPPED_LEAKY_FEATURES) == {
        "SourceIP",
        "DestinationIP",
        "SourcePort",
        "DestinationPort",
        "TimeStamp",
    }


# --- labels and tools --------------------------------------------------


def test_labels_are_binary_malicious_is_one():
    ds = _dataset(
        [
            _row("Benign", BENIGN_TOOL_LABEL),
            _row("Malicious", "dnscat2"),
            _row("Malicious", "tuns"),
        ]
    )
    labels = ds.labels()
    assert set(labels.unique()) <= {0, 1}
    assert labels.tolist() == [0, 1, 1]


def test_tools_preserves_per_row_tool_name():
    ds = _dataset([_row("Benign", BENIGN_TOOL_LABEL), _row("Malicious", "dnstt")])
    assert ds.tools().tolist() == [BENIGN_TOOL_LABEL, "dnstt"]


def test_len_matches_frame_length():
    ds = _dataset([_row("Benign", BENIGN_TOOL_LABEL) for _ in range(5)])
    assert len(ds) == 5


# --- construction validation --------------------------------------------


def test_missing_behavioral_column_raises():
    rows = [_row("Benign", BENIGN_TOOL_LABEL)]
    frame = pd.DataFrame(rows).drop(columns=["PacketLengthVariance"])
    with pytest.raises(ValueError, match="missing expected behavioral columns"):
        DoHDataset(frame=frame)


def test_missing_label_or_tool_column_raises():
    frame = pd.DataFrame([{c: 1.0 for c in BEHAVIORAL_FEATURES}])
    with pytest.raises(ValueError, match="label.*tool"):
        DoHDataset(frame=frame)


def test_feature_matrix_is_a_copy_not_a_view():
    """Mutating the returned matrix must not corrupt the dataset's frame,
    since callers (models, scalers) mutate their input in place routinely.
    """
    ds = _dataset([_row("Benign", BENIGN_TOOL_LABEL)])
    matrix = ds.feature_matrix()
    matrix.iloc[0, 0] = 999999.0
    assert ds.frame.loc[0, BEHAVIORAL_FEATURES[0]] != 999999.0


def test_feature_matrix_handles_nan_free_numeric_data():
    ds = _dataset([_row("Benign", BENIGN_TOOL_LABEL, PacketLengthVariance=np.nan)])
    matrix = ds.feature_matrix()
    # data.py's loader drops NaN rows before construction; DoHDataset itself
    # doesn't refuse them, so this documents that the matrix can carry a NaN
    # through untouched if a caller builds a DoHDataset directly.
    assert matrix["PacketLengthVariance"].isna().all()
