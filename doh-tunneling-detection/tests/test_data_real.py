"""Tests that load the real dataset CSVs and check the loader against the
actual published row counts and schema. Skipped if the data isn't present
(it's ~800MB and gitignored; see data/README.md).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.data import BEHAVIORAL_FEATURES, BENIGN_TOOL_LABEL, DROPPED_LEAKY_FEATURES, load_dataset

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _require_data() -> Path:
    if not (DATA_DIR / "l2-total-add.csv").exists() or not (DATA_DIR / "l3-total-add.csv").exists():
        pytest.skip(f"dataset CSVs not present under {DATA_DIR}; see data/README.md")
    return DATA_DIR


def test_load_dataset_matches_published_class_counts():
    data_dir = _require_data()
    ds = load_dataset(data_dir)
    labels = ds.labels()
    n_benign = int((labels == 0).sum())
    n_malicious = int((labels == 1).sum())
    # README.txt: "Normal DoH 19807 and Suspicious DoH 354996" (l2), a
    # handful may be dropped for NaNs in ResponseTimeTime* columns, so
    # this is an upper bound check, not an exact match.
    assert n_benign <= 19807
    assert n_benign > 19807 - 100
    assert n_malicious <= 354996
    assert n_malicious > 354996 - 400


def test_load_dataset_tool_labels_match_published_per_tool_counts():
    data_dir = _require_data()
    ds = load_dataset(data_dir)
    tool_counts = ds.tools().value_counts()
    published = {
        "dns2tcp": 167486,
        "dnscat2": 35770,
        "iodine": 46580,
        "dnstt": 46080,
        "tcp-over-dns": 30040,
        "tuns": 29040,
    }
    for tool, expected in published.items():
        assert tool in tool_counts.index
        # allow a drop for NaN rows in ResponseTimeTime* columns (measured:
        # 283 such rows in l3-total-add.csv, unevenly spread across tools,
        # up to 199 for dns2tcp), so this checks "close to published, never
        # over" rather than an exact match.
        assert tool_counts[tool] <= expected
        assert tool_counts[tool] > expected * 0.995


def test_load_dataset_feature_matrix_has_no_identity_columns():
    data_dir = _require_data()
    ds = load_dataset(data_dir)
    matrix = ds.feature_matrix()
    for col in DROPPED_LEAKY_FEATURES:
        assert col not in matrix.columns


def test_load_dataset_feature_matrix_has_no_nulls():
    data_dir = _require_data()
    ds = load_dataset(data_dir)
    matrix = ds.feature_matrix()
    assert not matrix.isna().any().any()


def test_load_dataset_raises_clear_error_when_files_missing(tmp_path):
    with pytest.raises(FileNotFoundError, match="l2-total-add.csv"):
        load_dataset(tmp_path)


def test_load_dataset_benign_rows_all_carry_benign_tool_label():
    data_dir = _require_data()
    ds = load_dataset(data_dir)
    benign_tools = ds.frame.loc[ds.labels() == 0, "tool"].unique()
    assert list(benign_tools) == [BENIGN_TOOL_LABEL]
