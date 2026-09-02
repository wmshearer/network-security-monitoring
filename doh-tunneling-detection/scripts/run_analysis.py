#!/usr/bin/env python3
"""Run the full DoH tunneling detection pipeline and print the contrast.

Loads the dataset, drops the identity/session columns, trains a logistic
regression (the headline model) and a random forest (used only for its
feature importances) and reports two numbers side by side:

  1. random-split accuracy -- the number you get from the standard,
     wrong way to evaluate this dataset. Labeled inflated/leaky.
  2. leave-one-tool-out accuracy -- train on two tunneling tools, test on
     a third the model has never seen. Labeled honest.

Writes reports/results.json with the full numbers (both models, both
evaluation methods, per-fold detail, feature importances) so
reports/findings.md can cite exact figures.

Usage:
    .venv/bin/python scripts/run_analysis.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.data import BEHAVIORAL_FEATURES, DROPPED_LEAKY_FEATURES, load_dataset  # noqa: E402
from src.evaluate import (  # noqa: E402
    leave_one_tool_out_eval,
    random_split_eval,
    summarize_leave_one_tool_out,
)
from src.model import feature_importances, fit, make_logistic_regression, make_random_forest  # noqa: E402

DATA_DIR = PROJECT_ROOT / "data"
RESULTS_PATH = PROJECT_ROOT / "reports" / "results.json"


def main() -> None:
    print(f"Loading dataset from {DATA_DIR} ...")
    dataset = load_dataset(DATA_DIR)
    print(f"  {len(dataset)} rows after dropping NaNs")
    print(f"  {int((dataset.labels() == 0).sum())} benign, {int((dataset.labels() == 1).sum())} malicious")
    print(f"  tools: {sorted(t for t in dataset.tools().unique() if t != 'benign')}")

    print(f"\nDROPPED (identity/session, never reach the model): {list(DROPPED_LEAKY_FEATURES)}")
    print(f"KEPT (behavioral, {len(BEHAVIORAL_FEATURES)} features): {list(BEHAVIORAL_FEATURES)}")

    X = dataset.feature_matrix()
    y = dataset.labels()
    tools = dataset.tools()

    results: dict = {
        "dataset": {
            "n_rows": len(dataset),
            "n_benign": int((y == 0).sum()),
            "n_malicious": int((y == 1).sum()),
            "tools": sorted(t for t in tools.unique() if t != "benign"),
        },
        "features": {
            "dropped_leaky": list(DROPPED_LEAKY_FEATURES),
            "kept_behavioral": list(BEHAVIORAL_FEATURES),
        },
        "models": {},
    }

    for model_name, model_fn in [
        ("logistic_regression", make_logistic_regression),
        ("random_forest", make_random_forest),
    ]:
        print(f"\n=== {model_name} ===")

        leaky = random_split_eval(model_fn, X, y)
        print(f"  random split (LEAKY):        accuracy={leaky.accuracy:.4f}  f1={leaky.f1:.4f}")

        loto_folds = leave_one_tool_out_eval(model_fn, X, y, tools)
        for fold in loto_folds:
            print(f"    {fold.name:<24s} accuracy={fold.accuracy:.4f}  f1={fold.f1:.4f}  n_test={fold.n_test}")
        loto_summary = summarize_leave_one_tool_out(loto_folds)
        print(
            f"  leave-one-tool-out (HONEST): mean accuracy={loto_summary['mean_accuracy']:.4f} "
            f"(range {loto_summary['min_accuracy']:.4f}-{loto_summary['max_accuracy']:.4f})"
        )
        gap = leaky.accuracy - loto_summary["mean_accuracy"]
        print(f"  GAP (leaky - honest): {gap:.4f}")

        full_model = fit(model_fn, X, y)
        importances = feature_importances(full_model)
        print("  top 5 behavioral features by importance:")
        for feat, score in importances.head(5).items():
            print(f"    {feat:<40s} {score:.4f}")

        results["models"][model_name] = {
            "random_split_leaky": leaky.as_row(),
            "leave_one_tool_out_folds": [f.as_row() for f in loto_folds],
            "leave_one_tool_out_summary": loto_summary,
            "gap_leaky_minus_honest": round(gap, 4),
            "feature_importances": {k: round(float(v), 6) for k, v in importances.items()},
        }

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(results, indent=2))
    print(f"\nWrote {RESULTS_PATH}")


if __name__ == "__main__":
    main()
