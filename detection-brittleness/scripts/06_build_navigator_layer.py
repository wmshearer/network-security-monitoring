#!/usr/bin/env python3
"""Stage 6: build an ATT&CK Navigator layer showing per-technique survival.

Reads evidence/03_matrix.json (real, already-computed results) and emits a
Navigator layer JSON coloring T1003.001 and T1059.001 by how many of that
technique's technique-tagged rules survived every independently captured
sample group, versus how many fired at all. This is descriptive of THIS
project's own measured result, not a general detection-coverage claim.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "evidence" / "03_matrix.json"
OUT_PATH = ROOT / "evidence" / "gui" / "survival-navigator-layer.json"


def main() -> None:
    matrix = json.loads(MATRIX_PATH.read_text())

    techniques = []
    for tid, data in matrix.items():
        survived = data["rules_fired_in_every_group"]
        fired_at_all = data["rules_fired_at_least_once"]
        pct = 100.0 * survived / fired_at_all if fired_at_all else 0.0
        techniques.append({
            "techniqueID": tid,
            "score": round(pct, 1),
            "comment": (
                f"{survived} of {fired_at_all} technique-tagged Sigma rules that fired at all "
                f"survived every independently captured sample group scored "
                f"({', '.join(data['group_names'])}). Source: detection-brittleness project, "
                f"evidence/03_matrix.json."
            ),
        })

    layer = {
        "name": "Detection rule survival across independent tool executions",
        "versions": {"attack": "15", "navigator": "5.3.2", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            "Percent of technique-tagged Sigma rules (from Zircolite's vendored "
            "rules_windows_merged.json) that fired unmodified against EVERY independently "
            "captured real telemetry sample scored for that technique, out of the rules that "
            "fired against at least one. 0% does not mean no detection exists for the "
            "technique; it means no single rule generalized across all of this project's "
            "sample groups. See FINDINGS.md for the telemetry-absent vs logic-too-narrow "
            "breakdown behind each number."
        ),
        "filters": {"platforms": ["Windows"]},
        "sorting": 3,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#e8e2d8", "#f2d675", "#2f6f4f"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [],
        "metadata": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(layer, indent=2))
    print(f"wrote {OUT_PATH}")
    for t in techniques:
        print(f"  {t['techniqueID']}: score={t['score']}")


if __name__ == "__main__":
    main()
