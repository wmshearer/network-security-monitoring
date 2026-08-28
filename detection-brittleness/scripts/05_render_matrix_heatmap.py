#!/usr/bin/env python3
"""Stage 5: render the rule x tool x dataset survival matrix as a real PNG heatmap.

Reads evidence/03_matrix.json (never hand-typed) and plots, for each
technique, one row per rule that fired anywhere and one column per sample
group, coloring survive/miss. Saved to evidence/gui/matrix_heatmap_<tech>.png.
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "evidence" / "03_matrix.json"
OUT_DIR = ROOT / "evidence" / "gui"

GROUP_LABELS = {
    "attack_data_snapattack": "attack_data\n(SnapAttack)",
    "attack_data_atomic_red_team": "attack_data\n(Atomic Red Team)",
    "evtx_attack_samples": "EVTX-ATTACK-\nSAMPLES",
    "evtx_to_mitre_attack": "EVTX-to-\nMITRE-Attack",
}


def render_technique(technique: str, data: dict) -> Path:
    groups = data["group_names"]
    detail = data["detail"]
    rule_ids = sorted(detail.keys(), key=lambda rid: detail[rid]["title"])
    titles = [detail[rid]["title"] for rid in rule_ids]

    grid = np.zeros((len(rule_ids), len(groups)))
    for i, rid in enumerate(rule_ids):
        for j, g in enumerate(groups):
            grid[i, j] = 1 if detail[rid]["counts"].get(g, 0) > 0 else 0

    fig_h = max(3.0, 0.35 * len(rule_ids) + 1.5)
    fig, ax = plt.subplots(figsize=(9, fig_h))

    cmap = matplotlib.colors.ListedColormap(["#e8e2d8", "#2f6f4f"])
    ax.imshow(grid, cmap=cmap, aspect="auto", vmin=0, vmax=1)

    ax.set_xticks(range(len(groups)))
    ax.set_xticklabels([GROUP_LABELS.get(g, g) for g in groups], fontsize=9)
    ax.set_yticks(range(len(titles)))
    ax.set_yticklabels(titles, fontsize=7.5)

    for i in range(len(rule_ids)):
        for j in range(len(groups)):
            n = detail[rule_ids[i]]["counts"].get(groups[j], 0)
            if n > 0:
                ax.text(j, i, str(n), ha="center", va="center", fontsize=7, color="white")

    survivors = data["rules_fired_in_every_group"]
    total = data["rules_fired_at_least_once"]
    ax.set_title(
        f"{technique}: rule x sample-group survival\n"
        f"({survivors} of {total} technique-tagged rules that fired at all survived every independently captured group)",
        fontsize=10,
    )
    ax.set_xlabel("independently captured sample group (real telemetry, unmodified rule)", fontsize=8)

    from matplotlib.patches import Patch
    handles = [Patch(color="#2f6f4f", label="fired (event count shown)"),
               Patch(color="#e8e2d8", label="did not fire")]
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.12 if fig_h < 6 else -0.06),
              ncol=2, fontsize=8, frameon=False)

    fig.tight_layout()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / f"matrix_heatmap_{technique.replace('.', '')}.png"
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out_path


def main() -> None:
    data = json.loads(MATRIX_PATH.read_text())
    for technique, tdata in data.items():
        out = render_technique(technique, tdata)
        print(f"wrote {out}")


if __name__ == "__main__":
    main()
