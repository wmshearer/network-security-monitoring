#!/usr/bin/env python3
"""Generate the per-engine capability chart from evidence/19_capability_matrix_source.json.

Every cell's status and note comes from that JSON file, which itself cites
the evidence file each claim was drawn from (see the file's own comments
and FINDINGS.md for the full trace). This script only lays the data out;
it does not invent or adjust any value.

Status colors are the fixed status ramp from the project's dataviz
skill (good/warning/serious/critical), reserved for state and never reused
as a categorical series color. Every cell also carries a text label
(never color alone), per that skill's accessibility rule.
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "evidence" / "19_capability_matrix_source.json"
OUT = ROOT / "evidence" / "gui" / "06_engine_capability_chart.png"

STATUS_COLOR = {
    "native": "#0ca30c",       # good
    "workaround": "#fab219",   # warning
    "wrong": "#d03b3b",        # critical
    "impossible": "#ec835a",   # serious
}
STATUS_ICON = {
    "native": "OK",
    "workaround": "~",
    "wrong": "X!",
    "impossible": "X",
}
STATUS_LABEL = {
    "native": "native",
    "workaround": "workaround",
    "wrong": "SILENT WRONG",
    "impossible": "impossible",
}


def main() -> int:
    data = json.loads(SOURCE.read_text())
    capabilities = data["capabilities"]
    cap_labels = data["capability_labels"]
    engines = data["engines"]
    engine_keys = list(engines.keys())

    n_rows = len(engine_keys)
    n_cols = len(capabilities)

    fig, ax = plt.subplots(figsize=(2.9 * n_cols + 2.2, 1.7 * n_rows + 2.4))
    ax.set_xlim(-0.2, n_cols)
    ax.set_ylim(-1.4, n_rows + 1.0)
    ax.invert_yaxis()
    ax.axis("off")

    surface = "#ffffff"
    fig.patch.set_facecolor(surface)
    ax.set_facecolor(surface)

    for row, ekey in enumerate(engine_keys):
        engine = engines[ekey]
        ax.text(
            -0.15, row + 0.5, engine["label"],
            ha="right", va="center", fontsize=12, fontweight="bold",
            color="#1a1a19",
        )
        for col, cap in enumerate(capabilities):
            cell = engine.get(cap)
            gap = 0.04
            rect = Rectangle(
                (col + gap, row + gap), 1 - 2 * gap, 1 - 2 * gap,
                linewidth=0,
            )
            if cell is None:
                rect.set_facecolor("#e5e5e3")
                ax.add_patch(rect)
                ax.text(
                    col + 0.5, row + 0.5, "n/a",
                    ha="center", va="center", fontsize=10, color="#6b6b68",
                )
                continue
            status = cell["status"]
            color = STATUS_COLOR[status]
            rect.set_facecolor(color)
            rect.set_alpha(0.85)
            ax.add_patch(rect)
            icon = STATUS_ICON[status]
            label = STATUS_LABEL[status]
            ax.text(
                col + 0.5, row + 0.38, icon,
                ha="center", va="center", fontsize=13, fontweight="bold",
                color="#1a1a19",
            )
            ax.text(
                col + 0.5, row + 0.68, label,
                ha="center", va="center", fontsize=9.5, color="#1a1a19",
            )

    import textwrap

    for col, cap in enumerate(capabilities):
        wrapped = "\n".join(textwrap.wrap(cap_labels[cap], width=22))
        ax.text(
            col + 0.5, -0.15, wrapped,
            ha="center", va="bottom", fontsize=9.5, color="#1a1a19",
        )

    ax.text(
        n_cols / 2 - 0.1, -1.5,
        "T1558.003 Kerberoasting: what each detection engine expresses,\n"
        "and where it silently produces a different result",
        ha="center", va="top", fontsize=14, fontweight="bold", color="#1a1a19",
    )

    legend_y = n_rows + 0.5
    legend_x_start = 0
    for i, status in enumerate(["native", "workaround", "wrong", "impossible"]):
        lx = legend_x_start + i * (n_cols / 4)
        ax.add_patch(Rectangle((lx, legend_y), 0.3, 0.3, color=STATUS_COLOR[status], alpha=0.85))
        ax.text(
            lx + 0.4, legend_y + 0.15, STATUS_LABEL[status],
            ha="left", va="center", fontsize=10, color="#1a1a19",
        )

    fig.subplots_adjust(left=0.18, right=0.98, top=0.88, bottom=0.02)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT, dpi=150, facecolor=surface)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
