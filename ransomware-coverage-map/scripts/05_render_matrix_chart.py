#!/usr/bin/env python3
"""Stage 5: render the coverage matrix as a real chart, generated only from
matrix/coverage_matrix.json (never a hand-authored data point).

Rows: MITRE ATT&CK technique IDs. Columns: families (ransomware_ttp last,
visually separated and labelled as a reference bucket, not a real family).

Cell state to color follows the dataviz skill's STATUS palette (a small
fixed scale with reserved meaning, always paired with icon + label, never
color alone), since these are four states of one thing (detection coverage)
rather than four independent categorical series:
  GREEN         status "good"     #0ca30c
  RED-LOGIC     status "critical" #d03b3b
  RED-TELEMETRY status "serious"  #ec835a
  GREY          neutral (outside the status scale, kept muted, never
                 alarming) #d8d6cd, matching the skill's chart-chrome gridline
                 tone rather than a status color, because GREY is not a
                 finding.

Per the skill's rule that a status color never carries meaning alone: EVERY
cell also carries a one-letter glyph (G / L / T / -) INSIDE the cell, so
colorblind readers and grayscale prints get the same information a sighted
color reader gets. RED-LOGIC and RED-TELEMETRY are further distinguished by
hatch pattern (diagonal for RED-LOGIC, cross-hatch for RED-TELEMETRY) so the
two "bad" states are never confused even before reading the glyph.

Low-confidence families (thin, single-file, Sysmon-only captures, from the
manifest's LOW_CONFIDENCE_FAMILIES / matrix's per-family confidence field)
get a dashed column-header border and an explicit "(low confidence)" label
suffix, so a red cell there is visually flagged as weaker evidence before
the reader even reaches the caveat text in FINDINGS.md.
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "matrix" / "coverage_matrix.json"
OUT_PATH = ROOT / "matrix" / "coverage_matrix.png"

STATE_STYLE = {
    "GREEN":         {"color": "#0ca30c", "hatch": None, "glyph": "G"},
    "RED-LOGIC":      {"color": "#d03b3b", "hatch": "///", "glyph": "L"},
    "RED-TELEMETRY":  {"color": "#ec835a", "hatch": "xxx", "glyph": "T"},
    "GREY":           {"color": "#d8d6cd", "hatch": None, "glyph": "–"},  # en dash
}

SURFACE = "#fcfcfb"
INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRIDLINE = "#e1e0d9"


def main() -> None:
    matrix = json.loads(MATRIX_PATH.read_text())
    families = matrix["family_order"]
    techniques = matrix["technique_order"]
    fam_meta = matrix["families"]
    tech_meta = matrix["techniques"]

    n_rows = len(techniques)
    n_cols = len(families)

    fig_w = max(11.5, 2.1 * n_cols + 3.4)
    fig_h = max(7.2, 0.66 * n_rows + 3.0)
    fig, ax = plt.subplots(figsize=(fig_w, fig_h), facecolor=SURFACE)
    ax.set_facecolor(SURFACE)

    for row_i, tech_id in enumerate(techniques):
        y = n_rows - 1 - row_i
        for col_i, fam_name in enumerate(families):
            cell = matrix["cells"][f"{fam_name}|{tech_id}"]
            style = STATE_STYLE[cell["state"]]
            rect = Rectangle(
                (col_i, y), 1, 1,
                facecolor=style["color"], edgecolor=SURFACE, linewidth=2,
                hatch=style["hatch"], hatch_linewidth=0.8,
            )
            ax.add_patch(rect)
            # secondary encoding: a glyph inside every cell so no state
            # depends on color alone (dataviz skill requirement for status
            # colors, since red/green CVD separation fails on its own). Drawn
            # with a small filled circle behind it so the hatch pattern never
            # visually merges with the glyph strokes (observed defect in an
            # earlier draft: "T" became illegible against the cross-hatch).
            glyph_color = "#ffffff" if cell["state"] in ("GREEN", "RED-LOGIC", "RED-TELEMETRY") else INK_SECONDARY
            if style["hatch"]:
                ax.add_patch(plt.Circle((col_i + 0.5, y + 0.5), 0.24, facecolor=style["color"], edgecolor="none", zorder=3))
            ax.text(col_i + 0.5, y + 0.5, style["glyph"], ha="center", va="center",
                     fontsize=14, fontweight="bold", color=glyph_color, family="monospace", zorder=4)

    # column headers: family name on its own row, caveat directly below on a
    # SEPARATE fixed row (not appended into the same wrapped string), so
    # adjacent columns' multi-line labels never visually interleave (an
    # earlier draft embedded "\n(low confidence...)" in the same text() call
    # per column, which strung labels into overlapping runs since each
    # column's text still shares the same baseline but Matplotlib's default
    # line spacing pushed neighbours together at this column width).
    for col_i, fam_name in enumerate(families):
        meta = fam_meta[fam_name]
        label = fam_name.replace("_ransomware", "").replace("_", " ")
        ax.text(col_i + 0.5, n_rows + 1.0, label, ha="center", va="bottom",
                 fontsize=10, color=INK_PRIMARY,
                 fontweight="bold" if not meta["is_reference_bucket"] else "normal")
        if meta["is_reference_bucket"]:
            caveat = "reference bucket,\nnot a family"
        elif meta["confidence"] == "LOW":
            caveat = "low confidence:\nthin capture"
        else:
            caveat = ""
        if caveat:
            ax.text(col_i + 0.5, n_rows + 0.95, caveat, ha="center", va="top",
                     fontsize=6.6, color=INK_MUTED, linespacing=1.3)
        if meta["is_reference_bucket"]:
            ax.add_patch(Rectangle((col_i, -1.2), 1, n_rows + 1.2, fill=False,
                                    edgecolor=INK_MUTED, linestyle=(0, (4, 2)), linewidth=1.4))

    # row headers (technique id + short name)
    for row_i, tech_id in enumerate(techniques):
        y = n_rows - 1 - row_i
        name = tech_meta[tech_id]["name"]
        ax.text(-0.15, y + 0.5, f"{tech_id}", ha="right", va="center",
                 fontsize=10, fontweight="bold", color=INK_PRIMARY, family="monospace")
        ax.text(-0.15, y + 0.15, name, ha="right", va="center",
                 fontsize=6.6, color=INK_MUTED)

    ax.set_xlim(-4.4, n_cols)
    ax.set_ylim(-1.5, n_rows + 1.8)
    ax.set_aspect("equal")
    ax.axis("off")

    counts = matrix["state_counts"]
    title = "Ransomware detection coverage: technique x family"
    subtitle = (
        f"GREEN={counts['GREEN']} (covered)   RED-LOGIC={counts['RED-LOGIC']} (detection exists, "
        f"its own literals do not match this capture)   RED-TELEMETRY={counts['RED-TELEMETRY']} "
        f"(behaviour occurred, Splunk ships no detection for it here)   "
        f"GREY={counts['GREY']} (behaviour not observed in this capture, no claim possible)"
    )
    ax.text(-4.4, n_rows + 1.7, title, ha="left", va="bottom", fontsize=14, fontweight="bold", color=INK_PRIMARY)
    ax.text(-4.4, -0.65, subtitle, ha="left", va="top", fontsize=7.6, color=INK_SECONDARY, wrap=True)

    fig.tight_layout()
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT_PATH, dpi=170, facecolor=SURFACE)
    print(f"wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
