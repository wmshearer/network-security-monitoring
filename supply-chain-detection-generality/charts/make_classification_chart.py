#!/usr/bin/env python3
"""
Render the classification tally (evidence/03_classification_tally.json) as a
horizontal bar chart. Categorical palette slots 1 (blue) and 2 (orange) from
the project's default validated palette, in fixed order (behavioral first,
matching the order it is discussed in FINDINGS.md).

Read-only against evidence/. Writes charts/classification_breakdown.png.
Idempotent.
"""
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
TALLY = ROOT / "evidence" / "03_classification_tally.json"
OUT = ROOT / "charts" / "classification_breakdown.png"

# Validated default palette (see rubric/RUBRIC.md's parent dataviz skill),
# categorical slots 1 and 2, light mode.
BLUE = "#2a78d6"
ORANGE = "#eb6834"
TEXT_PRIMARY = "#0b0b0b"
TEXT_SECONDARY = "#52514e"
SURFACE = "#fcfcfb"


def main():
    if not TALLY.exists():
        print(f"SKIP: {TALLY} not found, run scripts/03_tally_classification.py first", file=sys.stderr)
        sys.exit(0)

    data = json.loads(TALLY.read_text())
    behavioral = data["behavioral"]
    incident_bound = data["incident_bound"]
    total = data["total_detections"]

    labels = ["Behavioral\n(technique-generic)", "Incident-bound\n(one campaign's indicators)"]
    values = [behavioral, incident_bound]
    colors = [BLUE, ORANGE]

    fig, ax = plt.subplots(figsize=(8.5, 3.2), facecolor=SURFACE)
    ax.set_facecolor(SURFACE)

    bars = ax.barh(labels, values, color=colors, height=0.5)

    for bar, val in zip(bars, values):
        pct = round(100 * val / total)
        ax.text(
            bar.get_width() + total * 0.015,
            bar.get_y() + bar.get_height() / 2,
            f"{val} of {total}  ({pct}%)",
            va="center",
            ha="left",
            color=TEXT_PRIMARY,
            fontsize=11,
        )

    ax.set_xlim(0, total * 1.28)
    ax.set_xlabel("Number of detections", color=TEXT_SECONDARY, fontsize=10)
    ax.set_title(
        "Splunk supply chain detections (T1195 family + Sunburst), n=%d" % total,
        color=TEXT_PRIMARY,
        fontsize=12,
        loc="left",
        pad=12,
    )
    ax.tick_params(colors=TEXT_SECONDARY, labelsize=10)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    for spine in ("left", "bottom"):
        ax.spines[spine].set_color(TEXT_SECONDARY)
        ax.spines[spine].set_alpha(0.3)

    fig.tight_layout()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT, dpi=150, facecolor=SURFACE)
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
