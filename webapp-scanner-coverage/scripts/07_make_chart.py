#!/usr/bin/env python3
"""Build the coverage-by-category chart from evidence/scoring/coverage_by_category.csv.

Horizontal stacked bar: for each Juice Shop category, how many of its
challenges were found by an automated scanner, found only by manual testing,
or found by neither. Categories ordered by total challenge count (largest at
top), matching the manifest breakdown already reported.
"""
import csv
from pathlib import Path

import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
IN_CSV = ROOT / "evidence" / "scoring" / "coverage_by_category.csv"
OUT_PNG = ROOT / "charts" / "coverage_by_category.png"

# Palette from the dataviz skill's validated default (light mode).
COLOR_AUTOMATED = "#2a78d6"  # categorical slot 1, blue
COLOR_MANUAL = "#008300"  # categorical slot 6, green
COLOR_NEITHER = "#d8d6d0"  # neutral gray, not a categorical identity, an absence state
TEXT_COLOR = "#0b0b0b"
TEXT_SECONDARY = "#52514e"


def main() -> int:
    rows = []
    with open(IN_CSV) as f:
        for row in csv.DictReader(f):
            rows.append(row)

    # Already ordered largest-total-first by the scoring script; keep that
    # order but reverse for barh, which draws bottom-to-top.
    rows = list(reversed(rows))

    categories = [r["category"] for r in rows]
    automated = [int(r["found_by_automated_scanner"]) for r in rows]
    manual = [int(r["found_by_manual_only"]) for r in rows]
    neither = [int(r["found_by_neither"]) for r in rows]

    fig, ax = plt.subplots(figsize=(9, 6.5), dpi=200)
    fig.patch.set_facecolor("#fcfcfb")
    ax.set_facecolor("#fcfcfb")

    y = range(len(categories))
    ax.barh(y, automated, color=COLOR_AUTOMATED, label="Found by automated scanner (ZAP or nuclei)", height=0.65)
    ax.barh(y, manual, left=automated, color=COLOR_MANUAL, label="Found only by manual testing (Burp)", height=0.65)
    left2 = [a + m for a, m in zip(automated, manual)]
    ax.barh(y, neither, left=left2, color=COLOR_NEITHER, label="Found by neither", height=0.65)

    ax.set_yticks(list(y))
    ax.set_yticklabels(categories, color=TEXT_COLOR, fontsize=10)
    ax.set_xlabel("Challenges in category", color=TEXT_SECONDARY, fontsize=10)
    ax.set_title(
        "Juice Shop challenge coverage by category (116 challenges, 3 scanners)",
        color=TEXT_COLOR,
        fontsize=12,
        loc="left",
        pad=14,
    )

    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_color(TEXT_SECONDARY)
    ax.tick_params(axis="x", colors=TEXT_SECONDARY)
    ax.tick_params(axis="y", length=0)
    ax.xaxis.grid(True, color="#e5e3dc", linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)

    # Direct labels only where a segment is non-zero and would otherwise be
    # invisible against the gray (the two real hits).
    for i, (a, m) in enumerate(zip(automated, manual)):
        if a:
            ax.text(a / 2, i, str(a), ha="center", va="center", color="white", fontsize=9, fontweight="bold")
        if m:
            ax.text(a + m / 2, i, str(m), ha="center", va="center", color="white", fontsize=9, fontweight="bold")

    ax.legend(
        loc="lower right",
        frameon=False,
        fontsize=9,
        labelcolor=TEXT_COLOR,
    )

    fig.tight_layout()
    OUT_PNG.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT_PNG, facecolor=fig.get_facecolor())
    print(f"Wrote {OUT_PNG}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
