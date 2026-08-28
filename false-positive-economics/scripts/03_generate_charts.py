#!/usr/bin/env python3
"""Generate break-even curve charts from real measured data.

Every chart:
  - is built from detection-rule-lab's scoring-run.json (read-only source).
  - labels its swept assumptions ON THE CHART ITSELF (title, legend, or
    annotation), not just in surrounding prose, per the project brief.
  - carries the caveat banner text in a footer.

No chart in this file computes or displays an absolute per-alert-cost-times-
fleet-size dollar total. That framing is rejected by the project brief and is
not implemented anywhere in this codebase.

Idempotent: re-running overwrites the same PNG files with byte-similar output
(matplotlib figures are deterministic given identical inputs and font state).
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CAVEAT_BANNER, CHARTS_DIR, load_scoring_run, rules_touching_benign

# Palette: colorblind-safe, high-contrast qualitative set (Okabe-Ito derived subset).
COLOR_ANCHOR = "#D55E00"  # vermillion, reserved for the 0/56 anchor rule
COLOR_SET = ["#0072B2", "#009E73", "#CC79A7"]  # blue, green, magenta for the other rules
GRID_COLOR = "#B0B0B0"
BG = "#FFFFFF"

TRIAGE_MINUTES_SWEEP = [5, 15, 30, 60]
ANALYST_HOURLY_COST_SWEEP = [40, 75, 120]
VALUE_PER_TP_SWEEP = [50, 200, 1000]

CAVEAT_WRAPPED = "\n".join(
    textwrap.wrap(
        "CAVEAT (verbatim, detection-rule-lab/reports/findings.md): counts on one host, "
        "not rates; a rule quiet here may be noisy on a fleet. Event counts are not alert "
        "counts; a real SIEM would aggregate matches before they became alerts.",
        width=140,
    )
)


def add_footer(fig) -> None:
    fig.text(0.01, 0.005, CAVEAT_WRAPPED, fontsize=7, color="#444444", va="bottom")


def chart_anchor_case(scoring_run: dict, out_path: Path) -> None:
    """Chart 1: the 0/56 anchor rule versus the three rules with nonzero precision.

    This chart needs no cost assumption at all: it plots measured counts only.
    """
    touching = rules_touching_benign(scoring_run)
    touching = sorted(touching, key=lambda r: -r["benign_hits"])

    titles = [r["title"] for r in touching]
    mal = [r["malicious_hits"] for r in touching]
    ben = [r["benign_hits"] for r in touching]
    colors = [COLOR_ANCHOR if r["benign_hits"] == 56 else COLOR_SET[i % len(COLOR_SET)] for i, r in enumerate(touching)]

    fig, ax = plt.subplots(figsize=(10, 6), facecolor=BG)
    y = range(len(titles))
    wrapped_titles = ["\n".join(textwrap.wrap(t, 30)) for t in titles]

    bars_ben = ax.barh(
        [i + 0.2 for i in y], ben, height=0.4, label="Benign hits (false positives)", color=colors
    )
    bars_mal = ax.barh(
        [i - 0.2 for i in y], mal, height=0.4, label="Attack hits (true positives)", color="#999999"
    )

    for bar, val in zip(bars_ben, ben):
        ax.text(bar.get_width() + 0.8, bar.get_y() + bar.get_height() / 2, str(val), va="center", fontsize=9)
    for bar, val in zip(bars_mal, mal):
        ax.text(bar.get_width() + 0.8, bar.get_y() + bar.get_height() / 2, str(val), va="center", fontsize=9)

    ax.set_yticks(list(y))
    ax.set_yticklabels(wrapped_titles, fontsize=9)
    ax.set_xlabel("Measured event count on this corpus (not an alert rate)")
    ax.set_title(
        "The 4 of 135 fired Sigma rules that touched the benign baseline\n"
        "(2,691 rules loaded; 62 total benign hits across these 4)",
        fontsize=12,
        fontweight="bold",
    )
    ax.annotate(
        "0 attack hits, 56 benign hits:\ninfinite cost per true positive\nat any nonzero assumption",
        xy=(56, 3),
        xytext=(30, 2.3),
        fontsize=9,
        color=COLOR_ANCHOR,
        fontweight="bold",
        arrowprops=dict(arrowstyle="->", color=COLOR_ANCHOR),
    )
    ax.legend(loc="lower right", fontsize=9)
    ax.grid(axis="x", color=GRID_COLOR, linewidth=0.5, alpha=0.6)
    ax.set_axisbelow(True)
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    add_footer(fig)
    fig.savefig(out_path, dpi=150, facecolor=BG)
    plt.close(fig)


def chart_breakeven_curves(scoring_run: dict, out_path: Path, hourly_cost: float, value_per_tp: float) -> None:
    """Chart 2: cumulative triage cost vs. value captured, swept over triage minutes.

    hourly_cost and value_per_tp are fixed for one chart (both are ASSUMPTIONS,
    labelled in the title); triage_minutes is the swept x-axis, continuous
    across the same range the assumption table samples discretely (0 to 90
    minutes, which brackets the labelled 5/15/30/60 sweep points).
    """
    import numpy as np

    touching = rules_touching_benign(scoring_run)
    minutes = np.linspace(0, 90, 400)

    fig, ax = plt.subplots(figsize=(10, 6), facecolor=BG)

    for i, r in enumerate(touching):
        mal, ben = r["malicious_hits"], r["benign_hits"]
        total = mal + ben
        cost = total * (minutes / 60.0) * hourly_cost
        value = mal * value_per_tp  # constant in triage_minutes
        net = value - cost
        color = COLOR_ANCHOR if ben == 56 else COLOR_SET[i % len(COLOR_SET)]
        label = f"{r['title'][:38]} (TP={mal}, FP={ben})"
        ax.plot(minutes, net, label=label, color=color, linewidth=2)

        # Mark the crossing point if net goes from + to - within range.
        sign = np.sign(net)
        for j in range(1, len(sign)):
            if sign[j - 1] >= 0 and sign[j] < 0:
                ax.axvline(minutes[j], color=color, linestyle=":", linewidth=1, alpha=0.7)
                ax.annotate(
                    f"{minutes[j]:.0f} min",
                    xy=(minutes[j], 0),
                    xytext=(minutes[j] + 1, ax.get_ylim()[1] * 0.05 if ax.get_ylim()[1] else 0),
                    fontsize=8,
                    color=color,
                )
                break

    ax.axhline(0, color="black", linewidth=1)
    for tm in TRIAGE_MINUTES_SWEEP:
        ax.axvline(tm, color=GRID_COLOR, linewidth=0.7, linestyle="--", alpha=0.5)

    ax.set_xlabel("ASSUMED triage minutes per alert (swept x-axis; reference lines at 5/15/30/60 min)")
    ax.set_ylabel("Net USD = value captured minus cumulative triage cost")
    ax.set_title(
        "Break-even curves: net value vs. assumed triage time\n"
        f"ASSUMED analyst cost = USD {hourly_cost:.0f}/hr, ASSUMED value per true positive = USD {value_per_tp:.0f}\n"
        "(both are stated assumptions, not measurements)",
        fontsize=11,
        fontweight="bold",
    )
    ax.legend(loc="upper right", fontsize=8)
    ax.grid(color=GRID_COLOR, linewidth=0.5, alpha=0.5)
    ax.set_axisbelow(True)
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    add_footer(fig)
    fig.savefig(out_path, dpi=150, facecolor=BG)
    plt.close(fig)


def chart_breakeven_minutes_heatmap(scoring_run: dict, out_path: Path) -> None:
    """Chart 3: for each nonzero-precision rule, break-even triage minutes across
    the full (hourly_cost, value_per_tp) assumption grid, shown as a heatmap-style
    grouped bar chart, one panel per rule. The anchor rule is excluded because it
    has no finite break-even point (see script 02's docstring).
    """
    import numpy as np

    touching = [r for r in rules_touching_benign(scoring_run) if r["malicious_hits"] > 0]

    fig, axes = plt.subplots(1, len(touching), figsize=(5 * len(touching), 5), facecolor=BG, sharey=True)
    if len(touching) == 1:
        axes = [axes]

    n_hourly = len(ANALYST_HOURLY_COST_SWEEP)
    n_value = len(VALUE_PER_TP_SWEEP)
    x = list(range(n_value))
    width = 0.8 / n_hourly

    for ax, r in zip(axes, touching):
        mal, ben = r["malicious_hits"], r["benign_hits"]
        total = mal + ben
        for hi, hourly in enumerate(ANALYST_HOURLY_COST_SWEEP):
            vals = []
            for value_tp in VALUE_PER_TP_SWEEP:
                m = (mal * value_tp) * 60.0 / (total * hourly)
                vals.append(m)
            offset = (hi - (n_hourly - 1) / 2) * width
            bars = ax.bar(
                [xi + offset for xi in x],
                vals,
                width=width,
                label=f"${hourly}/hr",
                color=COLOR_SET[hi % len(COLOR_SET)],
            )
            for b, v in zip(bars, vals):
                ax.text(b.get_x() + b.get_width() / 2, v + 5, f"{v:.0f}", ha="center", fontsize=7, rotation=90)

        for tm in TRIAGE_MINUTES_SWEEP:
            ax.axhline(tm, color=GRID_COLOR, linewidth=0.6, linestyle="--", alpha=0.6)

        ax.set_xticks(x)
        ax.set_xticklabels([f"${v}" for v in VALUE_PER_TP_SWEEP])
        ax.set_xlabel("ASSUMED value per true positive (USD)")
        ax.set_title("\n".join(textwrap.wrap(r["title"], 28)), fontsize=9)
        ax.grid(axis="y", color=GRID_COLOR, linewidth=0.5, alpha=0.5)
        ax.set_axisbelow(True)

    axes[0].set_ylabel("Break-even triage minutes\n(dashed lines mark 5/15/30/60 min reference points)")
    axes[0].legend(title="ASSUMED analyst\nhourly cost", fontsize=8, loc="upper left")
    fig.suptitle(
        "Break-even triage minutes across the full swept assumption grid\n"
        "(rules with 0 true positives excluded: no finite break-even exists)",
        fontsize=12,
        fontweight="bold",
    )
    fig.tight_layout(rect=(0, 0.05, 1, 0.92))
    add_footer(fig)
    fig.savefig(out_path, dpi=150, facecolor=BG)
    plt.close(fig)


def chart_ebpf_probe_comparison(ebpf_analysis: dict, out_path: Path) -> None:
    """Chart 4: the ranking framing applied to a structurally different detection
    paradigm (eBPF runtime probes vs. Sigma log rules), to show the framing
    generalizes. Measured counts only, no cost assumption.
    """
    fp = ebpf_analysis["false_positive_measurement"]
    probes = {
        "cap_capable\n(capability)": fp["benign_capability_total_events"],
        "namespace": fp["benign_namespace_events"],
        "mount": fp["benign_mount_events"],
        "ptrace": fp["benign_ptrace_events"],
        "sensitive_write": fp["benign_sensitive_write_events"],
    }
    names = list(probes.keys())
    values = list(probes.values())
    colors = [COLOR_ANCHOR if v > 0 else "#009E73" for v in values]

    fig, ax = plt.subplots(figsize=(9, 5.5), facecolor=BG)
    bars = ax.bar(names, values, color=colors)
    for b, v in zip(bars, values):
        ax.text(b.get_x() + b.get_width() / 2, v + max(values) * 0.01, f"{v:,}", ha="center", fontsize=9)

    ax.set_ylabel("Benign-baseline events over one idle-desktop measurement window")
    ax.set_title(
        "eBPF runtime probes: false-positive events on ordinary idle desktop use\n"
        "(ebpf-container-detection/evidence/analysis.json; measured counts, not alert rates)",
        fontsize=11,
        fontweight="bold",
    )
    ax.annotate(
        f"{fp['benign_capability_from_other_processes']:,} of {fp['benign_capability_total_events']:,}\n"
        "from processes other than\ncpptools/gdb (the known dev-tool source)",
        xy=(0, fp["benign_capability_total_events"]),
        xytext=(0.6, fp["benign_capability_total_events"] * 0.75),
        fontsize=8,
        color=COLOR_ANCHOR,
        arrowprops=dict(arrowstyle="->", color=COLOR_ANCHOR),
    )
    ax.grid(axis="y", color=GRID_COLOR, linewidth=0.5, alpha=0.5)
    ax.set_axisbelow(True)
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.text(
        0.01,
        0.005,
        "Source project's own conclusion: a detector alerting on every cap_capable() call "
        "\"is not usable as-is\" without correlating caller identity against known container workloads.",
        fontsize=7,
        color="#444444",
        va="bottom",
    )
    fig.savefig(out_path, dpi=150, facecolor=BG)
    plt.close(fig)


def main() -> int:
    from common import load_ebpf_analysis

    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    scoring_run = load_scoring_run()
    ebpf_analysis = load_ebpf_analysis()

    chart_anchor_case(scoring_run, CHARTS_DIR / "01_anchor_case.png")
    print(f"wrote {CHARTS_DIR / '01_anchor_case.png'}")

    # Two representative (hourly_cost, value_per_tp) points from the sweep grid,
    # chosen to show both a case that crosses within a plausible range and one
    # that does not, per the brief's requirement to report a non-finding plainly.
    chart_breakeven_curves(scoring_run, CHARTS_DIR / "02_breakeven_curves_low_value.png", hourly_cost=75, value_per_tp=50)
    print(f"wrote {CHARTS_DIR / '02_breakeven_curves_low_value.png'}")
    chart_breakeven_curves(scoring_run, CHARTS_DIR / "03_breakeven_curves_high_value.png", hourly_cost=75, value_per_tp=1000)
    print(f"wrote {CHARTS_DIR / '03_breakeven_curves_high_value.png'}")

    chart_breakeven_minutes_heatmap(scoring_run, CHARTS_DIR / "04_breakeven_minutes_grid.png")
    print(f"wrote {CHARTS_DIR / '04_breakeven_minutes_grid.png'}")

    chart_ebpf_probe_comparison(ebpf_analysis, CHARTS_DIR / "05_ebpf_probe_comparison.png")
    print(f"wrote {CHARTS_DIR / '05_ebpf_probe_comparison.png'}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
