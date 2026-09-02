#!/usr/bin/env python3
"""
Generate the two evidence charts for the writeup, both computed directly
from saved evidence JSON files, never from hand-entered numbers:

  chart_q1_false_positive_rate.png : match rate per ruleset per corpus (Q1)
  chart_q2_cost_by_construct.png   : mean scan time per construct, with
                                      error bars from the repeated-run stdev (Q2)

Palette: the portfolio's validated categorical/sequential palette
(dataviz skill, references/palette.md), light-mode values.
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

PROJECT_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = PROJECT_DIR / "evidence"

# Validated categorical palette (light mode), fixed order, from the dataviz skill.
SERIES = {
    "blue": "#2a78d6",
    "orange": "#eb6834",
    "aqua": "#1baf7a",
    "yellow": "#eda100",
}
TEXT_PRIMARY = "#0b0b0b"
TEXT_SECONDARY = "#52514e"
GRID = "#d9d8d0"

plt.rcParams.update(
    {
        "font.size": 10,
        "text.color": TEXT_PRIMARY,
        "axes.edgecolor": GRID,
        "axes.labelcolor": TEXT_PRIMARY,
        "xtick.color": TEXT_SECONDARY,
        "ytick.color": TEXT_SECONDARY,
        "figure.facecolor": "white",
        "axes.facecolor": "white",
    }
)


def chart_q1_false_positive_rate():
    with open(EVIDENCE_DIR / "04_scan_clean_corpus_yara_python.json") as fh:
        d = json.load(fh)

    rulesets = ["yara-rules", "yara-rules-official-index", "reversinglabs", "signature-base", "protections-artifacts"]
    labels = ["yara-rules\n(naive clone)", "yara-rules\n(official index)", "reversinglabs", "signature-base", "protections-\nartifacts"]
    corpora = ["usr_bin", "usr_lib_x86_64", "openwrt_firmware", "iotgoat_firmware"]
    corpus_labels = ["usr/bin", "usr/lib", "OpenWrt firmware", "IoTGoat firmware"]
    colors = [SERIES["blue"], SERIES["orange"], SERIES["aqua"], SERIES["yellow"]]

    n_groups = len(rulesets)
    n_bars = len(corpora)
    width = 0.19
    x = range(n_groups)

    fig, ax = plt.subplots(figsize=(11, 5.5))
    for i, (corpus, corpus_label, color) in enumerate(zip(corpora, corpus_labels, colors)):
        rates = []
        for rs in rulesets:
            c = d[rs]["corpora"][corpus]
            scanned = c["files_scanned"]
            matched = c["files_matched"]
            rates.append(100.0 * matched / scanned if scanned else 0.0)
        offsets = [xi + (i - (n_bars - 1) / 2) * width for xi in x]
        bars = ax.bar(offsets, rates, width=width, label=corpus_label, color=color, zorder=3)
        for b, r in zip(bars, rates):
            label = f"{r:.1f}%" if r >= 0.05 else "0%"
            ax.text(
                b.get_x() + b.get_width() / 2,
                b.get_height() + 1.2,
                label,
                ha="center",
                va="bottom",
                fontsize=7 if r < 0.5 else 7.5,
                color=TEXT_SECONDARY,
                rotation=90 if r < 0.5 else 0,
            )

    ax.set_ylabel("Files matched (% of files scanned)")
    ax.set_title("Q1: false-positive rate on clean files, per ruleset per corpus", fontsize=12, color=TEXT_PRIMARY, loc="left")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 105)
    ax.grid(axis="y", color=GRID, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    ax.legend(frameon=False, ncols=4, loc="upper center", bbox_to_anchor=(0.5, -0.12))
    fig.text(
        0.01, 0.01,
        "Source: evidence/04_scan_clean_corpus_yara_python.json. usr/bin and usr/lib capped to 400 files for the two\n"
        "yara-rules variants only (see evidence/04_yara_rules_speed_probe.txt); all other cells are full corpus size.",
        fontsize=7, color=TEXT_SECONDARY,
    )
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    out = EVIDENCE_DIR / "chart_q1_false_positive_rate.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"Wrote {out}")


def chart_q2_cost_by_construct():
    with open(EVIDENCE_DIR / "06_cost_experiment_timing.json") as fh:
        d = json.load(fh)

    order = ["cost_literal_string", "cost_regex", "cost_hex_wildcard", "cost_elf_loop"]
    display = ["literal\nstring", "regex", "hex +\nwildcards", "for loop over\nelf.sections"]
    means = [d["results"][r]["mean_seconds"] for r in order]
    stdevs = [d["results"][r]["stdev_seconds"] for r in order]
    matches = [d["results"][r]["match_count"] for r in order]

    colors = [SERIES["blue"], SERIES["blue"], SERIES["blue"], SERIES["orange"]]

    fig, ax = plt.subplots(figsize=(8, 5.5))
    bars = ax.bar(display, means, yerr=stdevs, capsize=4, color=colors, zorder=3, error_kw={"ecolor": TEXT_SECONDARY, "linewidth": 1.2})
    for b, m, mc in zip(bars, means, matches):
        ax.text(
            b.get_x() + b.get_width() / 2,
            b.get_height() + max(stdevs) + 0.05,
            f"{m:.2f}s\n({mc} matches)",
            ha="center",
            va="bottom",
            fontsize=8.5,
            color=TEXT_SECONDARY,
        )

    ax.set_ylabel(f"Mean wall-clock time, {d['corpus_file_count']} files, {d['repeats']} repeats (seconds)")
    ax.set_title("Q2: scan cost by pattern-matching construct, same 28 bytes of content", fontsize=11.5, color=TEXT_PRIMARY, loc="left")
    ax.grid(axis="y", color=GRID, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.text(
        0.01, 0.01,
        "Source: evidence/06_cost_experiment_timing.json. First three rules match the identical 2278 files; the elf-loop\n"
        "rule matches 2310 (36-file difference explained in FINDINGS.md), so its bar is a distinct, not equivalent, measurement.",
        fontsize=7, color=TEXT_SECONDARY,
    )
    fig.tight_layout(rect=(0, 0.07, 1, 1))
    out = EVIDENCE_DIR / "chart_q2_cost_by_construct.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"Wrote {out}")


if __name__ == "__main__":
    chart_q1_false_positive_rate()
    chart_q2_cost_by_construct()
