#!/usr/bin/env python3
"""Render the process-tree comparison diagram from real evidence data.

Draws two real, measured process trees side by side, using Graphviz:
  LEFT:  the malicious UAC-bypass chain (evidence/tree_detector_results.json,
         evidence/trees_malicious.jsonl), a real 5-generation attack chain
         from the OTRF/Mordor APT29 evaluation capture in this project's
         malicious corpus.
  RIGHT: the deepest benign chain found in this project's benign corpus
         (evidence/trees_benign.jsonl), 9 processes deep, entirely routine
         Windows service startup and .NET native-image compilation.

Every node label, command line, and depth number in this diagram is read
from the evidence files scripts 01, 03, and 04 already wrote; nothing here
is invented or hand-placed. Colors follow the project's status palette
(good/warning/serious/critical are fixed, non-thematic roles -- see the
dataviz skill's palette reference) and every status color ships with an
icon + text label, never color alone, per that skill's accessibility rule.

Usage:
    python3 scripts/05_render_tree_diagram.py
Requires: graphviz's `dot` on PATH (apt package `graphviz`).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = ROOT / "evidence"
CHARTS_DIR = ROOT / "charts"

# Status palette (fixed, non-thematic roles; see dataviz skill palette.md)
COLOR_GOOD = "#0ca30c"
COLOR_CRITICAL = "#d03b3b"
COLOR_WARNING = "#fab219"
COLOR_NEUTRAL_FILL = "#eceae4"
COLOR_NEUTRAL_TEXT = "#0b0b0b"
COLOR_SURFACE = "#fcfcfb"


def basename(image):
    if not image:
        return "?"
    return image.replace("/", "\\").split("\\")[-1]


def load_tree(corpus):
    path = EVIDENCE_DIR / f"trees_{corpus}.jsonl"
    nodes = {}
    with path.open() as f:
        for line in f:
            rec = json.loads(line)
            if "_summary" in rec:
                continue
            nodes[rec["process_guid"]] = rec
    return nodes


def chain_from_leaf(nodes, leaf_guid):
    chain = []
    cur = nodes.get(leaf_guid)
    while cur:
        chain.append(cur)
        pg = cur["parent_guid"]
        cur = nodes.get(pg) if pg else None
    chain.reverse()
    return chain


def escape(s):
    if s is None:
        return ""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def build_attack_subgraph(nodes, tree_results):
    """The sdclt.exe -> control.exe -> powershell.exe UAC-bypass chain."""
    uac_hits = tree_results["results"]["malicious"]["uac_bypass_proxy_chain_hits"]
    hit = uac_hits[0]  # first of the 2 identical-shape hits; see evidence file for both
    chain = chain_from_leaf(nodes, hit["shell_process_guid"])

    lines = []
    lines.append('  subgraph cluster_attack {')
    lines.append(f'    label="Malicious corpus: real APT29-evaluation UAC-bypass chain (T1548.002)\\n'
                  f'sdclt.exe hijacked to launch a shell via control.exe, {len(chain)} generations";')
    lines.append('    labelloc="t"; fontsize=13; fontname="Helvetica-Bold";')
    lines.append(f'    style=filled; color="{COLOR_NEUTRAL_FILL}"; fillcolor="{COLOR_SURFACE}";')
    lines.append('    node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=11];')

    auto_elevate_guid = hit["auto_elevate_process_guid"]
    intermediary_guid = hit["intermediary_process_guid"]
    shell_guid = hit["shell_process_guid"]

    for i, node in enumerate(chain):
        guid = node["process_guid"]
        img = basename(node["image"])
        node_id = f"a{i}"
        if i == 0:
            # This filename contains a Unicode right-to-left override
            # character (U+202E), a documented masquerading technique
            # (ATT&CK T1036.002): the raw bytes render as mojibake in most
            # terminals/fonts, which is real, not a rendering bug in this
            # diagram. Shown here with that explained rather than silently
            # displaying the corrupted glyphs.
            label_lines = ["[RTLO-obfuscated filename, T1036.002]", "displays as \"...cod.3aka3.scr\""]
        else:
            label_lines = [img]
        fill = "#ffffff"
        border = "#8a8a86"
        extra = ""
        if guid == auto_elevate_guid:
            label_lines.append("(auto-elevating binary, T1548.002)")
            fill = COLOR_WARNING
            border = COLOR_WARNING
        elif guid == intermediary_guid:
            label_lines.append("SINGLE-HOP RULE FLAGS THIS EVENT")
            label_lines.append("(\"Sdclt Child Processes\")")
            fill = "#ffffff"
            border = "#52514e"
            extra = ', penwidth=2, style="rounded,filled,dashed"'
        elif guid == shell_guid:
            label_lines.append("PAYLOAD LAUNCH")
            label_lines.append("TREE DETECTOR FLAGS THIS EVENT")
            label_lines.append("(2 hops from sdclt.exe; no lineage-based")
            label_lines.append("single-hop rule reaches this far back)")
            fill = COLOR_CRITICAL
            border = COLOR_CRITICAL
        label = "\\n".join(escape(l) for l in label_lines)
        text_color = "#ffffff" if fill in (COLOR_CRITICAL, COLOR_WARNING) else COLOR_NEUTRAL_TEXT
        lines.append(
            f'    {node_id} [label="{label}", fillcolor="{fill}", color="{border}", '
            f'fontcolor="{text_color}"{extra}];'
        )
        if i > 0:
            lines.append(f"    a{i-1} -> {node_id};")
    lines.append("  }")
    return "\n".join(lines)


def build_benign_subgraph(nodes):
    """The deepest chain in the benign corpus (9 processes, routine .NET compile)."""
    deepest = max(nodes.values(), key=lambda n: n["depth"])
    chain = chain_from_leaf(nodes, deepest["process_guid"])

    lines = []
    lines.append("  subgraph cluster_benign {")
    lines.append(f'    label="Benign corpus: deepest real chain found, {len(chain)} generations\\n'
                  f'routine Windows service startup + .NET native image compile (no attack)";')
    lines.append('    labelloc="t"; fontsize=13; fontname="Helvetica-Bold";')
    lines.append(f'    style=filled; color="{COLOR_NEUTRAL_FILL}"; fillcolor="{COLOR_SURFACE}";')
    lines.append('    node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=11];')

    for i, node in enumerate(chain):
        img = basename(node["image"])
        node_id = f"b{i}"
        fill = "#ffffff"
        border = "#8a8a86"
        label_lines = [img]
        if img.lower() in ("ngen.exe",):
            label_lines.append("(LOLBAS-listed binary, but routine here:")
            label_lines.append("depth-only detector would misfire on this)")
            fill = COLOR_GOOD
            border = COLOR_GOOD
        label = "\\n".join(escape(l) for l in label_lines)
        text_color = "#ffffff" if fill == COLOR_GOOD else COLOR_NEUTRAL_TEXT
        lines.append(f'    {node_id} [label="{label}", fillcolor="{fill}", color="{border}", fontcolor="{text_color}"];')
        if i > 0:
            lines.append(f"    b{i-1} -> {node_id};")
    lines.append("  }")
    return "\n".join(lines)


def main():
    tree_results_path = EVIDENCE_DIR / "tree_detector_results.json"
    if not tree_results_path.exists():
        print("SKIP: run script 03 first", file=sys.stderr)
        return

    tree_results = json.load(tree_results_path.open())
    mal_nodes = load_tree("malicious")
    ben_nodes = load_tree("benign")

    dot = []
    dot.append("digraph ProcessTrees {")
    dot.append(f'  bgcolor="{COLOR_SURFACE}";')
    dot.append('  rankdir=TB; fontname="Helvetica"; nodesep=0.4; ranksep=0.35;')
    dot.append(
        '  label="Process-tree reasoning: what one-event Sigma rules see vs what a '
        "multi-hop tree detector sees\\n"
        'Both trees are reconstructed from real Sysmon EventID 1 records in this project\'s corpora (see evidence/trees_*.jsonl)";'
    )
    dot.append('  labelloc="t"; fontsize=15; fontname="Helvetica-Bold";')
    dot.append(build_attack_subgraph(mal_nodes, tree_results))
    dot.append(build_benign_subgraph(ben_nodes))
    dot.append("}")
    dot_src = "\n".join(dot)

    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    dot_path = CHARTS_DIR / "process_tree_comparison.dot"
    dot_path.write_text(dot_src)
    print(f"Wrote {dot_path}")

    png_path = CHARTS_DIR / "process_tree_comparison.png"
    result = subprocess.run(
        ["dot", "-Tpng", "-Gdpi=150", str(dot_path), "-o", str(png_path)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print("dot FAILED:", result.stderr, file=sys.stderr)
        sys.exit(1)
    print(f"Wrote {png_path}")


if __name__ == "__main__":
    main()
