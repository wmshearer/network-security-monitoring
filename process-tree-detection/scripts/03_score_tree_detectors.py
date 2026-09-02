#!/usr/bin/env python3
"""Score two multi-hop ("N-hop") process-tree detectors against both corpora.

Background for readers new to this: a "process tree" is the record of which
process started which other process, several generations back, the same way
a family tree links parents to children to grandchildren. Windows Sysmon
(System Monitor, a free Microsoft driver) logs "EventID 1" every time a new
process starts, and that record includes the new process's own executable
path (Image) and its immediate parent's path (ParentImage). A "single-hop"
or "single-event" detection rule can only look at the fields of ONE such
record, so it can see a process and its immediate parent, but not further
back. A LOLBIN ("living-off-the-land binary") is a legitimate, pre-installed
Windows program that attackers can abuse to run their own code, which is
useful to them because the binary is already trusted and signed, so its
execution alone rarely looks suspicious.

Both detectors below need MORE than one event to decide: they walk the
ancestor chain built by scripts/01_build_trees.py (evidence/trees_*.jsonl),
which is exactly the reconstruction a single Sigma rule (one row of one
table) cannot do.

Detector 1: UAC_BYPASS_PROXY_CHAIN (maps to ATT&CK T1548.002)
    Fires when a documented auto-elevating Windows binary (one that Windows
    silently grants administrator rights to without a prompt) has a CHILD
    that itself has a CHILD (i.e. a grandchild of the auto-elevating binary)
    that is a shell or script interpreter. The well-documented abuse pattern
    (see FINDINGS.md for primary sources) hijacks the auto-elevating binary
    so that when it looks up a helper program to launch, it launches
    something attacker-controlled instead; that attacker-controlled program
    is usually a generic-looking intermediary (here, Control Panel's
    control.exe) that then launches the real payload. The intermediary hop
    is what makes this only visible two generations down, not one: a rule
    watching only "what did the auto-elevating binary launch" sees the
    generic intermediary and stops there.

Detector 2: DEEP_CHAIN_TO_LOLBIN
    Fires when a process chain reaches a documented LOLBAS (Living Off The
    Land Binaries And Scripts project, lolbas-project.github.io) binary at
    least 4 processes down from its root ancestor. The justification is
    tradecraft-based, not depth-for-its-own-sake: MITRE ATT&CK's System
    Binary Proxy Execution (T1218) describes adversaries proxying execution
    through trusted binaries specifically to put distance, in defensive
    tooling's eyes, between the initial compromise and the payload. A rule
    keyed on "process X's immediate parent is Y" cannot express "however
    many hops it took to get here," which is exactly the shape of this
    evasion.

Both detectors are intentionally NOT anchored to the one attack scenario
found in this corpus (see FINDINGS.md: the corpus contains a Mordor/APT29
evaluation capture using sdclt.exe -> control.exe -> powershell.exe). The
auto-elevating binary list and the LOLBAS list are drawn from primary
sources and would fire on any chain shaped this way, not just this one.

Usage:
    python3 scripts/03_score_tree_detectors.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = ROOT / "evidence"

# ATT&CK T1548.002 (attack.mitre.org, fetched and confirmed 2026-08-28) names
# eventvwr.exe, fodhelper.exe, and sdclt.exe directly. The LOLBAS project
# (lolbas-project.github.io, evidence/sources/lolbas_project.json, fetched
# live) independently tags computerdefaults.exe, eudcedit.exe, eventvwr.exe,
# iscsicpl.exe, odbcad32.exe, and wsreset.exe with MitreID T1548. This is the
# union of both primary sources, not a list invented for this corpus.
AUTO_ELEVATE_BINARIES = {
    "eventvwr.exe",
    "fodhelper.exe",
    "sdclt.exe",
    "computerdefaults.exe",
    "eudcedit.exe",
    "iscsicpl.exe",
    "odbcad32.exe",
    "wsreset.exe",
}

# Shells and script interpreters that indicate real code execution rather
# than the auto-elevating binary's normal helper UI. Kept short and specific
# rather than "anything": these are the interpreters actually capable of
# running attacker-supplied logic once reached this way.
SHELLS_AND_INTERPRETERS = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "powershell_ise.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
}

MIN_DEPTH_FOR_DEEP_CHAIN = 4  # nodes in chain (root counts as depth 1)


def basename(image: str | None) -> str | None:
    if not image:
        return None
    return image.replace("/", "\\").split("\\")[-1].lower()


def load_lolbas_names() -> set[str]:
    path = EVIDENCE_DIR / "sources" / "lolbas_project.json"
    with path.open() as f:
        data = json.load(f)
    return {entry["Name"].lower() for entry in data}


def load_tree(corpus_name: str) -> dict[str, dict]:
    path = EVIDENCE_DIR / f"trees_{corpus_name}.jsonl"
    nodes: dict[str, dict] = {}
    with path.open() as f:
        for line in f:
            rec = json.loads(line)
            if "_summary" in rec:
                continue
            nodes[rec["process_guid"]] = rec
    return nodes


def detect_uac_bypass_proxy_chain(nodes: dict[str, dict]) -> list[dict]:
    """Auto-elevate binary -> anything -> shell/interpreter (2+ hops down).

    Deliberately does NOT require the middle hop to be any specific binary
    (like control.exe): the documented technique family covers several
    auto-elevating binaries and several possible hijacked intermediaries, so
    hardcoding "control.exe" would fit only the one sample in this corpus.
    What is invariant across the documented tradecraft is the SHAPE: an
    auto-elevating binary's grandchild is a shell/interpreter, which a
    single-hop "what is this binary's immediate parent" rule cannot see,
    because the immediate parent of the shell is the intermediary, not the
    auto-elevating binary.
    """
    findings = []
    for node in nodes.values():
        img = basename(node["image"])
        if img not in AUTO_ELEVATE_BINARIES:
            continue
        for child_guid in node["children"]:
            child = nodes.get(child_guid)
            if not child:
                continue
            for grandchild_guid in child["children"]:
                grandchild = nodes.get(grandchild_guid)
                if not grandchild:
                    continue
                gimg = basename(grandchild["image"])
                if gimg in SHELLS_AND_INTERPRETERS:
                    findings.append(
                        {
                            "detector": "UAC_BYPASS_PROXY_CHAIN",
                            "attack_technique": "T1548.002",
                            "auto_elevate_process_guid": node["process_guid"],
                            "auto_elevate_image": node["image"],
                            "intermediary_process_guid": child["process_guid"],
                            "intermediary_image": child["image"],
                            "shell_process_guid": grandchild["process_guid"],
                            "shell_image": grandchild["image"],
                            "shell_command_line": grandchild["command_line"],
                            "single_hop_visible_node": "intermediary (child of "
                            "auto-elevating binary) only; a rule keyed on "
                            "ParentImage=<auto-elevate binary> matches the "
                            "intermediary event, never the shell event where "
                            "the payload actually runs",
                        }
                    )
    return findings


def detect_deep_chain_to_lolbin(nodes: dict[str, dict], lolbas_names: set[str]) -> list[dict]:
    """A process chain reaching a LOLBAS binary at depth >= MIN_DEPTH_FOR_DEEP_CHAIN."""
    findings = []
    for node in nodes.values():
        img = basename(node["image"])
        if img not in lolbas_names:
            continue
        chain_len = node["depth"] + 1
        if chain_len < MIN_DEPTH_FOR_DEEP_CHAIN:
            continue
        findings.append(
            {
                "detector": "DEEP_CHAIN_TO_LOLBIN",
                "attack_technique": "T1218",
                "process_guid": node["process_guid"],
                "image": node["image"],
                "lolbin_name": img,
                "chain_length_nodes": chain_len,
                "ancestor_images": node["ancestor_images"],
                "single_hop_visible_node": "only the immediate parent-child "
                "pair at the bottom of this chain; a rule cannot see how "
                "many hops it took to arrive here",
            }
        )
    return findings


def main():
    lolbas_path = EVIDENCE_DIR / "sources" / "lolbas_project.json"
    if not lolbas_path.exists():
        print(f"SKIP: LOLBAS source not found at {lolbas_path}", file=sys.stderr)
        return
    lolbas_names = load_lolbas_names()
    print(f"Loaded {len(lolbas_names)} LOLBAS binary names from {lolbas_path}")

    all_results = {}
    for corpus in ("malicious", "benign"):
        tree_path = EVIDENCE_DIR / f"trees_{corpus}.jsonl"
        if not tree_path.exists():
            print(f"SKIP {corpus}: {tree_path} not found, run 01_build_trees.py first", file=sys.stderr)
            continue
        nodes = load_tree(corpus)
        uac_hits = detect_uac_bypass_proxy_chain(nodes)
        lolbin_hits = detect_deep_chain_to_lolbin(nodes, lolbas_names)
        all_results[corpus] = {
            "unique_processes": len(nodes),
            "uac_bypass_proxy_chain_hits": uac_hits,
            "deep_chain_to_lolbin_hits": lolbin_hits,
        }
        print(
            f"[{corpus}] {len(nodes)} processes: "
            f"UAC_BYPASS_PROXY_CHAIN={len(uac_hits)} hits, "
            f"DEEP_CHAIN_TO_LOLBIN={len(lolbin_hits)} hits"
        )

    out_path = EVIDENCE_DIR / "tree_detector_results.json"
    with out_path.open("w") as f:
        json.dump(
            {
                "auto_elevate_binaries": sorted(AUTO_ELEVATE_BINARIES),
                "shells_and_interpreters": sorted(SHELLS_AND_INTERPRETERS),
                "min_depth_for_deep_chain_nodes": MIN_DEPTH_FOR_DEEP_CHAIN,
                "results": all_results,
            },
            f,
            indent=2,
        )
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
