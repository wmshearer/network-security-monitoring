#!/usr/bin/env python3
"""Reconstruct process trees from Sysmon EventID 1 (process creation) records.

Reads a corpus JSONL file one line at a time (the malicious corpus is 2.2 GB,
so nothing here loads the whole file into memory), keeps only EventID 1
records, and builds a parent-to-children process tree keyed by ProcessGuid.

A "process tree" here means: every process on a machine has a ProcessGuid
(a unique id Sysmon assigns to that process instance) and, if it was
launched by another process, a ParentProcessGuid pointing at the process
that created it. Chaining ParentProcessGuid -> ProcessGuid links across many
events reconstructs "what spawned what", several generations back, the same
way a family tree links parents to children to grandchildren.

For every process this script computes:
  - depth: how many hops back to the furthest reconstructable ancestor
    (0 = a process whose parent never appears in this corpus, i.e. a root)
  - ancestor_images: the chain of Image (executable path) values from the
    root down to this process, oldest first
  - children: ProcessGuids of processes this one directly spawned
  - fan_out: how many direct children a process has

Output is one JSON object per process, written as JSONL, to
evidence/trees_<corpus>.json. This file is the tree reconstruction evidence
that every later script and every number in FINDINGS.md is computed from.

Usage:
    python3 scripts/01_build_trees.py malicious
    python3 scripts/01_build_trees.py benign
    python3 scripts/01_build_trees.py both   # default
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = Path("/home/kali/director/projects/detection-rule-lab/data/events")
EVIDENCE_DIR = ROOT / "evidence"

CORPORA = {
    "malicious": SOURCE_DIR / "malicious.jsonl",
    "benign": SOURCE_DIR / "benign.jsonl",
}


def norm_guid(g):
    """Strip curly braces and lowercase a ProcessGuid.

    The malicious corpus (OTRF Security-Datasets, Mordor format) writes GUIDs
    as "{47ab858c-...}". The benign corpus (NextronSystems evtx-baseline)
    writes them as "CCEE75F4-..." with no braces. Both are the same kind of
    value (a Windows GUID); without normalizing, the same process would look
    like it has two different ids and the tree would be split by accident of
    the two source pipelines' formatting choices, not by anything real.
    """
    if g is None:
        return None
    return g.strip("{}").lower()


def stream_process_creation_events(path: Path):
    """Yield EventID 1 records from a JSONL file, one line at a time."""
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("EventID") != 1:
                continue
            yield line_no, rec


def build_tree(corpus_name: str, path: Path) -> dict:
    """Two-pass build: first collect all process nodes, then link and walk."""
    nodes: dict[str, dict] = {}
    total_events = 0
    process_creation_events = 0
    duplicate_guids = 0

    for line_no, rec in stream_process_creation_events(path):
        total_events += 1
        pguid = norm_guid(rec.get("ProcessGuid"))
        if pguid is None:
            continue
        process_creation_events += 1
        parent_guid = norm_guid(rec.get("ParentProcessGuid"))
        if pguid in nodes:
            duplicate_guids += 1
            continue
        nodes[pguid] = {
            "process_guid": pguid,
            "parent_guid": parent_guid,
            "image": rec.get("Image"),
            "parent_image": rec.get("ParentImage"),
            "command_line": rec.get("CommandLine"),
            "parent_command_line": rec.get("ParentCommandLine"),
            "utc_time": rec.get("UtcTime"),
            "user": rec.get("User"),
            "process_id": rec.get("ProcessId"),
            "parent_process_id": rec.get("ParentProcessId"),
            "children": [],
            "line_no": line_no,
        }

    # Link children. A parent that never appears as its own ProcessGuid node
    # in this corpus is an "unresolved parent": the chain is cut there
    # because the corpus does not contain that process's creation event
    # (it started before capture began, or on a host/session out of scope).
    parents_resolved = 0
    for guid, node in nodes.items():
        pg = node["parent_guid"]
        if pg and pg in nodes:
            nodes[pg]["children"].append(guid)
            parents_resolved += 1

    # Compute depth and ancestor image chain per node by walking parent links.
    # Iterative (not recursive) to avoid Python recursion-depth limits, and
    # cycle-guarded: a cycle would mean corrupted or adversarially-crafted
    # GUID data, which should be visible as a warning, not an infinite loop.
    depth_cache: dict[str, int] = {}
    ancestor_cache: dict[str, list[str]] = {}
    cycles_detected = 0

    def resolve(guid: str):
        if guid in depth_cache:
            return
        chain = []
        seen = set()
        cur = guid
        while cur is not None:
            if cur in seen:
                nonlocal cycles_detected
                cycles_detected += 1
                break
            seen.add(cur)
            chain.append(cur)
            node = nodes.get(cur)
            parent = node["parent_guid"] if node else None
            if parent not in nodes:
                break
            cur = parent
        # chain is [self, parent, grandparent, ...]; reverse for root-first
        chain.reverse()
        for i, g in enumerate(chain):
            if g not in depth_cache:
                depth_cache[g] = i
                ancestor_cache[g] = [nodes[a]["image"] for a in chain[: i + 1]]

    for guid in nodes:
        resolve(guid)

    for guid, node in nodes.items():
        node["depth"] = depth_cache.get(guid, 0)
        node["ancestor_images"] = ancestor_cache.get(guid, [node["image"]])
        node["fan_out"] = len(node["children"])
        node["parent_resolved"] = bool(node["parent_guid"] and node["parent_guid"] in nodes)

    max_depth = max((n["depth"] for n in nodes.values()), default=0)
    resolved_count = sum(1 for n in nodes.values() if n["parent_resolved"])

    # "max_chain_depth" is reported as chain LENGTH (number of processes in
    # the longest ancestor chain, root through leaf), not hop count, to match
    # the convention used when this corpus was first measured. Internally
    # each node's own "depth" field stays 0-indexed hop count from its root
    # (root's depth is 0); chain length for the deepest node is depth + 1.
    summary = {
        "corpus": corpus_name,
        "source_file": str(path),
        "eventid1_records": process_creation_events,
        "unique_processes": len(nodes),
        "duplicate_process_guids_skipped": duplicate_guids,
        "parents_resolved_in_corpus": resolved_count,
        "parents_resolved_pct": round(100 * resolved_count / len(nodes), 1) if nodes else 0.0,
        "max_chain_depth_hops": max_depth,
        "max_chain_depth_nodes": max_depth + 1 if nodes else 0,
        "cycles_detected": cycles_detected,
    }

    return {"summary": summary, "nodes": nodes}


def write_tree(corpus_name: str, tree: dict) -> Path:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    out_path = EVIDENCE_DIR / f"trees_{corpus_name}.jsonl"
    with out_path.open("w", encoding="utf-8") as f:
        f.write(json.dumps({"_summary": tree["summary"]}) + "\n")
        for guid, node in tree["nodes"].items():
            f.write(json.dumps(node) + "\n")
    return out_path


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "both"
    targets = list(CORPORA.items()) if which == "both" else [(which, CORPORA[which])]

    for name, path in targets:
        if not path.exists():
            print(f"SKIP {name}: source file not found at {path}", file=sys.stderr)
            continue
        print(f"[{name}] streaming {path} ...")
        tree = build_tree(name, path)
        out_path = write_tree(name, tree)
        print(f"[{name}] wrote {out_path}")
        print(json.dumps(tree["summary"], indent=2))


if __name__ == "__main__":
    main()
