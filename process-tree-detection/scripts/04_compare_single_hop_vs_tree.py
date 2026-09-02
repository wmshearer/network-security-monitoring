#!/usr/bin/env python3
"""Build the single-hop vs tree-detector comparison table (the deliverable).

Combines three evidence files already produced by earlier scripts:
  - evidence/single_hop_scoring.json   (every Zircolite rule x both corpora)
  - evidence/tree_detector_results.json (the 2 tree detectors x both corpora)
  - evidence/trees_*.jsonl              (reconstructed trees, for event lookup)

and answers the specific, falsifiable question this project asks: for the
exact process-creation events the tree detector flags as the attack's real
payload launch, does ANY single-hop Sigma rule in the 2,691-rule set also
match that same event? This re-uses the same "run the compiled SQL for real,
in SQLite" method as script 02, but narrows it to the handful of specific
events the tree detector found, which script 02's per-rule aggregate counts
cannot answer on their own (they say how many events overall each rule
matched, not which specific event(s)).

Usage:
    python3 scripts/04_compare_single_hop_vs_tree.py
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = ROOT / "evidence"
SOURCE_DIR = Path("/home/kali/director/projects/detection-rule-lab/data/events")
RULESET = Path(
    "/home/kali/director/projects/detection-rule-lab/vendor/Zircolite/rules/"
    "rules_windows_sysmon.json"
)


def norm_guid(g):
    return g.strip("{}").lower() if g else g


def find_raw_events(process_guids: set[str], path: Path) -> list[dict]:
    """Pull the full raw JSONL records for a set of target ProcessGuids."""
    found = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("EventID") == 1 and norm_guid(rec.get("ProcessGuid")) in process_guids:
                found.append(rec)
    return found


def sqlite_regexp(pattern, value):
    import re

    if value is None or pattern is None:
        return False
    try:
        return re.search(pattern, str(value)) is not None
    except re.error:
        return False


def which_rules_match_events(events: list[dict], rules: list[dict]) -> dict[str, list[str]]:
    """rule_id -> list of matched event ProcessGuids, for this small event set."""
    if not events:
        return {}
    cols: set[str] = set()
    for e in events:
        cols.update(e.keys())
    # Same backstop as script 02: also include any column a rule references,
    # so a rule naming a field these 2 events lack still gets a real NULL
    # column instead of a SQL error.
    import re

    identifier = re.compile(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|<>|!=|<|>|\bLIKE\b|\bGLOB\b|\bIS\b|\bREGEXP\b)"
    )
    for r in rules:
        for stmt in r.get("rule", []):
            for m in identifier.findall(stmt):
                cols.add(m)
    cols.discard("logs")
    cols_lower = {}
    for c in cols:
        cols_lower.setdefault(c.lower(), c)
    columns = sorted(cols_lower.values())

    con = sqlite3.connect(":memory:")
    con.create_function("REGEXP", 2, sqlite_regexp)
    quoted = ", ".join(f'"{c}"' for c in columns)
    con.execute(f"CREATE TABLE logs ({quoted})")
    for e in events:
        e_lower = {k.lower(): v for k, v in e.items()}
        row = []
        for c in columns:
            v = e_lower.get(c.lower())
            if c == "Channel" and isinstance(v, str) and v.lower() == "security":
                v = "Security"
            if v is not None and not isinstance(v, (str, int, float)):
                v = json.dumps(v)
            row.append(v)
        placeholders = ", ".join("?" for _ in columns)
        con.execute(f"INSERT INTO logs ({quoted}) VALUES ({placeholders})", row)
    con.commit()

    matches: dict[str, list[str]] = {}
    cur = con.cursor()
    for rule in rules:
        for stmt in rule.get("rule", []):
            try:
                cur.execute(stmt)
                rows = cur.fetchall()
            except sqlite3.Error:
                continue
            if rows:
                pg_idx = columns.index("ProcessGuid") if "ProcessGuid" in columns else None
                guids = [r[pg_idx] for r in rows] if pg_idx is not None else ["<unknown>"]
                matches.setdefault(rule["id"], []).extend(guids)
    con.close()
    return matches


def main():
    tree_results_path = EVIDENCE_DIR / "tree_detector_results.json"
    single_hop_path = EVIDENCE_DIR / "single_hop_scoring.json"
    if not tree_results_path.exists() or not single_hop_path.exists():
        print("SKIP: run scripts 02 and 03 first", file=sys.stderr)
        return

    tree = json.load(tree_results_path.open())
    single_hop = json.load(single_hop_path.open())
    rules = json.load(RULESET.open())
    rules_by_id = {r["id"]: r for r in rules}

    # --- Case study: the sdclt UAC-bypass payload-launch events ---
    uac_hits = tree["results"]["malicious"]["uac_bypass_proxy_chain_hits"]
    shell_guids = {h["shell_process_guid"] for h in uac_hits}
    events = find_raw_events(shell_guids, SOURCE_DIR / "malicious.jsonl")
    print(f"Found {len(events)} raw payload-launch events for the {len(shell_guids)} UAC-bypass hits")

    rule_matches = which_rules_match_events(events, rules)
    print(f"Single-hop rules matching these exact payload-launch events: {len(rule_matches)}")
    for rid, guids in rule_matches.items():
        print(f"  {rules_by_id[rid]['title']} ({rid}): {len(guids)} of these events")

    # --- Summary comparison table ---
    single_hop_fired = [r for r in single_hop["rows"] if r["malicious_hits"] > 0 or r["benign_hits"] > 0]
    single_hop_benign_fp = sum(r["benign_hits"] for r in single_hop["rows"])
    single_hop_malicious_hits = sum(r["malicious_hits"] for r in single_hop["rows"])

    tree_mal = tree["results"]["malicious"]
    tree_ben = tree["results"]["benign"]

    comparison = {
        "single_hop_baseline": {
            "description": "All 2,691 Zircolite-compiled SigmaHQ rules, run "
            "against every record in each corpus (all Sysmon/Security/System "
            "event types, not just EventID 1 process creation) via direct "
            "re-execution of their compiled SQL "
            "(see evidence/single_hop_scoring.json).",
            "rules_evaluated": single_hop["ruleset_rule_count"],
            "rules_fired_at_all": len(single_hop_fired),
            "total_malicious_events_matched": single_hop_malicious_hits,
            "total_benign_events_matched": single_hop_benign_fp,
            "sdclt_payload_launch_events_matched_by_any_rule": len(
                [g for guids in rule_matches.values() for g in guids]
            ),
            "sdclt_payload_launch_events_total": len(events),
        },
        "tree_detector_uac_bypass_proxy_chain": {
            "description": "This project's Detector 1 (T1548.002): "
            "auto-elevating binary -> intermediary -> shell/interpreter, "
            "2 hops down. See evidence/tree_detector_results.json.",
            "malicious_hits": len(tree_mal["uac_bypass_proxy_chain_hits"]),
            "benign_hits": len(tree_ben["uac_bypass_proxy_chain_hits"]),
            "precision": (
                len(tree_mal["uac_bypass_proxy_chain_hits"])
                / (len(tree_mal["uac_bypass_proxy_chain_hits"]) + len(tree_ben["uac_bypass_proxy_chain_hits"]))
                if (len(tree_mal["uac_bypass_proxy_chain_hits"]) + len(tree_ben["uac_bypass_proxy_chain_hits"])) > 0
                else None
            ),
        },
        "tree_detector_deep_chain_to_lolbin": {
            "description": "This project's Detector 2 (T1218): a process "
            "chain reaches a LOLBAS-listed binary 4+ processes deep. "
            "REPORTED AS A NEGATIVE RESULT: see FINDINGS.md, this detector "
            "fires promiscuously on benign infrastructure (conhost.exe, "
            "ngen.exe) and does not discriminate malicious from benign "
            "chains even after excluding those two names.",
            "malicious_hits": len(tree_mal["deep_chain_to_lolbin_hits"]),
            "benign_hits": len(tree_ben["deep_chain_to_lolbin_hits"]),
            "precision": (
                len(tree_mal["deep_chain_to_lolbin_hits"])
                / (len(tree_mal["deep_chain_to_lolbin_hits"]) + len(tree_ben["deep_chain_to_lolbin_hits"]))
                if (len(tree_mal["deep_chain_to_lolbin_hits"]) + len(tree_ben["deep_chain_to_lolbin_hits"])) > 0
                else None
            ),
        },
        "case_study_sdclt_uac_bypass": {
            "description": "The 2 real payload-launch events (sdclt.exe -> "
            "control.exe -> powershell.exe, from the OTRF/Mordor APT29 "
            "evaluation capture in the malicious corpus) that Detector 1 "
            "catches. Existing single-hop rule 'Sdclt Child Processes' "
            "(da2738f2-fadb-4394-afa7-0a0674885afa) matches the INTERMEDIARY "
            "control.exe event (one hop from sdclt.exe) but never the "
            "powershell.exe event where the payload actually executes, "
            "because that event's ParentImage is control.exe, not sdclt.exe.",
            "payload_launch_events": len(events),
            "single_hop_rules_matching_payload_launch_events": list(rule_matches.keys()),
        },
    }

    out_path = EVIDENCE_DIR / "comparison_table.json"
    with out_path.open("w") as f:
        json.dump(comparison, f, indent=2)
    print(f"\nWrote {out_path}")
    print(json.dumps(comparison, indent=2))


if __name__ == "__main__":
    main()
