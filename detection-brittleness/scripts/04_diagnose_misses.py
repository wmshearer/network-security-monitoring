#!/usr/bin/env python3
"""Stage 4: diagnose the near-zero full-survival rate before calling it brittleness.

For every technique-tagged rule that fired in at least one group but not all
(from evidence/03_matrix.json), checks whether the EventIDs the rule's SQL
targets even occur in the groups where it did not fire. If they don't occur
at all, the miss is telemetry absence (structural, like the ir-activemq-lockbit
D5 case), not a logic failure. If they do occur but the rule still didn't
fire, that is a genuine logic-specificity miss (like D3/D6 in that same
project) and is reported as such.

This directly implements the instruction: don't call ~0% survival brittleness
without first checking whether the corpora simply differ in which event types
they captured.

Bug fixed in this version (see FINDINGS.md, "Bug found during this project:
the EVTX EventID extraction defect"): EventIDs used to be read by regex over
each staged sample file's TEXT. `.evtx` is a BINARY format, so that regex read
nothing from the two EVTX sample groups and silently returned an empty set for
them, which made every miss in those two groups fall through to TELEMETRY
ABSENT by default, even when the true cause was logic-too-narrow. This is now
read from evidence/03b_evtx_eventid_inventory.json, which
scripts/03b_extract_evtx_eventids.py produces by asking Zircolite itself (the
same tool already used to score this project, not a new dependency) to decode
each EVTX group's full, unfiltered event stream to JSON. If that inventory is
missing or null for a group, this script reports UNDETERMINED for every miss
in that group rather than assuming zero EventIDs present, which is the same
kind of silent-default bug being fixed here.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLES_DIR = ROOT / "evidence" / "samples"
MATRIX_PATH = ROOT / "evidence" / "03_matrix.json"
RAW_DIR = ROOT / "evidence" / "zircolite_raw"
EVTX_INVENTORY_PATH = ROOT / "evidence" / "03b_evtx_eventid_inventory.json"


def load_rule_sql_by_id() -> dict[str, set[str]]:
    """Pull every distinct compiled SQL variant seen for each rule id, across all raw run output.

    The vendored ruleset compiles some Sigma rules more than once under the
    same id, once per log-source variant (e.g. a "- Generic" variant against
    Security EventID 4688 and a "- Sysmon" variant against Sysmon EventID 1).
    A rule "fires" if EITHER variant matches, so for miss diagnosis its target
    EventIDs must be the UNION of every variant's EventIDs, not whichever
    variant happened to be read first (that depended on filesystem glob
    order, which is not a meaningful or stable signal).
    """
    sql_variants_by_id: dict[str, set[str]] = {}
    for f in RAW_DIR.rglob("*.json"):
        try:
            matches = json.loads(f.read_text() or "[]")
        except json.JSONDecodeError:
            continue
        for m in matches:
            rid = m.get("id")
            sql = m.get("sigma")
            if rid and sql:
                sql_str = " ".join(sql) if isinstance(sql, list) else str(sql)
                sql_variants_by_id.setdefault(rid, set()).add(sql_str)
    return sql_variants_by_id


def eventids_in_group(technique: str, group: str, evtx_inventory: dict) -> set[str] | None:
    """Collect every EventID present in a group's raw staged data.

    Returns None if this group has staged .evtx samples but no reliable
    EventID inventory could be determined for them (missing or null entry in
    evidence/03b_evtx_eventid_inventory.json), so the caller can report
    UNDETERMINED instead of silently treating "could not read" as "absent".
    """
    group_dir = SAMPLES_DIR / technique / group
    ids: set[str] = set()
    for xml_file in group_dir.glob("*.xml"):
        text = xml_file.read_text(errors="replace")
        ids.update(re.findall(r"<EventID>(\d+)</EventID>", text))

    evtx_files = list(group_dir.glob("*.evtx"))
    if evtx_files:
        key = f"{technique}/{group}"
        entry = evtx_inventory.get(key)
        if entry is None:
            return None
        ids.update(entry)
    return ids


def rule_eventids(sigma_sql_variants: set[str]) -> set[str]:
    """Best-effort extraction of EventID=<n> literals referenced across every
    compiled SQL variant of a rule (see load_rule_sql_by_id)."""
    ids: set[str] = set()
    for sql in sigma_sql_variants:
        ids.update(re.findall(r"EventID\s*=\s*'?(\d+)'?", sql))
    return ids


def main() -> None:
    matrix = json.loads(MATRIX_PATH.read_text())
    sql_by_id = load_rule_sql_by_id()
    evtx_inventory: dict = {}
    if EVTX_INVENTORY_PATH.exists():
        evtx_inventory = json.loads(EVTX_INVENTORY_PATH.read_text())
    report_lines = []

    telemetry_absent_count = 0
    logic_narrow_count = 0
    unknown_count = 0
    undetermined_count = 0

    eventid_cache: dict[tuple[str, str], set[str] | None] = {}

    for technique, tdata in matrix.items():
        group_names = tdata["group_names"]
        for g in group_names:
            eventid_cache[(technique, g)] = eventids_in_group(technique, g, evtx_inventory)

        report_lines.append(f"=== {technique}: EventIDs present per group (from raw staged samples) ===")
        for g in group_names:
            present = eventid_cache[(technique, g)]
            if present is None:
                report_lines.append(f"  {g}: UNDETERMINED (could not read this group's EventIDs)")
            else:
                report_lines.append(f"  {g}: {sorted(present, key=lambda x: int(x))}")
        report_lines.append("")

        report_lines.append(f"=== {technique}: miss diagnosis for rules that fired somewhere but not everywhere ===")
        for rid, info in sorted(tdata["detail"].items(), key=lambda kv: kv[1]["title"]):
            fired_in = {g for g, c in info["counts"].items() if c > 0}
            missed_in = [g for g in group_names if g not in fired_in]
            if not missed_in:
                continue  # survived everywhere, nothing to diagnose
            # union of EventIDs across every compiled SQL variant of this rule id
            # (a rule can compile to more than one log-source variant; see
            # load_rule_sql_by_id's docstring)
            rule_sql_variants = sql_by_id.get(rid, set())
            rule_eids = rule_eventids(rule_sql_variants)
            report_lines.append(f"  {info['title']} (id {rid[:8]}...) targets EventID(s): {sorted(rule_eids) if rule_eids else 'unknown (not extracted from SQL)'}")
            for g in missed_in:
                present = eventid_cache[(technique, g)]
                if present is None:
                    verdict = "UNDETERMINED (could not read this group's EventIDs)"
                    undetermined_count += 1
                elif rule_eids and not (rule_eids & present):
                    verdict = "TELEMETRY ABSENT (rule's EventID never occurs in this group's raw data)"
                    telemetry_absent_count += 1
                elif rule_eids and (rule_eids & present):
                    verdict = "LOGIC TOO NARROW (rule's EventID is present in this group but the rule's field/value match still did not fire)"
                    logic_narrow_count += 1
                else:
                    verdict = "UNKNOWN (could not extract rule's target EventID from its SQL)"
                    unknown_count += 1
                report_lines.append(f"    MISSED in {g}: {verdict}")
                present_str = sorted(present, key=lambda x: int(x)) if present else ("UNDETERMINED" if present is None else "(none extracted)")
                report_lines.append(f"      EventIDs present in that group: {present_str}")
        report_lines.append("")

    report_lines.append("=== Overall miss-cause tally across both techniques ===")
    report_lines.append(f"telemetry absent: {telemetry_absent_count}")
    report_lines.append(f"logic too narrow: {logic_narrow_count}")
    report_lines.append(f"undetermined (could not read group's EventIDs): {undetermined_count}")
    report_lines.append(f"unknown (SQL parse failed): {unknown_count}")

    out_path = ROOT / "evidence" / "04_miss_diagnosis.txt"
    out_path.write_text("\n".join(report_lines) + "\n")
    print("\n".join(report_lines))
    print(f"\nwrote {out_path}")


if __name__ == "__main__":
    main()
