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
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLES_DIR = ROOT / "evidence" / "samples"
MATRIX_PATH = ROOT / "evidence" / "03_matrix.json"
RAW_DIR = ROOT / "evidence" / "zircolite_raw"


def load_rule_sql_by_id() -> dict[str, str]:
    """Pull each rule's compiled SQL from wherever it appears in any raw run output."""
    sql_by_id: dict[str, str] = {}
    for f in RAW_DIR.rglob("*.json"):
        try:
            matches = json.loads(f.read_text() or "[]")
        except json.JSONDecodeError:
            continue
        for m in matches:
            rid = m.get("id")
            sql = m.get("sigma")
            if rid and sql and rid not in sql_by_id:
                sql_by_id[rid] = " ".join(sql) if isinstance(sql, list) else str(sql)
    return sql_by_id


def eventids_in_group(technique: str, group: str) -> set[str]:
    """Read raw staged sample files directly and collect every EventID present."""
    group_dir = SAMPLES_DIR / technique / group
    ids: set[str] = set()
    for xml_file in group_dir.glob("*.xml"):
        text = xml_file.read_text(errors="replace")
        ids.update(re.findall(r"<EventID>(\d+)</EventID>", text))
    evtx_files = list(group_dir.glob("*.evtx"))
    if evtx_files:
        try:
            from evtx import PyEvtxParser
        except ImportError:
            return ids
        for evtx_file in evtx_files:
            try:
                p = PyEvtxParser(str(evtx_file))
                for rec in p.records():
                    m = re.search(r"<EventID>(\d+)</EventID>", rec["data"])
                    if m:
                        ids.add(m.group(1))
            except Exception:
                continue
    return ids


def rule_eventids(sigma_sql: str) -> set[str]:
    """Best-effort extraction of EventID=<n> literals referenced in the compiled SQL."""
    return set(re.findall(r"EventID\s*=\s*'?(\d+)'?", sigma_sql))


def main() -> None:
    matrix = json.loads(MATRIX_PATH.read_text())
    sql_by_id = load_rule_sql_by_id()
    report_lines = []

    telemetry_absent_count = 0
    logic_narrow_count = 0
    unknown_count = 0

    eventid_cache: dict[tuple[str, str], set[str]] = {}

    for technique, tdata in matrix.items():
        group_names = tdata["group_names"]
        for g in group_names:
            eventid_cache[(technique, g)] = eventids_in_group(technique, g)

        report_lines.append(f"=== {technique}: EventIDs present per group (from raw staged samples) ===")
        for g in group_names:
            report_lines.append(f"  {g}: {sorted(eventid_cache[(technique, g)], key=lambda x: int(x))}")
        report_lines.append("")

        report_lines.append(f"=== {technique}: miss diagnosis for rules that fired somewhere but not everywhere ===")
        for rid, info in sorted(tdata["detail"].items(), key=lambda kv: kv[1]["title"]):
            fired_in = {g for g, c in info["counts"].items() if c > 0}
            missed_in = [g for g in group_names if g not in fired_in]
            if not missed_in:
                continue  # survived everywhere, nothing to diagnose
            # we don't have the compiled SQL here without re-reading raw output; approximate via
            # cross-referencing the raw JSON that DOES carry the sigma SQL for at least one hit
            rule_sql = sql_by_id.get(rid, "")
            rule_eids = rule_eventids(rule_sql)
            report_lines.append(f"  {info['title']} (id {rid[:8]}...) targets EventID(s): {sorted(rule_eids) if rule_eids else 'unknown (not extracted from SQL)'}")
            for g in missed_in:
                present = eventid_cache[(technique, g)]
                if rule_eids and not (rule_eids & present):
                    verdict = "TELEMETRY ABSENT (rule's EventID never occurs in this group's raw data)"
                    telemetry_absent_count += 1
                elif rule_eids and (rule_eids & present):
                    verdict = "LOGIC TOO NARROW (rule's EventID is present in this group but the rule's field/value match still did not fire)"
                    logic_narrow_count += 1
                else:
                    verdict = "UNKNOWN (could not extract rule's target EventID from its SQL)"
                    unknown_count += 1
                report_lines.append(f"    MISSED in {g}: {verdict}")
                report_lines.append(f"      EventIDs present in that group: {sorted(present, key=lambda x: int(x)) if present else '(none extracted)'}")
        report_lines.append("")

    report_lines.append("=== Overall miss-cause tally across both techniques ===")
    report_lines.append(f"telemetry absent: {telemetry_absent_count}")
    report_lines.append(f"logic too narrow: {logic_narrow_count}")
    report_lines.append(f"unknown (SQL parse failed): {unknown_count}")

    out_path = ROOT / "evidence" / "04_miss_diagnosis.txt"
    out_path.write_text("\n".join(report_lines) + "\n")
    print("\n".join(report_lines))
    print(f"\nwrote {out_path}")


if __name__ == "__main__":
    main()
