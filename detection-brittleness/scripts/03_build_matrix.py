#!/usr/bin/env python3
"""Stage 3: build the rule x tool x dataset survival matrix.

Reads the raw Zircolite output saved by 02_run_zircolite.py (never
hand-edited) and the full ruleset (to know which rules were even eligible,
i.e. tagged for the technique, so a rule that never had a chance to fire is
not silently conflated with one that fired elsewhere and missed here).

Writes evidence/03_matrix.json (machine-readable) and
evidence/03_matrix_summary.txt (human-readable table), which FINDINGS.md
quotes numbers from directly. Every number in this file is recomputed from
the raw JSON, not carried over by hand.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "evidence" / "zircolite_raw"
RULESET = Path("/home/kali/director/projects/detection-as-code/vendor/Zircolite/rules/rules_windows_merged.json")

TECHNIQUES = ["T1003.001", "T1059.001"]


def eligible_rule_ids(tag: str) -> tuple[set[str], int]:
    """Distinct Sigma rule IDs tagged for this technique, and the raw compiled-entry count.

    The two numbers differ because rules_windows_merged.json compiles some
    Sigma rules more than once under the same id, once per log-source variant
    (observed here: "<Title> - Generic" targeting Security EventID 4688 and
    "<Title> - Sysmon" targeting Sysmon EventID 1, same underlying detection
    intent, different source). The rule-id count (deduplicated) is what is
    reported as "how many distinct detections", the raw count is reported
    alongside for transparency.
    """
    rules = json.loads(RULESET.read_text())
    tag_l = f"attack.{tag.lower()}"
    matches = [r for r in rules if tag_l in [t.lower() for t in r.get("tags", [])]]
    return {r["id"] for r in matches}, len(matches)


def load_groups(technique: str) -> dict[str, list[dict]]:
    tech_dir = RAW_DIR / technique
    groups = {}
    for f in sorted(tech_dir.glob("*.json")):
        groups[f.stem] = json.loads(f.read_text() or "[]")
    return groups


def main() -> None:
    matrix_out = {}
    lines = []

    for technique in TECHNIQUES:
        eligible, eligible_raw_count = eligible_rule_ids(technique)
        groups = load_groups(technique)
        group_names = list(groups.keys())

        # rule_id -> {title, per-group count}
        rules_seen: dict[str, dict] = {}
        for gname, matches in groups.items():
            for m in matches:
                rid = m["id"]
                if rid not in eligible:
                    continue  # rule fired but isn't tagged for this technique; out of scope for this matrix
                rules_seen.setdefault(rid, {"title": m["title"], "level": m.get("rule_level"), "counts": {}})
                rules_seen[rid]["counts"][gname] = m.get("count", 0)

        lines.append(f"=== {technique} ===")
        lines.append(f"Eligible (technique-tagged) distinct Sigma rule IDs in ruleset: {len(eligible)} "
                      f"({eligible_raw_count} compiled rule-variants; the ruleset compiles some rules twice, "
                      f"once per log-source variant, same id)")
        lines.append(f"Sample groups scored: {group_names}")
        lines.append(f"Technique-tagged rules that fired in at least one group: {len(rules_seen)}")
        lines.append("")

        survived_all = []
        partial = []
        for rid, info in sorted(rules_seen.items(), key=lambda kv: kv[1]["title"]):
            fired_in = [g for g in group_names if info["counts"].get(g, 0) > 0]
            row = f"  [{info['level']:>6}] {info['title']} (id {rid[:8]}...)"
            counts_str = "  ".join(f"{g}={info['counts'].get(g, 0)}" for g in group_names)
            lines.append(row)
            lines.append(f"           {counts_str}")
            if len(fired_in) == len(group_names):
                survived_all.append(rid)
            else:
                partial.append(rid)

        lines.append("")
        lines.append(f"Fired in EVERY sample group scored for {technique}: {len(survived_all)} / {len(rules_seen)}")
        lines.append(f"Fired in SOME but not all groups: {len(partial)} / {len(rules_seen)}")
        lines.append("")

        matrix_out[technique] = {
            "eligible_rule_count": len(eligible),
            "eligible_raw_compiled_variant_count": eligible_raw_count,
            "group_names": group_names,
            "rules_fired_at_least_once": len(rules_seen),
            "rules_fired_in_every_group": len(survived_all),
            "rules_fired_in_every_group_ids": survived_all,
            "detail": rules_seen,
        }

    matrix_path = ROOT / "evidence" / "03_matrix.json"
    matrix_path.write_text(json.dumps(matrix_out, indent=2))
    summary_path = ROOT / "evidence" / "03_matrix_summary.txt"
    summary_path.write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"\nwrote {matrix_path}\nwrote {summary_path}")


if __name__ == "__main__":
    main()
