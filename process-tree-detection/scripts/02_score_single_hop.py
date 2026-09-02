#!/usr/bin/env python3
"""Score every Zircolite-compiled Sigma rule against both corpora, faithfully.

This reuses the SAME compiled SQL that the sibling project (detection-rule-lab)
runs through Zircolite, at vendor/Zircolite/rules/rules_windows_sysmon.json.
Zircolite compiles each Sigma detection into a SQL WHERE clause with pySigma's
SQLite backend, then runs it in SQLite; that JSON file already contains the
compiled SQL strings. Re-executing them directly in Python's stdlib sqlite3
module reproduces Zircolite's own matching logic exactly, without needing to
install its (large, version-sensitive) dependency stack.

Why this matters for the tree-detection question: nearly the entire Zircolite
Windows/Sysmon ruleset compiles down to a single "SELECT * FROM logs WHERE ..."
statement evaluated against ONE ROW at a time. Every field a condition can name
(Image, ParentImage, CommandLine, User, ...) comes from that one row: one
process creation event. The one documented exception found in this ruleset is
GrandParentImage, used by exactly 2 of 2,691 rules; see FINDINGS.md for why
that is not actually a counterexample (it is not a Sysmon field, so it is
always NULL against this data and those 2 rules can never fire here).

Output: evidence/single_hop_scoring.json, one row per rule with malicious_hits
and benign_hits, computed by running its real compiled SQL against a SQLite
table built from the corpus. Also evidence/single_hop_sdclt_case.json, the
specific before/after for the sdclt.exe -> control.exe -> powershell.exe
chain used as the GUI evidence.

Usage:
    python3 scripts/02_score_single_hop.py
"""
from __future__ import annotations

import json
import re
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = Path("/home/kali/director/projects/detection-rule-lab/data/events")
RULESET = Path(
    "/home/kali/director/projects/detection-rule-lab/vendor/Zircolite/rules/"
    "rules_windows_sysmon.json"
)
EVIDENCE_DIR = ROOT / "evidence"

CORPORA = {
    "malicious": SOURCE_DIR / "malicious.jsonl",
    "benign": SOURCE_DIR / "benign.jsonl",
}


def sqlite_regexp(pattern, value):
    """REGEXP support for SQLite, backing Sigma's |re modifier.

    Stock SQLite has no REGEXP function; the `x REGEXP y` operator only works
    if the host application registers one, which Zircolite does (via
    pysigma-backend-sqlite) and this reproduces with Python's re module.
    Sigma's |re modifier does a partial (search-anywhere) match, not a
    full-string match, so re.search is the correct semantics here.
    """
    if value is None or pattern is None:
        return False
    try:
        return re.search(pattern, str(value)) is not None
    except re.error:
        return False


def discover_columns_from_ruleset(rules: list[dict]) -> set[str]:
    """Extract every column name referenced in the compiled SQL, as a backstop.

    Sampling the corpus for field names (discover_columns) can miss a field
    that never happens to appear in the sample of events actually present in
    this corpus, causing "no such column" instead of the correct "0 matches
    since the corpus lacks this field". Parsing the compiled SQL text and
    unioning those names with the corpus-discovered ones guarantees every
    column a rule can reference exists in the table, defaulting to NULL where
    absent from the data, which is the correct value for "field not present".
    """
    # Compiled Zircolite SQL uses bare identifiers (no quoting), e.g.
    #   ParentImage LIKE '%\\sdclt.exe' ESCAPE '\'
    #   CommandLine REGEXP ':[^ \\]'
    # so a column name is a bareword directly followed by a comparison
    # operator, LIKE, GLOB, IS, or REGEXP. This is intentionally permissive
    # (it will also catch a few false positives like "EventID" or "AND" if
    # they happen to precede such a token) since extra harmless NULL columns
    # cost nothing, whereas a missing real column breaks a rule's query.
    cols: set[str] = set()
    identifier = re.compile(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|<>|!=|<|>|\bLIKE\b|\bGLOB\b|\bIS\b|\bREGEXP\b)"
    )
    sql_keywords = {
        "AND", "OR", "NOT", "SELECT", "FROM", "WHERE", "IS", "IN", "NULL",
        "LIKE", "GLOB", "REGEXP", "ESCAPE",
    }
    for r in rules:
        for stmt in r.get("rule", []):
            for m in identifier.findall(stmt):
                if m.upper() not in sql_keywords:
                    cols.add(m)
    return cols


def discover_columns(paths: list[Path]) -> list[str]:
    """One streaming pass per file to collect the union of all JSON keys.

    SQLite needs a fixed column list to CREATE TABLE. A key present in some
    events but not others is fine: sqlite3's row insertion supplies NULL for
    columns a given record does not have, which is the correct semantics for
    "this rule's field was absent from this event" (the condition on it can
    never be true, so it correctly contributes no match).
    """
    # SQLite column names are compared case-INSENSITIVELY for uniqueness
    # within a table, but this data has both spellings of some fields (for
    # example "IpAddress" and "Ipaddress" from different source pipelines).
    # Keep one canonical spelling per case-fold group so CREATE TABLE does
    # not collide; the first spelling seen wins, and rule SQL is matched
    # case-insensitively by SQLite anyway so no condition changes meaning.
    seen: dict[str, str] = {}
    for path in paths:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                for key in rec.keys():
                    seen.setdefault(key.lower(), key)
    return sorted(seen.values())


def to_sql_value(v, column=None):
    """JSON value -> a SQLite-storable scalar. Lists/dicts become JSON text.

    Channel is special-cased to a canonical capitalization. This corpus has
    both 'Security' and 'security' as the same Windows event channel (a
    difference in the two source collection pipelines, OTRF Mordor vs
    NextronSystems, not a real distinct channel); confirmed by checking every
    distinct Channel value in both files (see evidence file for the check).
    Every compiled rule condition uses 'Security' with a capital S, and a
    live Zircolite run (reports/scoring-run.json in the sibling project,
    read-only reference) matches 'security'-channel events against those
    rules, so its pipeline evidently normalizes channel case before matching.
    SQLite's default TEXT '=' is case-sensitive, so without this the 9 rules
    that key on Channel='Security' would wrongly show 0 malicious hits here.
    """
    if column == "Channel" and isinstance(v, str) and v.lower() == "security":
        v = "Security"
    if v is None or isinstance(v, (str, int, float)):
        return v
    if isinstance(v, bool):
        return int(v)
    return json.dumps(v)


def load_corpus_into_sqlite(con: sqlite3.Connection, path: Path, columns: list[str]) -> int:
    quoted_cols = ", ".join(f'"{c}"' for c in columns)
    placeholders = ", ".join("?" for _ in columns)
    con.execute(f"CREATE TABLE logs ({quoted_cols})")
    insert_sql = f"INSERT INTO logs ({quoted_cols}) VALUES ({placeholders})"
    n = 0
    batch = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            rec_lower = {k.lower(): v for k, v in rec.items()}
            row = [to_sql_value(rec_lower.get(c.lower()), column=c) for c in columns]
            batch.append(row)
            n += 1
            if len(batch) >= 5000:
                con.executemany(insert_sql, batch)
                batch.clear()
    if batch:
        con.executemany(insert_sql, batch)
    con.commit()
    # Nearly every compiled rule filters on Channel and EventID first (see the
    # module docstring: "SELECT * FROM logs WHERE Channel=... AND (EventID=...
    # AND ...)"). Indexing them lets SQLite's planner narrow each of the 2,691
    # per-rule table scans to a handful of candidate rows instead of scanning
    # all ~834k/110k rows per rule, which is what makes scoring the full
    # ruleset against both corpora finish in minutes instead of hours.
    con.execute('CREATE INDEX idx_channel_eventid ON logs ("Channel", "EventID")')
    con.commit()
    return n


def load_ruleset() -> list[dict]:
    with RULESET.open() as f:
        return json.load(f)


def score_corpus(con: sqlite3.Connection, rules: list[dict], label: str) -> dict[str, int]:
    """Run every rule's compiled SQL and count matched rows. rule_id -> hits."""
    hits: dict[str, int] = {}
    cur = con.cursor()
    t0 = time.time()
    for i, rule in enumerate(rules, start=1):
        rid = rule["id"]
        total = 0
        for stmt in rule.get("rule", []):
            try:
                cur.execute(stmt)
                total += len(cur.fetchall())
            except sqlite3.Error as e:
                # A statement referencing a column absent from our discovered
                # schema would be a bug in discover_columns, not expected;
                # record it loudly rather than silently treating as 0.
                print(f"SQL ERROR rule={rid}: {e}", file=sys.stderr)
        hits[rid] = hits.get(rid, 0) + total
        if i % 500 == 0:
            print(f"  [{label}] {i}/{len(rules)} rules scored ({time.time()-t0:.1f}s)")
    return hits


def main():
    if not RULESET.exists():
        print(f"SKIP: ruleset not found at {RULESET}", file=sys.stderr)
        return
    for name, path in CORPORA.items():
        if not path.exists():
            print(f"SKIP: {name} corpus not found at {path}", file=sys.stderr)
            return

    t0 = time.time()
    rules = load_ruleset()
    print(f"Loaded {len(rules)} compiled rules from {RULESET}")

    print("Discovering column schema across both corpora (one streaming pass each)...")
    columns = discover_columns(list(CORPORA.values()))
    # Union with every column name any compiled rule references, so a rule
    # naming a field this corpus never happens to populate gets a real NULL
    # column (correctly: 0 matches) instead of a SQL error.
    from_data = len(columns)
    ruleset_cols = discover_columns_from_ruleset(rules)
    seen_lower = {c.lower() for c in columns}
    for c in sorted(ruleset_cols):
        if c.lower() not in seen_lower:
            columns.append(c)
            seen_lower.add(c.lower())
    print(
        f"  {from_data} fields observed in corpus data, "
        f"{len(columns) - from_data} more backstopped from ruleset SQL text "
        f"(these will be all-NULL columns), {len(columns)} total. "
        f"({time.time()-t0:.1f}s)"
    )

    results: dict[str, dict] = {}
    for name, path in CORPORA.items():
        t1 = time.time()
        con = sqlite3.connect(":memory:")
        con.create_function("REGEXP", 2, sqlite_regexp)
        n = load_corpus_into_sqlite(con, path, columns)
        print(f"[{name}] loaded {n} events into SQLite ({time.time()-t1:.1f}s)")
        t2 = time.time()
        hits = score_corpus(con, rules, name)
        fired = sum(1 for h in hits.values() if h > 0)
        total_hits = sum(hits.values())
        print(
            f"[{name}] scored {len(rules)} rules: {fired} fired, "
            f"{total_hits} total matched events ({time.time()-t2:.1f}s)"
        )
        results[name] = hits
        con.close()

    # Join by rule id.
    by_id = {r["id"]: r for r in rules}
    rows = []
    for rid in by_id:
        rule = by_id[rid]
        mal = results.get("malicious", {}).get(rid, 0)
        ben = results.get("benign", {}).get(rid, 0)
        rows.append(
            {
                "rule_id": rid,
                "title": rule.get("title"),
                "level": rule.get("level"),
                "tags": rule.get("tags", []),
                "malicious_hits": mal,
                "benign_hits": ben,
            }
        )

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    out_path = EVIDENCE_DIR / "single_hop_scoring.json"
    with out_path.open("w") as f:
        json.dump(
            {
                "ruleset_file": str(RULESET),
                "ruleset_rule_count": len(rules),
                "malicious_source": str(CORPORA["malicious"]),
                "benign_source": str(CORPORA["benign"]),
                "columns_discovered": len(columns),
                "rows": rows,
            },
            f,
            indent=2,
        )
    print(f"Wrote {out_path}")

    # Case study extraction: which rules matched the specific sdclt.exe chain
    # events (used later for the GUI annotation and FINDINGS.md).
    sdclt_case = extract_sdclt_case(rows, results)
    case_path = EVIDENCE_DIR / "single_hop_sdclt_case.json"
    with case_path.open("w") as f:
        json.dump(sdclt_case, f, indent=2)
    print(f"Wrote {case_path}")

    print(f"Total runtime: {time.time()-t0:.1f}s")


def extract_sdclt_case(rows: list[dict], results: dict) -> dict:
    """Which of the fired rules are about sdclt.exe/control.exe specifically.

    This does not re-derive hit counts (already computed above); it just
    filters the already-computed rows to the handful of rules whose title or
    id names this specific chain, for the FINDINGS.md case study and the GUI
    annotation. Kept separate from the full table so the specific claim about
    this one chain is traceable to its own small evidence file.
    """
    keywords = ("sdclt", "uac bypass")
    matches = [
        r
        for r in rows
        if any(k in (r["title"] or "").lower() for k in keywords)
    ]
    return {"rules_naming_sdclt_or_uac_bypass": matches}


if __name__ == "__main__":
    main()
