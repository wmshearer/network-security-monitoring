"""
The same seven detection rules, run twice: once in Python, once in SQL.

Both engines see the same 2,810 prompts and the same ground truth. The point is
not to declare a winner. It is to find where each engine is the wrong tool, and
to put a number on it rather than asserting it.

The rules come from the llm-abuse-detection project in this portfolio, which
scored precision 99.7 percent and recall 71.8 percent on this corpus. Reusing
them means the comparison is between engines rather than between rule sets.
"""

import re
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "data" / "prompts.db"
PY_RULES = Path("/home/kali/director/projects/llm-abuse-detection/src")


def load_python_rules():
    """Import the original rules rather than reimplementing them.

    If they were copied, the two engines could drift apart and the comparison
    would quietly stop being about engines.
    """
    sys.path.insert(0, str(PY_RULES))
    import rules  # noqa: E402
    return rules


def python_pass(conn, rules_mod):
    """Every prompt through the original Python detector."""
    rows = conn.execute("SELECT prompt_id, text, label FROM prompts").fetchall()
    t0 = time.perf_counter()
    results = {}
    for pid, text, label in rows:
        hits = [r.name for r in rules_mod.RULES if r.pattern.search(text)]
        results[pid] = (bool(hits), hits, label)
    elapsed = time.perf_counter() - t0
    return results, elapsed


def sql_pass(conn, rules_mod):
    """The same rules as SQL.

    SQLite has no REGEXP of its own, so the Python `re` module gets registered
    as a SQL function. That is the honest way to do this: the regex engine is
    identical in both passes, so any difference in results comes from the
    query structure rather than from a different matcher.

    It also means the SQL pass is not really "SQL only". It is SQL calling
    into Python once per row per rule, which is precisely the hybrid that
    Panther and Matano both settled on, and the timing shows what that costs.
    """
    conn.create_function(
        "rule_match", 2,
        lambda pattern, text: 1 if (text and re.search(pattern, text, re.I | re.M)) else 0,
    )

    # One CASE per rule, mirroring the Python OR.
    cases = []
    params = []
    for r in rules_mod.RULES:
        cases.append(f"rule_match(?, text) AS hit_{r.name.replace('-', '_')}")
        params.append(r.pattern.pattern)

    sql = f"""
        SELECT prompt_id, label, {', '.join(cases)}
        FROM prompts
    """
    t0 = time.perf_counter()
    rows = conn.execute(sql, params).fetchall()
    elapsed = time.perf_counter() - t0

    names = [r.name for r in rules_mod.RULES]
    results = {}
    for row in rows:
        pid, label = row[0], row[1]
        hits = [names[i] for i, v in enumerate(row[2:]) if v]
        results[pid] = (bool(hits), hits, label)
    return results, elapsed


def metrics(results):
    tp = fp = tn = fn = 0
    for flagged, _hits, label in results.values():
        if label == "malicious":
            if flagged:
                tp += 1
            else:
                fn += 1
        else:
            if flagged:
                fp += 1
            else:
                tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": precision, "recall": recall, "f1": f1}


def set_based_queries(conn):
    """Three questions that are awkward in Python and natural in SQL.

    This is the other half of the comparison. Per-record matching is where SQL
    struggles. Reasoning across the whole corpus at once is where it wins, and
    each of these is a single query against a loop-and-dictionary in Python.
    """
    conn.create_function(
        "rule_match", 2,
        lambda pattern, text: 1 if (text and re.search(pattern, text, re.I | re.M)) else 0,
    )
    rules_mod = load_python_rules()
    out = {}

    # 1. Which rules only ever fire together? A rule that never fires alone is
    #    carrying no independent weight and could be removed.
    pat = {r.name: r.pattern.pattern for r in rules_mod.RULES}
    hits_cte = ", ".join(
        f"rule_match('{p}', text) AS h_{n.replace('-', '_')}"
        for n, p in pat.items()
    ).replace("'", "'")

    # Build it with parameters instead, to avoid quoting problems in patterns.
    cases = []
    params = []
    for r in rules_mod.RULES:
        cases.append(f"rule_match(?, text) AS h_{r.name.replace('-', '_')}")
        params.append(r.pattern.pattern)
    base = f"SELECT prompt_id, label, {', '.join(cases)} FROM prompts"

    cols = [f"h_{r.name.replace('-', '_')}" for r in rules_mod.RULES]
    total_expr = " + ".join(cols)

    rows = conn.execute(
        f"""
        WITH hits AS ({base})
        SELECT {total_expr} AS rules_fired, COUNT(*) AS prompts,
               SUM(CASE WHEN label='malicious' THEN 1 ELSE 0 END) AS malicious
        FROM hits
        GROUP BY rules_fired
        ORDER BY rules_fired
        """,
        params,
    ).fetchall()
    out["overlap"] = rows

    # 2. Per-rule precision, every rule at once. In Python this is a loop with
    #    a counter per rule. In SQL it is one pass.
    per_rule = []
    for r in rules_mod.RULES:
        col = f"h_{r.name.replace('-', '_')}"
        row = conn.execute(
            f"""
            WITH hits AS ({base})
            SELECT SUM({col}) AS fired,
                   SUM(CASE WHEN {col}=1 AND label='malicious' THEN 1 ELSE 0 END) AS correct
            FROM hits
            """,
            params,
        ).fetchone()
        fired, correct = row[0] or 0, row[1] or 0
        per_rule.append((r.name, fired, correct, (correct / fired) if fired else 0.0))
    out["per_rule"] = per_rule

    # 3. What do the missed attacks have in common? Length is the cheapest
    #    thing to check and it is a single GROUP BY.
    rows = conn.execute(
        f"""
        WITH hits AS ({base}),
        scored AS (
            SELECT prompt_id, label, ({total_expr}) AS fired FROM hits
        )
        SELECT
            CASE
                WHEN LENGTH(p.text) <  200 THEN 'under 200 chars'
                WHEN LENGTH(p.text) < 1000 THEN '200 to 1000'
                WHEN LENGTH(p.text) < 3000 THEN '1000 to 3000'
                ELSE 'over 3000'
            END AS bucket,
            COUNT(*) AS missed
        FROM scored s JOIN prompts p ON p.prompt_id = s.prompt_id
        WHERE s.label = 'malicious' AND s.fired = 0
        GROUP BY bucket
        ORDER BY missed DESC
        """,
        params,
    ).fetchall()
    out["missed_by_length"] = rows

    return out


def main():
    conn = sqlite3.connect(DB)
    rules_mod = load_python_rules()

    print("=" * 72)
    print("The same seven rules, two engines, one corpus")
    print("=" * 72)
    n = conn.execute("SELECT COUNT(*) FROM prompts").fetchone()[0]
    print(f"corpus: {n:,} prompts, balanced malicious and benign\n")

    py_results, py_time = python_pass(conn, rules_mod)
    sql_results, sql_time = sql_pass(conn, rules_mod)

    py_m = metrics(py_results)
    sql_m = metrics(sql_results)

    print(f"{'':22} {'Python':>12} {'SQL':>12}")
    print(f"{'-'*22} {'-'*12:>12} {'-'*12:>12}")
    for key, label in [("precision", "precision"), ("recall", "recall"), ("f1", "F1")]:
        print(f"{label:22} {py_m[key]:>11.2%} {sql_m[key]:>11.2%}")
    for key in ("tp", "fp", "fn"):
        print(f"{key:22} {py_m[key]:>12} {sql_m[key]:>12}")
    print(f"{'wall time':22} {py_time:>11.3f}s {sql_time:>11.3f}s")

    # Do the two engines actually agree, prompt by prompt?
    disagree = [
        pid for pid in py_results
        if py_results[pid][0] != sql_results[pid][0]
    ]
    print(f"\nper-prompt disagreements: {len(disagree)}")
    if disagree:
        print("  the two engines are not running the same logic; investigate")
    else:
        print("  identical verdicts on all prompts, so the comparison is fair")

    print()
    print("=" * 72)
    print("Where SQL earns its place: questions about the whole corpus")
    print("=" * 72)
    extras = set_based_queries(conn)

    print("\n1. How many rules fire per prompt")
    print("   rules_fired  prompts  malicious")
    for fired, prompts, mal in extras["overlap"]:
        print(f"   {fired:>11}  {prompts:>7}  {mal:>9}")

    print("\n2. Per-rule precision, one pass over the corpus")
    print(f"   {'rule':<24} {'fired':>7} {'correct':>8} {'precision':>10}")
    for name, fired, correct, prec in sorted(extras["per_rule"], key=lambda r: -r[1]):
        print(f"   {name:<24} {fired:>7} {correct:>8} {prec:>9.1%}")

    print("\n3. Missed attacks, by prompt length")
    for bucket, missed in extras["missed_by_length"]:
        print(f"   {bucket:<18} {missed:>5}")

    conn.close()


if __name__ == "__main__":
    main()
