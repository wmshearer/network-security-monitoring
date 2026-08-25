"""
Run every query in sql/ against the database and print what each returns.

This is the script a reader runs to reproduce the whole project. It does no
analysis of its own. Each query is a file, the file is the artifact, and this
just executes them in order and shows the output.

Queries that can be scored against ground truth are scored. The one that
cannot is labelled as unscored rather than given a flattering number.
"""

import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "data" / "events.db"
SQL_DIR = ROOT / "sql"

# What each query is for, and whether this corpus can score it.
NOTES = {
    "01_beaconing.sql": (
        "Callbacks on a schedule. SCORED: 50% precision, and tightening the "
        "threshold makes it worse. See docs/FINDING.md."
    ),
    "02_scanning.sql": (
        "One source, many silent targets. SCORED: separates Torii (63.4% "
        "silent) from benign (6.3%) by a factor of ten."
    ),
    "03_exploit_burst.sql": (
        "Dense traffic to one service. SCORED: finds all three attack "
        "captures, no benign false positives."
    ),
    "04_first_contact.sql": (
        "Destinations absent from the baseline. UNSCORED: the corpus cannot "
        "evaluate it, because the malicious capture is compromised throughout "
        "and its baseline already contains the bad channels."
    ),
}


def run_query(conn, path: Path):
    sql = path.read_text()
    cur = conn.execute(sql)
    cols = [d[0] for d in cur.description]
    rows = cur.fetchall()
    return cols, rows


def render(cols, rows, limit=12):
    if not rows:
        print("    (no rows)")
        return
    widths = [len(c) for c in cols]
    for r in rows[:limit]:
        for i, v in enumerate(r):
            widths[i] = max(widths[i], len(str(v)))
    header = "  ".join(c.ljust(widths[i]) for i, c in enumerate(cols))
    print("    " + header)
    print("    " + "  ".join("-" * w for w in widths))
    for r in rows[:limit]:
        print("    " + "  ".join(str(v).ljust(widths[i]) for i, v in enumerate(r)))
    if len(rows) > limit:
        print(f"    ... {len(rows) - limit} more rows")


def main():
    if not DB.exists():
        print(f"No database at {DB}. Run src/ingest.py first.", file=sys.stderr)
        return 1

    conn = sqlite3.connect(DB)

    total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    captures = conn.execute("SELECT COUNT(DISTINCT capture) FROM events").fetchone()[0]
    print(f"Corpus: {total_events:,} events from {captures} public captures\n")

    for path in sorted(SQL_DIR.glob("*.sql")):
        print("=" * 78)
        print(path.name)
        note = NOTES.get(path.name)
        if note:
            print(f"  {note}")
        print("=" * 78)
        cols, rows = run_query(conn, path)
        print(f"  {len(rows)} row(s)")
        render(cols, rows)
        print()

    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
