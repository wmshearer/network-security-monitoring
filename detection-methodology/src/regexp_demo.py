"""
The same query, twice: once failing, once working.

sql/05_regex_limit.sql uses the REGEXP operator. SQLite parses it but ships no
implementation, so it has to be registered by whatever program opens the
database.

The part I got wrong on the first attempt, and kept because it is the more
useful finding: this is not a version question. On this machine the sqlite3
CLI and Python's sqlite3 module both report SQLite 3.46.1, and the CLI has
REGEXP while Python does not. The shell binary registers one; the library does
not. Availability follows the host application.

The practical consequence is a bad failure order. A Sigma rule using the `re`
modifier can be tested successfully in the shell and then break inside a
Python detection pipeline, because pySigma's SQLite backend compiles `re`
straight to REGEXP.

Registering it is three lines. The reason it gets a file to itself is that it
marks the line this project is about: SQL is excellent at filtering, grouping
and joining at scale, and it hands off the moment the work becomes per-record
string logic. Every production platform in the research does that handoff.
"""

import re
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "data" / "events.db"
QUERY = (ROOT / "sql" / "05_regex_limit.sql").read_text()


def regexp(pattern: str, value: str) -> bool:
    """SQLite calls this as regexp(Y, X) for the expression `X REGEXP Y`.

    Note the argument order. It is the reverse of what the SQL reads like, and
    getting it backwards produces a query that runs and silently returns
    nothing, which is worse than an error.
    """
    if value is None:
        return False
    return re.search(pattern, value) is not None


def show_versions():
    """Same version number, different capability. This is the whole point."""
    import subprocess

    print("0. Both report the same SQLite version")
    print("   " + "-" * 60)
    print(f"   python sqlite3 module links: {sqlite3.sqlite_version}")
    cli = subprocess.run(["sqlite3", "--version"], capture_output=True, text=True)
    print(f"   sqlite3 CLI reports:         {cli.stdout.split()[0]}")

    shell = subprocess.run(
        ["sqlite3", ":memory:", "SELECT 'abc' REGEXP 'b';"],
        capture_output=True, text=True,
    )
    got = shell.stdout.strip() or shell.stderr.strip()
    print(f"   CLI, 'abc' REGEXP 'b'   ->  {got}")


def without_registration():
    print("\n1. Python, same version, no registration")
    print("   " + "-" * 60)
    conn = sqlite3.connect(DB)
    try:
        conn.execute(QUERY).fetchall()
        print("   unexpectedly succeeded")
    except sqlite3.OperationalError as exc:
        print(f"   OperationalError: {exc}")
        print("   The CLI ran this fine. The library will not.")
        print("   This is what a Sigma rule using the `re` modifier hits.")
    finally:
        conn.close()


def with_registration():
    print("\n2. Same query, after create_function('regexp', 2, ...)")
    print("   " + "-" * 60)
    conn = sqlite3.connect(DB)
    conn.create_function("regexp", 2, regexp)
    rows = conn.execute(QUERY).fetchall()
    print(f"   {len(rows)} row(s)")
    for capture, src, dst, proto, packets in rows[:8]:
        print(f"   {proto:<6} {src:>15} -> {dst:<15} {packets:>5}  {capture}")
    conn.close()


def where_sql_gives_up():
    """A worked example of the handoff, not an assertion about it.

    Counting packets per protocol is set work and belongs in SQL. Deciding
    whether a byte sequence looks like an SMB negotiate followed by a
    transaction with a mismatched displacement is per-record parsing, and it
    belongs in code. The EternalBlue project elsewhere in this portfolio does
    exactly that second half in Python, because the discriminator is a field
    inside a packet rather than a property of a group of packets.
    """
    print("\n3. Where the handoff happens")
    print("   " + "-" * 60)
    conn = sqlite3.connect(DB)
    conn.create_function("regexp", 2, regexp)

    # SQL narrows 74,040 events to the handful worth parsing.
    rows = conn.execute(
        """
        SELECT capture, source_ip, destination_ip, COUNT(*) AS packets
        FROM events
        WHERE destination_port = 445
        GROUP BY capture, source_ip, destination_ip
        HAVING COUNT(*) > 50
        """
    ).fetchall()
    print(f"   SQL narrowed the corpus to {len(rows)} candidate conversation(s):")
    for capture, src, dst, packets in rows:
        print(f"     {src} -> {dst}  {packets} packets  ({capture})")
    print("   Confirming EternalBlue then needs the Multiplex ID of a Trans2")
    print("   response, which is a field inside a packet. SQL cannot reach it.")
    print("   That is the boundary, and it is where Python takes over.")
    conn.close()


if __name__ == "__main__":
    show_versions()
    without_registration()
    with_registration()
    where_sql_gives_up()
