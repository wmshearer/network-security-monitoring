#!/usr/bin/env python3
"""Empirically prove that a Sigma event_count correlation rule with an
`lt` condition cannot express "this principal made zero qualifying
requests," even though the specification allows `lt` as a condition
operator and pySigma compiles it without error.

Research context: the task that produced this project found no primary
source stating this limitation explicitly (SigmaHQ's correlation spec at
https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md
documents `lt` as a valid condition operator with no caveat about it being
unable to match zero-count groups). So this script demonstrates the
limitation directly, from the rule model itself, rather than citing a
source that does not exist. This is reasoned-and-demonstrated, not
cited-from-authority; that distinction is stated again in FINDINGS.md.

Method: compile a Sigma correlation rule with `condition: {lt: 1}` (real
sigma-cli invocation, see evidence/18_negation_sqlite_compile.txt for the
exact compiled SQL) then RUN that exact SQL against a real SQLite
in-memory database seeded with a case the rule is meant to catch: a
principal ("bob") with a real event that does NOT qualify (a different
TicketEncryptionType), which should mean "zero qualifying RC4 requests for
bob" and should be exactly what an absence-of-event rule needs to surface.

The query, run for real, returns zero rows. Not "zero rows because there
were zero events at all" -- bob has a real, present event, just not a
qualifying one. A SQL GROUP BY never emits a row for a group that has no
rows to group in the underlying filtered result set, so `HAVING event_count
< 1` can never be satisfied by any GROUP BY query, for any input data. This
is a structural fact about SQL aggregation, not a bug in this particular
compiled query, and it is why this project treats the correlation
mechanism as fundamentally unable to express "absence of a qualifying
event for one principal," not merely awkward at it.
"""

from __future__ import annotations

import sqlite3


COMPILED_ABSENCE_QUERY = (
    "SELECT TargetUserName, COUNT(*) AS event_count FROM "
    "(SELECT * FROM logs WHERE EventID=4769 AND TicketEncryptionType='0x17') "
    "AS subquery GROUP BY TargetUserName HAVING event_count < 1"
)


def main() -> int:
    con = sqlite3.connect(":memory:")
    cur = con.cursor()
    cur.execute(
        "CREATE TABLE logs (EventID INTEGER, TicketEncryptionType TEXT, TargetUserName TEXT)"
    )
    # alice: 2 qualifying RC4 TGS requests (has the "signal" the rule targets)
    # bob:   1 real event, but NOT RC4 (0x12, not 0x17) -- bob made ZERO
    #        qualifying requests, which is exactly the case an
    #        "absence of qualifying event" rule should catch.
    cur.executemany(
        "INSERT INTO logs VALUES (?,?,?)",
        [
            (4769, "0x17", "alice"),
            (4769, "0x17", "alice"),
            (4769, "0x12", "bob"),
        ],
    )
    con.commit()

    rows = cur.execute(COMPILED_ABSENCE_QUERY).fetchall()

    print("Compiled query (from `sigma convert -t sqlite` on an event_count")
    print("correlation with condition: {lt: 1}):")
    print("  " + COMPILED_ABSENCE_QUERY)
    print()
    print("Seed data: alice has 2 qualifying events; bob has 1 event that")
    print("does NOT qualify (0 qualifying events for bob).")
    print()
    print("Rows returned:", rows)
    print()
    if rows == []:
        print(
            "CONFIRMED: the query returns zero rows. bob, who genuinely made "
            "zero qualifying requests, does not appear. A GROUP BY query "
            "never emits a row for a group with no members in the filtered "
            "subquery, so HAVING event_count < 1 is unsatisfiable by "
            "construction, for any data."
        )
        return 0
    else:
        print(
            "UNEXPECTED: rows were returned. This would contradict the "
            "claim above and needs re-investigation before publishing it."
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
