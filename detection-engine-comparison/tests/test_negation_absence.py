"""Pin the negation/absence-of-event finding: a Sigma event_count
correlation with condition {lt: 1} compiles without error but the compiled
SQL can never match, because SQL GROUP BY never emits a row for an empty
group. This is REASONED FROM THE RULE MODEL AND DEMONSTRATED HERE, not
cited from a primary source: the task's own research pass found no
SigmaHQ documentation stating this limitation explicitly. That is stated
plainly in FINDINGS.md; this test file is the demonstration, not a
citation.
"""
from __future__ import annotations

import subprocess
import sqlite3

from conftest import ROOT, SIGMA_CLI, requires_sigma_cli

NEGATION_RULES_DIR = ROOT / "rules" / "sigma_negation_test"


@requires_sigma_cli
def test_lt_condition_compiles_without_error():
    proc = subprocess.run(
        [str(SIGMA_CLI), "convert", "-t", "sqlite", "-p", "sysmon", str(NEGATION_RULES_DIR)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout.strip()
    assert "HAVING event_count < 1" in out


@requires_sigma_cli
def test_compiled_absence_query_cannot_match_a_real_zero_count_case():
    proc = subprocess.run(
        [str(SIGMA_CLI), "convert", "-t", "sqlite", "-p", "sysmon", str(NEGATION_RULES_DIR)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    query = proc.stdout.strip()

    con = sqlite3.connect(":memory:")
    cur = con.cursor()
    cur.execute(
        "CREATE TABLE logs (EventID INTEGER, TicketEncryptionType TEXT, TargetUserName TEXT)"
    )
    cur.executemany(
        "INSERT INTO logs VALUES (?,?,?)",
        [
            (4769, "0x17", "alice"),  # alice: qualifying event exists
            (4769, "0x17", "alice"),
            (4769, "0x12", "bob"),  # bob: real event, but 0 qualifying ones
        ],
    )
    con.commit()

    rows = cur.execute(query).fetchall()
    # bob genuinely made zero qualifying requests. If the correlation could
    # express absence, bob would appear here. He never can, by construction.
    assert rows == []
