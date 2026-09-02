"""
Tests that pin the findings in place.

These are not tests that the SQL parses. They assert the specific numbers the
project reports, so that a later edit cannot quietly change a published claim.
Several of them assert that a detection performs BADLY, which is the point:
the failures are the findings, and a change that made them disappear would
need to be noticed and explained.

Run: python3 -m pytest tests/ -v
"""

import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "data" / "events.db"
SQL = ROOT / "sql"

MALICIOUS = "192.168.100.103"   # CTU IoT-23 Torii
BENIGN = "192.168.1.132"        # CTU IoT-23 Philips Hue


@pytest.fixture(scope="module")
def conn():
    if not DB.exists():
        subprocess.run([sys.executable, str(ROOT / "src" / "ingest.py")], check=True)
    c = sqlite3.connect(DB)
    yield c
    c.close()


def run_sql(conn, name):
    return conn.execute((SQL / name).read_text()).fetchall()


# ---------------------------------------------------------------- corpus

def test_corpus_size(conn):
    """The published event count. If ingest changes, this must be updated
    deliberately rather than drifting."""
    n = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert n == 74040, f"corpus changed: {n} events, expected 74040"


def test_corpus_has_a_benign_control(conn):
    """The whole project depends on having benign traffic to compare against.
    Without it every detection scores perfectly and means nothing."""
    n = conn.execute(
        "SELECT COUNT(*) FROM events WHERE capture LIKE ?", (f"%{BENIGN}%",)
    ).fetchone()[0]
    assert n > 20000, "the benign control capture is missing or truncated"


def test_no_row_without_a_timestamp(conn):
    """Every time-based query depends on ts. A null would silently drop rows
    from window functions rather than erroring."""
    n = conn.execute("SELECT COUNT(*) FROM events WHERE ts IS NULL").fetchone()[0]
    assert n == 0


# ------------------------------------------------------------- beaconing

def test_beaconing_flags_both_classes(conn):
    """The headline finding: this query is 50 percent wrong at the obvious
    threshold. It flags five malicious pairs and five benign ones."""
    rows = run_sql(conn, "01_beaconing.sql")
    mal = sum(1 for r in rows if MALICIOUS in (r[0], r[1]))
    ben = sum(1 for r in rows if BENIGN in (r[0], r[1]))
    assert mal == 5, f"expected 5 malicious pairs, got {mal}"
    assert ben == 5, f"expected 5 benign pairs, got {ben}"


def test_the_steadiest_beacon_is_benign(conn):
    """The finding that inverts the intuition. The lowest-jitter pair in the
    whole corpus is the Philips Hue, not the botnet."""
    rows = run_sql(conn, "01_beaconing.sql")
    best = min(rows, key=lambda r: r[6])   # jitter column
    assert BENIGN in (best[0], best[1]), (
        "the steadiest beacon is no longer the benign device; "
        "the central finding of this project has changed"
    )
    assert best[6] < 0.001, f"expected near-zero jitter, got {best[6]}"


def test_tightening_the_threshold_makes_precision_worse(conn):
    """Counter-intuitive and load-bearing. At 0.02 jitter every survivor is
    benign, so precision is zero."""
    sys.path.insert(0, str(ROOT / "src"))
    from score import score

    loose = score(DB, 8, 0.15, quiet=True)
    tight = score(DB, 8, 0.02, quiet=True)

    assert loose["precision"] == 0.5
    assert tight["precision"] == 0.0, (
        "tightening the threshold no longer drives precision to zero; "
        "docs/FINDING.md needs revisiting"
    )


# -------------------------------------------------------------- scanning

def test_scanning_separates_malicious_from_benign(conn):
    """Unlike jitter, silence ratio points the right way."""
    rows = run_sql(conn, "02_scanning.sql")
    by_host = {r[1]: r[6] for r in rows}   # source_ip -> silent_ratio
    assert by_host[MALICIOUS] > 0.6
    assert by_host[BENIGN] < 0.1
    assert by_host[MALICIOUS] > by_host[BENIGN] * 5


def test_scanning_is_scoped_per_capture(conn):
    """Regression test for the host-identity bug. 192.168.1.46 appears in
    three captures years apart. Grouping on ip alone reported a three year
    scan window."""
    rows = run_sql(conn, "02_scanning.sql")
    for r in rows:
        window_s = r[7]
        assert window_s < 90000, (
            f"scan window of {window_s}s exceeds any single capture. "
            "The query has probably stopped grouping by capture."
        )


# --------------------------------------------------------- exploit burst

def test_exploit_burst_finds_every_attack_capture(conn):
    """All three exploitation captures, and nothing from the benign one."""
    rows = run_sql(conn, "03_exploit_burst.sql")
    captures = {r[0] for r in rows}
    assert any("eternalblue" in c.lower() for c in captures)
    assert any("rdp" in c.lower() for c in captures)
    assert not any(BENIGN in c for c in captures), (
        "the burst query has started flagging benign traffic"
    )


def test_exploit_burst_has_no_benign_false_positives(conn):
    rows = run_sql(conn, "03_exploit_burst.sql")
    assert all(BENIGN not in r[1] for r in rows)


# --------------------------------------------------------- first contact

def test_first_contact_is_honestly_unscored(conn):
    """This detection cannot be evaluated on this corpus, and the project says
    so. It returns only benign rows, because the malicious capture is
    compromised throughout and its baseline already holds the bad channels.

    The test asserts the limitation, so that the claim in docs/FINDING.md
    stays true."""
    rows = run_sql(conn, "04_first_contact.sql")
    assert len(rows) > 0
    assert all(BENIGN in r[0] for r in rows), (
        "first-contact now returns malicious rows. If real, this is good news "
        "and docs/FINDING.md must be rewritten, since it currently states the "
        "detection is unscoreable here."
    )


def test_torii_destination_set_shrinks(conn):
    """The reason first-contact finds nothing malicious: Torii contacts fewer
    destinations in the second half than the first. There is no first contact
    to catch."""
    row = conn.execute(
        """
        WITH b AS (
            SELECT capture, MIN(ts) + (MAX(ts) - MIN(ts)) / 2.0 AS mid
            FROM events GROUP BY capture
        )
        SELECT
          COUNT(DISTINCT CASE WHEN e.ts <  b.mid THEN e.destination_ip END),
          COUNT(DISTINCT CASE WHEN e.ts >= b.mid THEN e.destination_ip END)
        FROM events e JOIN b ON b.capture = e.capture
        WHERE e.capture LIKE ?
        """,
        (f"%{MALICIOUS}%",),
    ).fetchone()
    first_half, second_half = row
    assert second_half < first_half, (
        "Torii's destination set no longer shrinks; the explanation in "
        "docs/FINDING.md for why first-contact finds nothing is now wrong"
    )
