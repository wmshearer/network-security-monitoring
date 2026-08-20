"""
Turn packet captures into a flat events table in SQLite.

The point of this file is narrow on purpose. It reads captures with tshark,
normalises each packet into one row, and writes them to a database. Every
detection in sql/ then runs against that table, in SQL, with no Python in the
loop. That split is deliberate: it keeps the detection logic honest, because a
query cannot quietly fall back to a Python for-loop when SQL gets awkward.

Field names follow Elastic Common Schema where a sensible ECS field exists
(source.ip, destination.port, event.start). ECS uses dots, which are awkward as
SQL column names, so dots become underscores: source_ip, destination_port.
The mapping is written down in docs/SCHEMA.md rather than left implied.

Nothing here invents data. Every row comes from a public capture already used
by the network-traffic-analysis projects in this portfolio.
"""

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

# Fields pulled from every packet. Kept small on purpose: these are the fields
# the detections actually use, and a wider extract makes the ingest slower
# without making the queries better.
TSHARK_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "ip.proto",
    "frame.len",
    "tcp.flags",
    "_ws.col.protocol",
]

SCHEMA = """
DROP TABLE IF EXISTS events;
CREATE TABLE events (
    event_id        INTEGER PRIMARY KEY,
    capture         TEXT    NOT NULL,   -- which pcap this row came from
    dataset         TEXT    NOT NULL,   -- which public dataset the pcap belongs to
    ts              REAL    NOT NULL,   -- frame.time_epoch, seconds
    source_ip       TEXT,
    destination_ip  TEXT,
    source_port     INTEGER,
    destination_port INTEGER,
    ip_protocol     INTEGER,
    bytes           INTEGER,
    tcp_flags       TEXT,
    protocol        TEXT               -- wireshark's own protocol column
);

-- Indexes chosen from the queries in sql/, not added speculatively.
-- Every hunting query filters or groups on at least one of these.
CREATE INDEX idx_events_src      ON events(source_ip);
CREATE INDEX idx_events_dst      ON events(destination_ip);
CREATE INDEX idx_events_ts       ON events(ts);
CREATE INDEX idx_events_dport    ON events(destination_port);
CREATE INDEX idx_events_capture  ON events(capture);
-- Composite for the beaconing query, which walks one pair in time order.
CREATE INDEX idx_events_pair_ts  ON events(source_ip, destination_ip, ts);
"""


def read_capture(pcap: Path) -> list[list[str]]:
    """Run tshark once over a capture and return rows of raw field values.

    tshark is called with -T fields, which prints one tab-separated line per
    packet. That is far cheaper than -T json for a capture of this size, and
    the fields are all scalars so there is nothing json would add.
    """
    cmd = ["tshark", "-r", str(pcap), "-T", "fields"]
    for field in TSHARK_FIELDS:
        cmd += ["-e", field]
    # -E occurrence=f keeps the first value when a packet has a field twice
    # (tunnelled IP, for example). Without it a row can gain extra columns and
    # silently misalign.
    cmd += ["-E", "separator=/t", "-E", "occurrence=f"]

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        print(f"  tshark failed on {pcap.name}: {proc.stderr.strip()[:200]}", file=sys.stderr)
        return []
    return [line.split("\t") for line in proc.stdout.splitlines() if line.strip()]


def to_int(value: str):
    """tshark prints an empty string for a field a packet does not have."""
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def to_float(value: str):
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def normalise(row: list[str], capture: str, dataset: str):
    """One tshark line becomes one events row.

    TCP and UDP ports arrive in separate tshark fields. They collapse into one
    source_port / destination_port pair here, because a detection asking "what
    port was this" should not care which transport carried it.
    """
    # Pad short rows rather than dropping them. A truncated line means the
    # packet lacked trailing fields, not that the packet is unusable.
    row = row + [""] * (len(TSHARK_FIELDS) - len(row))

    ts = to_float(row[0])
    if ts is None:
        return None  # no timestamp means the row cannot take part in any query

    src_port = to_int(row[3]) if row[3] else to_int(row[5])
    dst_port = to_int(row[4]) if row[4] else to_int(row[6])

    return (
        capture,
        dataset,
        ts,
        row[1] or None,
        row[2] or None,
        src_port,
        dst_port,
        to_int(row[7]),
        to_int(row[8]),
        row[9] or None,
        row[10] or None,
    )


def build(manifest_path: Path, db_path: Path):
    manifest = json.loads(manifest_path.read_text())

    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)

    total = 0
    for entry in manifest["captures"]:
        pcap = Path(entry["path"])
        if not pcap.exists():
            print(f"  skip (not found): {pcap}")
            continue

        rows = read_capture(pcap)
        normalised = [
            n for n in (normalise(r, pcap.name, entry["dataset"]) for r in rows)
            if n is not None
        ]
        conn.executemany(
            """INSERT INTO events
               (capture, dataset, ts, source_ip, destination_ip,
                source_port, destination_port, ip_protocol, bytes,
                tcp_flags, protocol)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            normalised,
        )
        conn.commit()
        total += len(normalised)
        print(f"  {pcap.name}: {len(normalised):,} events")

    conn.close()
    print(f"\ntotal: {total:,} events -> {db_path}")
    return total


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent
    build(root / "data" / "captures.json", root / "data" / "events.db")
