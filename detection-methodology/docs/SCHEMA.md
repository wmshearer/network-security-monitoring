# Schema

One wide table. No star schema, no dimension tables, no joins to look up what a port means.

## Why flat

The research looked at how production security platforms model this. Panther stores raw log
fields in Snowflake VARIANT columns and reaches into them with path expressions. Matano
normalises to ECS on an Iceberg table. Neither normalises security telemetry into third normal
form, and the reason is that log sources are heterogeneous. Every source has a different field
set, and a fully normalised model needs a schema migration every time a new one arrives.

A heavily normalised security schema reads as academic rather than production. So this is one
table, wide, with the fields the queries actually use.

## Field naming

Names follow Elastic Common Schema where a sensible ECS field exists. ECS uses dots, which are
awkward as SQL identifiers, so dots become underscores.

| This project | ECS equivalent | Note |
|---|---|---|
| `source_ip` | `source.ip` | |
| `destination_ip` | `destination.ip` | |
| `source_port` | `source.port` | TCP and UDP collapsed into one column |
| `destination_port` | `destination.port` | same |
| `bytes` | `network.bytes` | per packet, not per flow |
| `protocol` | `network.protocol` | Wireshark's own protocol column |
| `ts` | `@timestamp` | epoch seconds, not a string |
| `capture` | — | which pcap the row came from |
| `dataset` | — | which public dataset the pcap belongs to |

`capture` and `dataset` have no ECS equivalent because ECS assumes a live pipeline where
provenance is implicit. Here it is not, and `capture` turned out to be load-bearing. See the
host-identity finding in FINDING.md: grouping without it merged three unrelated hosts that
happened to share an RFC 1918 address across captures recorded three years apart.

## Table

```sql
CREATE TABLE events (
    event_id         INTEGER PRIMARY KEY,
    capture          TEXT    NOT NULL,
    dataset          TEXT    NOT NULL,
    ts               REAL    NOT NULL,
    source_ip        TEXT,
    destination_ip   TEXT,
    source_port      INTEGER,
    destination_port INTEGER,
    ip_protocol      INTEGER,
    bytes            INTEGER,
    tcp_flags        TEXT,
    protocol         TEXT
);
```

## Indexes

Added from the queries that exist, not speculatively.

| Index | Which query needs it |
|---|---|
| `idx_events_src` | scanning, grouping by source |
| `idx_events_dst` | scanning, the answered-back lookup |
| `idx_events_ts` | anything ordering by time |
| `idx_events_dport` | exploit burst, filtering to one service |
| `idx_events_capture` | every query, since all are capture-scoped |
| `idx_events_pair_ts` | beaconing, which walks one pair in time order |

The composite `(source_ip, destination_ip, ts)` exists because the beaconing query partitions
by pair and orders by time inside the window function. Without it SQLite sorts each partition
from scratch.

## What is deliberately absent

- **No dimension tables.** No port-to-service lookup, no ASN table. Enrichment belongs at
  ingest in a real pipeline, and inventing it here would be inventing data.
- **No flow aggregation.** Rows are packets. A flow table would be faster for some queries but
  would bury the per-packet timing that beaconing depends on.
- **No JSON column.** SQLite supports it, but nothing in this corpus needs a bag of
  source-specific fields. Adding one to look modern would be decoration.

## Scale

74,040 events from 8 captures. Every query in `sql/` returns in under a fifth of a second.

The corpus is deliberately small enough to rebuild in about two seconds, so the whole project
is reproducible from source captures in one command. `data/captures.json` lists two larger
captures, 123MB and 200MB, held out of the default build with the reason recorded.
