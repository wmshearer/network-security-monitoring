# splunk-ingest-pipeline

A Universal Forwarder ingestion pipeline, measured, not just installed.
Second Splunk project. The first, `splunk-detection-lab`, wrote and scored
detections against an already-ingested index and is done; this project does
not repeat that. It builds the piece that project never had: an actual
forwarder in the data path, with the throughput and parsing-correctness
numbers that only exist once you have one.

## What this is NOT

- Not a repeat of splunk-detection-lab's props.conf work. That project
  already hand-authored an expert-level props.conf (SHOULD_LINEMERGE=false,
  explicit LINE_BREAKER, TIME_PREFIX/TIME_FORMAT, MAX_TIMESTAMP_LOOKAHEAD,
  TRUNCATE, KV_MODE=none) with every setting reasoned. This project reuses
  that same reasoning where the data shape repeats, and adds the one thing
  that project correctly had no reason to configure: EVENT_BREAKER, which
  only matters once a Universal Forwarder exists in the pipeline.
- Not Splunk Enterprise Security, and not full CIM add-on compliance. The
  CIM add-on (`Splunk_SA_CIM` 8.5.0) IS installed on this host and its
  schema/datamodels and shipped validation searches are used directly
  (see Phase 4), but the field mappings in this project's own
  `conf/indexer/props.conf` are hand-written against that schema, not
  provided by a vendor Technology Add-on. Where this project's own numbers
  are used as evidence of compliance, that is stated as "matches the
  published CIM schema and passes CIM's own shipped validation searches,"
  not "certified by Splunk."
- No offensive tooling was run. All data moved through the forwarder is
  pre-converted JSON already produced by splunk-detection-lab's own
  `convert_evtx.py`/`convert_otrf.py` scripts, read from that project
  read-only and copied into this project's own `data/` directory before
  being monitored. Nothing in this project modifies
  `splunk-detection-lab/` or its `detection_lab` index.

## Environment

- Splunk Enterprise 10.4.2, already installed and running at
  `/home/kali/splunk` before this project started (indexer role).
- Universal Forwarder 10.4.2 (build `33c3bf42cd73`), installed by this
  project, unprivileged, to `/home/kali/splunkforwarder` from an
  already-downloaded, checksum-verified tarball
  (`/home/kali/splunkforwarder-10.4.2-33c3bf42cd73-linux-amd64.tgz`).
- Both instances run on the same physical host (`kali`) since this is a
  single-node lab. Where that matters for a proof (host/splunk_server
  fields don't distinguish them), the forwarder's own GUID is used instead
  -- see "Proving the forwarder path" below.

## Reproduction steps

### 1. Install the Universal Forwarder, unprivileged

```
tar xzf splunkforwarder-10.4.2-33c3bf42cd73-linux-amd64.tgz -C /home/kali
```

No `sudo`, extracted to `/home/kali/splunkforwarder`, not `/opt`, mirroring
how the indexer itself was installed on this host.

First-run needs a non-interactive start (the default prompts for a
password on stdin, which hangs in a non-interactive shell) and a seed file
so the accepted admin credentials match the indexer's:

```
cat > /home/kali/splunkforwarder/etc/system/local/user-seed.conf <<'EOF'
[user_info]
USERNAME = admin
PASSWORD = [REDACTED]
EOF
```

**Failure #1, and the actual root cause (not a workaround):** the UF's
management port never bound. `splunk start` reported success, `splunk
status` reported `splunkd is running`, and web.conf's `mgmtHostPort =
127.0.0.1:8090` was accepted with no error -- but nothing was ever
listening on TCP 8090. Confirmed by reading `/proc/<splunkd pid>/net/tcp`
directly rather than trusting `splunk status`: no LISTEN socket on 8090
existed at all. The cause, found by reading Splunk's own
`server.conf.spec`: `mgmtMode` defaults to `auto` on a Universal Forwarder,
which means CLI/management traffic goes over a Unix Domain Socket, not
TCP, unless you explicitly set `mgmtMode = tcp` under `[httpServer]` in
`server.conf` (a first attempt put it under `[general]`, which fails with
"Invalid key in stanza [general]" at startup -- the spec file names
`[httpServer]` as the correct stanza). This is why `splunk status` can
report a UF as healthy while it is completely unreachable over the network
-- that command only checks the Unix socket / process, not the TCP port.
See `conf/uf/server.conf.local` and `conf/uf/web.conf.local` for the fix as
deployed.

### 2. Point the UF at the indexer

`conf/uf/outputs.conf`, deployed to
`/home/kali/splunkforwarder/etc/apps/splunk_ingest_pipeline_uf/local/outputs.conf`:

```
[tcpout]
defaultGroup = ingest_lab_indexers

[tcpout:ingest_lab_indexers]
server = 127.0.0.1:9997
```

On the indexer, `conf/indexer/inputs.conf` enables the receiving port:

```
[splunktcp://9997]
disabled = false
```

### 3. Monitor inputs on the UF, with an explicit sourcetype and EVENT_BREAKER

`conf/uf/inputs.conf` monitors two copies of
`splunk-detection-lab/data/converted/benign/Security.json` (22,085 lines,
one Windows Security-channel JSON event per line -- same format documented
in that project's own props.conf), each with an explicit sourcetype (never
Splunk's auto-detected default -- a named anti-pattern in
`research/splunk-ingestion-practice.md`).

`conf/uf/props.conf` sets `EVENT_BREAKER_ENABLE`/`EVENT_BREAKER` on both
sourcetypes. This is the one Magic-8-adjacent setting
splunk-detection-lab's props.conf correctly does not have, because that
project never had a forwarder. A Universal Forwarder cannot run the parsing
pipeline (no `SHOULD_LINEMERGE`/`LINE_BREAKER` available to it) -- without
`EVENT_BREAKER` it streams undifferentiated byte chunks, and
event-boundary-aware load distribution across a receiving indexer tier is
not possible. What this single-node lab genuinely cannot show: the actual
load-distribution *benefit*, which needs 2+ indexers to observe. It can
only be configured correctly and described here, not proven.

**Failure #2:** `EVENT_BREAKER_ENABLE`/`EVENT_BREAKER` were first written
into `inputs.conf`, since that's where the `[monitor://...]` stanza already
lives. Startup failed: `Invalid key in stanza [monitor://...]:
EVENT_BREAKER_ENABLE`. Reading
`etc/system/README/props.conf.spec` directly (not assumed) confirmed these
two settings belong in **props.conf**, keyed by sourcetype, not inputs.conf
-- fixed in `conf/uf/props.conf`.

**Failure #3:** the two monitored files (`security_good.json` and
`security_naive.json`) are byte-identical copies by design (the comparison
in Phase 2 needs the same source bytes through two different sourcetypes).
Splunk's UF fishbucket does CRC-based dedup on the first 256 bytes of a
file by default; with identical content, the second file was silently
never read at all (confirmed in splunkd.log: `security_good.json` logged
"Batch input finished reading," `security_naive.json` never did, despite
both being watched). Fixed with `crcSalt = <SOURCE>` on both monitor
stanzas, which salts the CRC with the file's full path so two
identical-content files are tracked independently.

### 4. Send data through it into a new index

`conf/indexer/indexes.conf` creates `ingest_lab` (good sourcetype) and
`ingest_lab_naive` (naive sourcetype), separate from splunk-detection-lab's
`detection_lab` index, which this project never writes to.

### Proving the forwarder path (not just asserting it)

Both Splunk instances run on the same host, so `host`/`splunk_server`
fields alone don't distinguish "came through the forwarder" from "read by
a local input" -- both show `kali`. The actual proof:

```
index=_internal sourcetype=splunkd source=*metrics.log group=tcpin_connections
| stats count values(fwdType) values(connectionType) values(destPort) values(guid) by hostname
```

Result (`evidence/forwarder_connection_proof.json`):
`fwdType=uf`, `connectionType=cooked`, `destPort=9997`,
`guid=980FCE87-A95B-45BE-976F-A07F972447FA`.

This is the indexer's own record of an inbound connection, explicitly
tagged as coming from a Universal Forwarder over the cooked (s2s)
protocol. Cross-checked against the UF's own identity
(`/home/kali/splunkforwarder/etc/instance.cfg`, copied to
`evidence/uf_instance_cfg.txt`): `guid =
980FCE87-A95B-45BE-976F-A07F972447FA` -- an exact match. That GUID
identifies the specific Splunk instance that opened the connection,
independent of the hostname collision.

## Phase 2: measurements

See `FINDINGS.md` for the full numbers, reasoning, and the good-vs-naive
comparison. Summary of what was measured, all sourced to real `_internal`
searches (raw output in `evidence/`):

- Indexing throughput per sourcetype from `metrics.log`
  (`per_sourcetype_thruput`) -- with the sampling caveat stated plainly:
  metrics.log samples the top 10 items per category in 30-second windows,
  and its event counts do NOT match the authoritative indexed count (see
  FINDINGS.md for the actual numbers, which diverge exactly as expected).
- License usage per sourcetype from `license_usage.log` (authoritative,
  unlike metrics.log).
- Parsing correctness as a number: `DateParserVerbose` and `Truncating`
  hit counts in `_internal` for both sourcetypes, plus the exact event-count
  reconciliation between source lines and indexed events.
- The good-vs-naive sourcetype comparison: same 22,085-line source file,
  one sourcetype with every Magic-8 setting explicit, one left at Splunk's
  automatic defaults. The naive sourcetype produced 345 events, not
  22,085 -- fully explained (see FINDINGS.md), not just observed.

## Phase 4: CIM Endpoint mapping (scope addition)

Verified live: `Splunk_SA_CIM` 8.5.0 is installed and enabled on this host,
shipping the Endpoint data model's schema (field contract) but almost no
actual sourcetype mappings -- its own `eventtypes.conf` has 3 stanzas, all
internal to Splunk itself, none referencing a real data source. The
Windows/Sysmon Technical Add-ons that normally supply those mappings key
off Splunk's native `WinEventLog:*`/`XmlWinEventLog:*` sourcetype names,
not splunk-detection-lab's custom `mordor:winlog:json`, so they would not
help here without the same hand-mapping work done in this project anyway.

This project writes the mapping (`FIELDALIAS`/`EVAL` in
`conf/indexer/props.conf`, `eventtypes.conf`, `tags.conf`) in its **own**
app (`splunk_ingest_pipeline`), read against `detection_lab`'s existing
data, so splunk-detection-lab's own files and index are never touched. See
FINDINGS.md for the before/after numbers and the CIM shipped-validation
search results.

## What a single-node lab genuinely cannot show

Named explicitly rather than implied away, per
`research/splunk-ingestion-practice.md`'s own guidance:

- Multi-indexer load distribution via EVENT_BREAKER. It is configured
  correctly (see Phase 1) but its actual benefit needs 2+ indexers to
  observe, which this lab does not have.
- Deployment Server fleet management at meaningful scale. Not attempted
  here at all -- this is a single hand-configured UF, not a fleet.
- Search-time CPU savings from index-time extraction under real concurrent
  search load. Not measured; this lab cannot generate honest production
  query volume.
- Real license-tier throughput ceilings at production scale.

## Repo layout

- `conf/indexer/` -- every .conf as deployed to
  `/home/kali/splunk/etc/apps/splunk_ingest_pipeline/local/`.
- `conf/uf/` -- every .conf as deployed to
  `/home/kali/splunkforwarder/etc/apps/splunk_ingest_pipeline_uf/local/`,
  plus the two system-level fixes (`server.conf.local`, `web.conf.local`)
  needed to make the UF's management port reachable at all (secrets
  redacted in the committed copies).
- `data/uf_monitor/` -- the two files the UF actually monitors, copied
  read-only from splunk-detection-lab's converted data.
- `src/splunk_search.py` -- thin REST search helper (same pattern as
  splunk-detection-lab's own script of the same name).
- `src/reconcile_counts.py` -- the good-vs-naive line-merge reconciliation
  arithmetic; run live against this host's Splunk with `python3
  src/reconcile_counts.py`.
- `tests/test_reconcile_counts.py` -- pytest for that arithmetic, against
  hand-built fixture counts (does not require a live Splunk instance to
  run).
- `evidence/` -- raw SPL search output (JSON), the forwarder connection
  proof, and the reconciliation script's live output.
