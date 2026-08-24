# Findings

All numbers below are from live searches against this host's Splunk
(`https://localhost:8089`), raw output saved in `evidence/`. Nothing here is
invented or rounded up.

## 1. Indexing throughput (metrics.log, sampled -- read the caveat first)

```
index=_internal metrics group=per_sourcetype_thruput sourcetype=<name>
| stats sum(kb) as totalKB, sum(ev) as totalEvents
```

| sourcetype | totalKB | totalEvents (metrics.log) | actual indexed events |
|---|---|---|---|
| `ingest_lab:security:json` | 70,161.183 | 45,611 | **22,085** |
| `ingest_lab:security:json_naive` | 42,898.490 | 1,356 | **345** |

Splunk states plainly that `metrics.log` samples the top 10 items per
category in 30-second windows -- it is a trend/performance diagnostic, not
an audit trail. The mismatch here (45,611 vs the real 22,085; 1,356 vs the
real 345) is not an error, it is exactly what that caveat predicts:
`totalEvents` from `per_sourcetype_thruput` is not a reliable event count
and should never be quoted as one. The actual indexed counts (below) are
authoritative.

## 2. License usage per sourcetype (authoritative)

```
index=_internal source=*license_usage.log type=Usage
| stats sum(b) as bytes by st | eval MB=round(bytes/1024/1024,2)
```

| sourcetype | bytes | MB |
|---|---|---|
| `ingest_lab:security:json` | 27,408,495 | 26.14 |
| `ingest_lab:security:json_naive` | 22,258,793 | 21.23 |

The naive sourcetype's license bytes (21.23 MB) match the raw source file
size almost exactly (22,259,138 bytes = 21.23 MB) -- license accounting
charges by bytes ingested, independent of how many usable events that data
became. The good sourcetype's license usage is 5.15 MB **higher** than the
same raw file, because it has `INDEXED_EXTRACTIONS=json` set (index-time
field extraction), which is a documented, real cost (confirmed via Splunk
Community: indexed extractions increase the bytes Splunk counts against
license, on top of storing the extracted fields). This is the one piece of
"index-time extraction is expensive" this single-instance lab can actually
measure directly, per the research file's own guidance: the license-byte
delta between the same source data with and without `INDEXED_EXTRACTIONS`
is a real, reproducible number, not an assertion.

**The naive config costs almost the same license bytes (21.23 MB vs 26.14
MB) to deliver 64x fewer usable events (345 vs 22,085).** That ratio is the
actual cost of the naive config, not the raw MB number.

## 3. Parsing correctness, as numbers

```
index=_internal sourcetype=splunkd component=DateParserVerbose "ingest_lab:security:json"
index=_internal sourcetype=splunkd component=DateParserVerbose "ingest_lab:security:json_naive"
index=_internal sourcetype=splunkd "Truncating" ("ingest_lab:security:json" OR "ingest_lab:security:json_naive")
```

| check | good sourcetype | naive sourcetype |
|---|---|---|
| `DateParserVerbose` warnings | 0 | 0 |
| `Truncating` warnings | 0 | 0 |

Zero for both is a real result, not a non-result, but it needs the next
section to actually mean anything -- zero `DateParserVerbose` warnings on
the naive sourcetype does NOT mean its timestamps are correct. It means
Splunk found *something* it was willing to accept without a warning, and
that something was wrong silently (see below). This is exactly the "not
setting TRUNCATE/TIME_FORMAT deliberately causes silent failure, not a
loud one" anti-pattern the research file names -- a naive config's failure
mode is not always a log line you can grep for.

**Why zero `Truncating` hits despite naive events up to 67,321 bytes,
above the 10,000-byte default `TRUNCATE`:** confirmed via Splunk Community
sourcing that `TRUNCATE` applies to individual source LINES, evaluated
before line-merging happens, not to the final merged multi-line event. Each
individual JSON line in the naive file is well under 10,000 bytes; only the
post-merge combined "event" is large. So `TRUNCATE` never triggers even
though the visible symptom (67KB events) looks exactly like something
`TRUNCATE` should have caught. The real damage here is done by
`SHOULD_LINEMERGE`, not `TRUNCATE` -- see section 4.

**What actually happened to the naive sourcetype's timestamps:** every
naive event's `_time` is `2026-08-23T20:12:32` -- the file's copy/mtime, not
any date from 2022 embedded in the source JSON. Splunk's automatic
timestamp detection silently fell back to file modification time with no
`DateParserVerbose` warning at all, because across a single merged "event"
containing 63+ different JSON objects with 63+ different `@timestamp`
values, there is no one unambiguous timestamp for Splunk's heuristic to
confidently reject or accept -- it just gives up quietly. Confirmed by
direct query:
```
index=ingest_lab_naive | head 3 | table _time _raw
```
all three had `_time` equal to file mtime, not any date in `_raw`.

## 4. Good-vs-naive sourcetype comparison, the actual point of Phase 2

Same 22,085-line source file (`security_good.json` / `security_naive.json`,
byte-identical copies of splunk-detection-lab's converted
`Security.json`), one sourcetype with every Magic-8 setting explicit
(`ingest_lab:security:json`), one left entirely at Splunk's automatic
defaults (`ingest_lab:security:json_naive`).

| | source lines | indexed events |
|---|---|---|
| good (`ingest_lab:security:json`) | 22,085 | **22,085** (exact match) |
| naive (`ingest_lab:security:json_naive`) | 22,085 | **345** |

That is not a small effect -- **the naive config produced 1.6% of the real
event count.**

**This is fully explained, not just observed.** Reconciliation
(`src/reconcile_counts.py`, `evidence/reconciliation_output.txt`):

```
source lines:              22085
good sourcetype events:    22085 (matches source lines: True)
naive sourcetype events:   345
newlines merged in:        21740
naive lines accounted for: 22085
unaccounted (should be 0): 0
naive reconciles exactly:  True
```

345 final naive events + 21,740 source lines counted as merged INSIDE those
events = 22,085 exactly. Zero source lines are unaccounted for -- this is
not data loss in the sense of events vanishing, it is Splunk's
`SHOULD_LINEMERGE=true` default heuristic merging on average 63 separate
JSON-lines events into one Splunk event (max observed: 84 lines in a single
merged event, `evidence/naive_merged_lines_sample.json`), because nothing
told it where one event actually ends. Direct confirmation on a sample
event: 42,104 characters, containing 47 embedded newlines --
`evidence/naive_event_size_stats.json` shows the largest merged event at
67,321 bytes.

This is exactly the mechanism the research file names as the reason
`SHOULD_LINEMERGE`'s automatic heuristic is a named anti-pattern, not a
theoretical concern: on this real data it destroyed 98.4% of the usable
event granularity while producing zero error-log evidence that anything
was wrong (see section 3).

## 5. Forwarder connection proof

```
index=_internal sourcetype=splunkd source=*metrics.log group=tcpin_connections
| stats count values(fwdType) values(connectionType) values(destPort) values(guid) by hostname
```

Result: `hostname=kali`, `count=24`, `fwdType=uf`, `connectionType=cooked`,
`destPort=9997`, `guid=980FCE87-A95B-45BE-976F-A07F972447FA`.

The indexer's own internal telemetry records an inbound connection
explicitly tagged as coming from a Universal Forwarder (`fwdType=uf`) over
the cooked/s2s protocol, not a raw or HEC path. The `host` field alone
(`kali` on both sides, since this is a single-node lab) cannot distinguish
"came through the forwarder" from "read by a local input" -- the GUID can:
`/home/kali/splunkforwarder/etc/instance.cfg` reports the exact same GUID
as this UF's own identity. Full detail in
`evidence/forwarder_connection_proof_notes.txt`.

## 6. Phase 4: CIM Endpoint mapping, before and after

Verified before writing any mapping:

```
| datamodel Endpoint Processes search | stats count   ->  0
search index=detection_lab EventID=1 | stats count    ->  2174
```

CIM ships the Endpoint data model's schema (the field contract in
`Splunk_SA_CIM/default/data/models/Endpoint.json`) but almost no actual
mappings -- its own `eventtypes.conf` has 3 stanzas, all internal to
Splunk itself. The field names used below (`dest`, `process`,
`parent_process`, `registry_path`, etc.) were read directly from that JSON
file's per-object `calculations` list, not recalled from memory.

Mapping added (this project's own app, `conf/indexer/props.conf` +
`eventtypes.conf` + `tags.conf`; splunk-detection-lab's own files and index
are untouched):

| CIM object | tags required | source |
|---|---|---|
| Processes | `tag=process tag=report` | Sysmon `EventID=1` |
| Registry | `tag=endpoint tag=registry` | Sysmon `EventID=12/13/14` |

After:

| search | before | after |
|---|---|---|
| `\| datamodel Endpoint Processes search \| stats count` | 0 | **2,174** |
| `\| datamodel Endpoint Registry search \| stats count` | 0 | **111,881** |

Both after-numbers are **exact matches** to the raw `EventID` counts
(`evidence/raw_processes_eventid_count.json`,
`evidence/raw_registry_eventid_count.json`) -- every event that qualifies
by EventID is picked up by the data model with zero loss. This is not a
partial mapping that happens to look complete; it was checked against the
raw count specifically to rule that out.

**Design note that became a real bug, fixed:** `mordor:winlog:json` carries
every Sysmon event type in one sourcetype, keyed by `EventID` -- there is
no separate sourcetype per event type to hang independent `FIELDALIAS`
lines on. A first attempt wrote two competing `FIELDALIAS-... = X AS
process` lines in the same stanza (one from `CommandLine` for Processes,
one from `Image` for Registry). `btool` accepted this silently with no
warning, but Splunk's precedence between two `FIELDALIAS` attributes
targeting the same output field in one stanza is undefined, not a real
per-`EventID` branch -- this would have silently mismapped one of the two
objects. Fixed by using `EVAL-` with `case()`/`if()` branching on `EventID`
for every field where the two objects would otherwise collide (see
`conf/indexer/props.conf`'s own comments).

**A real, honestly-reported gap found along the way, not fixed (out of
scope -- would require modifying splunk-detection-lab):**
`sysmon_event_type` -- a field splunk-detection-lab's own
`transforms.conf` is specifically supposed to populate (renaming the raw
JSON `EventType` key to avoid Splunk's reserved `eventtype` name
collision, per that project's own documented reasoning) -- does not
actually populate for ANY event in `detection_lab`. Verified directly:
```
index=detection_lab sysmon_event_type=*                                    -> 0 results
index=detection_lab EventID=13 | stats count by sysmon_event_type          -> 0 results
```
This project's `EVAL-action` mapping uses `extracted_EventType` (Splunk's
own automatic KV-JSON extraction of the same raw `EventType` key, confirmed
present) as a working substitute instead. This is a real defect in a
project that is out of scope to fix here; it is reported rather than
silently worked around without comment.

### CIM's own shipped validation tooling

`Splunk_SA_CIM` ships a real validation data model
(`Splunk_CIM_Validation.json`) with per-model `Missing_Extractions_*` and
`Untagged_*` objects -- this is Splunk's own tooling, not a third-party
script.

```
| datamodel Splunk_CIM_Validation Missing_Extractions_Processes search | stats count
```
Result: **0**. This object's constraint checks for events tagged into
Processes where `dest` or `process` literally equal the placeholder string
`"unknown"` -- zero here means no placeholder/missing-value markers leaked
into the mapped output.

```
| datamodel Splunk_CIM_Validation Untagged_Processes search | stats count
```
Result: **not usable as reported.** Running this directly returns a large,
continuously growing number (153,615, then 153,858 moments later, with
nothing new being indexed into `detection_lab` in between). Investigated
rather than reported at face value: `Untagged_Processes` is a **child**
object of `Untagged_Events`, whose `baseSearch` is literally `"*"` -- every
event in the environment, forever growing as Splunk's own internal
telemetry (`_internal`, `_introspection`) accumulates. Breaking the count
down by index (`evidence/cim_validation_untagged_processes_by_index.json`)
shows the growth is entirely `_internal` (29,897) and `_introspection`
(112,995) -- Splunk's own telemetry indexes, never in scope for this
mapping and never tagged to begin with. The only relevant slice is
`detection_lab`: **10,199** events matching the raw full-text constraint
`(process)` (a bareword search for the literal word "process" anywhere in
the event, not a check for a populated `process` field) that are not
tagged `process`+`report`.

Broken down by `EventID`
(`evidence/cim_validation_untagged_processes_detection_lab_by_eventid.json`):
these are legitimately OTHER Sysmon/Windows event types this project did
not map -- `EventID=10` (Sysmon ProcessAccess, 5,673), `EventID=4688/4689`
(Windows Security process start/stop via a different logging channel than
Sysmon, 567/501), PowerShell script-block events that happen to mention
the word "process" in their text, and others. None of them is `EventID=1`
(the event type this project actually mapped). Directly confirmed:
```
index=detection_lab EventID=1 (process) sourcetype!=stash NOT (tag=process tag=report)
```
returns **0** -- every one of the events this project's mapping targets is
correctly tagged; the 10,199 is honestly a to-do list of OTHER event types
in `detection_lab` that a fuller CIM onboarding could map next, not a
failure of this project's own mapping.

## What this project did not, and could not, prove

- Multi-indexer load distribution via `EVENT_BREAKER`. Configured
  correctly on the UF, but its benefit needs 2+ indexers to observe.
- Production-scale license/throughput ceilings.
- Search-time CPU savings from index-time extraction under real concurrent
  query load.
- Full CIM add-on certification. What is shown here is: matches the
  published Endpoint schema exactly (by event count), and passes CIM's own
  shipped validation searches for the mapped event types. That is not the
  same claim as "this add-on is Splunkbase-certified" or "Splunk Enterprise
  Security recognizes this out of the box" -- ES itself was never
  installed or used.
