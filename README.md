# cloud-detection-lab: Phase 1, ingestion

This is Phase 1 of a two-phase project. This phase's job is narrow: get cloud
audit-log data (AWS CloudTrail, Azure Monitor/AAD audit events, O365
Management Activity) correctly parsed into a local Splunk instance, mapped
onto Splunk's Common Information Model (CIM), and prove the parse is correct
with real numbers from a running search. A second phase (a different piece
of work, not built here) writes detections against this indexed data. This
phase does not write detections.

Terms used below, defined once, for a reader new to Splunk:
- **Sourcetype**: a label Splunk attaches to every indexed event that tells
  its parsing rules (timestamp format, field extraction) which format to
  expect.
- **props.conf**: the Splunk config file that controls how raw text is
  broken into events, timestamped, and parsed.
- **CIM (Common Information Model)**: Splunk's shared schema of standard
  field names and event categories ("data models"), so different log
  sources can be searched with one set of field names instead of learning
  each vendor's raw schema.
- **FIELDALIAS**: a props.conf setting that makes an existing field
  available under a second name at search time, without changing the
  indexed data. This project uses it to map raw fields (like AWS's
  `sourceIPAddress`) onto CIM's standard names (like `src`).
- **Index**: a separate, named bucket of stored events in Splunk. This
  project uses one new index, `cloud_lab`, and never touches any other
  index on this host.

## What actually got ingested

| Sourcetype | Platform | Events in `index=cloud_lab` | Source files |
|---|---|---|---|
| `aws:cloudtrail` | AWS CloudTrail (raw/native record shape) | 34,429 | 51 |
| `azure:monitor:aad` | Azure Monitor Activity Log / Azure AD audit | 724 | 44 |
| `o365:management:activity` | O365 Management Activity API | 9,169 | 52 |

Real numbers, from `evidence/01_event_counts_by_sourcetype.json`, run
against the live index after ingest completed with 0 failures out of 147
files (`python3 src/ingest_cloud_lab.py`, full output in the "reproduction"
section below).

A fourth shape exists in the corpus and is **explicitly excluded**: 34 files
match a different JSON schema called OCSF (Open Cybersecurity Schema
Framework), used by Amazon Security Lake's own CloudTrail export. Its `time`
field is an epoch-millisecond integer, not an ISO-8601 string, and its field
names (`actor.user.uid`, `api.operation`) are a different schema entirely.
It needs its own sourcetype and its own CIM mapping, and building that was
out of scope for the three sourcetypes this phase was asked to deliver. See
`conf/props.conf`'s "The OCSF CloudTrail variant" section for the full
reasoning, and `src/select_cloud_files.py`, which labels these files
`aws_cloudtrail_ocsf` in the manifest and `src/ingest_cloud_lab.py`, which
skips that label rather than guessing a config for it.

## How the files were found

`src/select_cloud_files.py` walks the corpus and classifies every `.json`/
`.log` file by reading its **actual first JSON line**, never by filename.
Filenames in this corpus are unreliable: a file named `azure_vidar_access.log`
is a Windows Security Event XML export, not Azure data at all, and several
files with `o365` in the path are a different JSON shape entirely (a Splunk
search-result export, not the real O365 Management Activity API shape).

Classification rule (see the script's own docstring for the exact key
checks): CloudTrail needs `eventTime` + `eventSource` + `awsRegion` together;
Azure needs `operationName` + a string `time` + (`category` or
`resourceId`); O365 needs `CreationTime` + `Operation`. A file matching none
of these, or matching the documented exclusion list (Falco logs, nginx
access logs, a risk-export log, a pre-flattened Splunk search export, the
four preview-shaped O365 files), is left out and counted separately, not
silently dropped.

Run it:
```
python3 src/select_cloud_files.py
```
Output (real run, this build):
```
manifest written: data/manifest.csv (181 files)
  aws_cloudtrail: 51 files, 40.1 MB
  aws_cloudtrail_ocsf: 34 files, 0.2 MB
  azure_monitor: 44 files, 2.0 MB
  o365_management: 52 files, 11.0 MB
excluded (matched exclusion list): 10
unclassified (no shape matched, not counted as cloud data): 183
```
The "unclassified" 183 files are real data too, just not in scope for this
phase: Okta, Cisco Duo, Google Workspace, Kubernetes audit logs, Azure
Activity Log events from a different export tool (`eventName`/`caller`/
`authorization` shape, not the `operationName` shape the three target
sourcetypes use), and various endpoint/network captures that happened to
also be JSON. None of these were asked for in this phase's scope.

These counts differ somewhat from the task brief's stated verified counts
(66 CloudTrail / 47 Azure / 56 O365). The brief's counts and this script's
counts were arrived at differently (the brief's by an earlier inventory
pass, this script's by a live content-shape classifier run just now), and
the difference is largely explained by the OCSF/raw CloudTrail split: this
script counts 51 raw + 34 OCSF = 85 total files with "cloudtrail" in their
content, close to but not identical to 66. This discrepancy is stated
plainly rather than forced to match; `data/manifest.csv` is the actual,
reproducible, content-verified list this project's ingestion ran against.

## The three timestamp shapes, and what actually happened when tested live

The three platforms use three genuinely different timestamp formats. This
was the single biggest risk in this phase, and it was checked against real
ingested data, not assumed from the config alone.

| Platform | Field | Example | Format string used |
|---|---|---|---|
| CloudTrail | `eventTime` | `2022-06-30T21:26:49Z` | `%Y-%m-%dT%H:%M:%S%Z` |
| Azure | `time` | `2023-06-20T16:30:24.1848520Z` | `%Y-%m-%dT%H:%M:%S.%7QZ` |
| O365 | `CreationTime` | `2021-01-19T22:21:39` | `%Y-%m-%dT%H:%M:%S` |

### CloudTrail: `%Z` against a literal `"Z"` DID work here

The research this phase was built from carried a caution from a prior
project (`splunk-detection-lab`) that Splunk's `strptime` did not match a
bare literal `"Z"` with `%Z`, and recommended testing before trusting it.
Tested here, against all 34,429 ingested CloudTrail events:

```
search index=cloud_lab sourcetype="aws:cloudtrail"
| eval et=mvindex(eventTime,0)
| eval event_epoch=strptime(et."+0000","%Y-%m-%dT%H:%M:%SZ%z")
| eval diff_seconds=_time-event_epoch
| stats count by diff_seconds
```
Result (`evidence/02_cloudtrail_timestamp_check.json`):
```
diff_seconds=0.000000   count=34429
```
Every single event's indexed `_time` matches its own `eventTime` field
exactly, with `%Z` in the deployed `TIME_FORMAT`. This **contradicts** the
prior project's caution for this exact Splunk build (Splunk Enterprise
10.4.2) and this exact data shape. It is reported as a correction to the
research, not silently adopted as if it always works everywhere; the safer
literal-`"Z"` fallback documented in `conf/props.conf` was never needed.

### Azure: the 7-digit fractional format, the one thing the research flagged as unconfirmed

The research explicitly flagged the 7-digit fractional Azure timestamp
(`%7Q`) as "not yet empirically confirmed to parse on this Splunk build."
Tested here, against all 724 ingested Azure events:
```
search index=cloud_lab sourcetype="azure:monitor:aad"
| eval t=mvindex(time,0)
| eval event_epoch=strptime(t,"%Y-%m-%dT%H:%M:%S.%7QZ")
| eval diff_seconds=round(_time-event_epoch,3)
| stats count by diff_seconds
```
Result (`evidence/03_azure_timestamp_check.json`):
```
diff_seconds=0.000   count=719
```
719 of 724 events match exactly. The remaining 5 are not a `%7Q` parsing
failure; they come from 2 files that use a completely different, non-ISO-8601
timestamp shape (`4/26/2023 6:57:47 PM`, confirmed by direct read, see
`evidence/04_azure_timestamp_format_mismatches.json`). Those 5 events did
not silently fall to ingest time either: Splunk's own automatic secondary
timestamp-detection pass caught them and indexed them at the correct date,
interpreted as the Splunk server's local timezone (America/Los_Angeles),
since the raw value carries no timezone marker at all. This is a real,
documented limitation, not a hidden failure: one sourcetype covering files
from more than one real Azure export tool means the "assume ISO-8601 with 7
fractional digits" TIME_FORMAT does not cover 100% of the corpus, and the
5 events that fall outside it are timestamped by a best-effort fallback the
raw data itself does not disambiguate.

### O365: no fractional seconds, no offset, and a real answer to "assume UTC or not"

The research flagged O365's "assume UTC" reasoning as an assumption, not
confirmed against real data (the corpus sample it checked carried no
explicit offset to test against). Tested here, against all 9,169 ingested
O365 events, comparing two different interpretations of the same
timestamp:
```
search index=cloud_lab sourcetype="o365:management:activity"
| eval t=mvindex(CreationTime,0)
| eval event_epoch_localtz=strptime(t,"%Y-%m-%dT%H:%M:%S")
| eval diff_seconds=round(_time-event_epoch_localtz,3)
| stats count by diff_seconds
```
Result (`evidence/05_o365_timestamp_check.json`):
```
diff_seconds=0.000   count=9167
```
9,167 of 9,169 events match exactly when `CreationTime` is interpreted as
the **Splunk server's local timezone**, not UTC. This means the deployed
`TIME_FORMAT` (`%Y-%m-%dT%H:%M:%S`, no offset marker) makes Splunk parse the
value in the server's own local timezone by default, not UTC. That
contradicts the "assume UTC" framing carried from the research and is
recorded here as the tested answer, not the assumption: on this Splunk
build, a `TIME_FORMAT` with no `%z`/`%Z` component parses in local time. A
project that needed these timestamps to be genuinely UTC (O365's own
documented behavior for `CreationTime`) would need to add an explicit
`TZ =` setting in props.conf; that was not done here, and this local-time
interpretation is what the indexed `_time` actually reflects.

The remaining 2 events are a genuinely malformed source timestamp, not a
Splunk problem: `"CreationTime": "2023-10-10T17:08:65"` has 65 seconds,
which does not exist (max valid is 59), confirmed directly in
`evidence/06_o365_malformed_timestamp.json`. Splunk's fallback parser still
indexed these two events at a plausible nearby time rather than dropping
them or falling back to ingest time, but the exact value it landed on
(`17:08:35`, not a value that follows obviously from `17:08:65`) is not
explained here and is stated as an open, unexplained detail rather than a
guessed one.

## The eventType collision: what happened and why the obvious fix does not work

CloudTrail records carry a top-level `eventType` field (e.g. `"AwsApiCall"`),
confirmed present in `_raw` for every one of the 34,429 ingested events
(`evidence/10_eventtype_collision_raw_presence.json`, `has_eventtype_in_raw
= yes, count = 34429`). This field name collides, case-insensitively, with
Splunk's own reserved `eventtype` concept (the mechanism `eventtypes.conf`
uses to tag and classify events). The result: `| stats count(eventType)`
against those same 34,429 events returns **0** populated
(`evidence/11_eventtype_collision_extraction_counts.json`).

**The obvious fix** is a `transforms.conf` stanza that renames `eventType`
to something else (say, `aws_event_type`) at index time. **This cannot
work here, and was not attempted as if it might, because it is already
proven not to work on this exact configuration in a prior project on this
host** (`splunk-detection-lab`, a structurally identical collision on
Sysmon's `EventType` field, verified there at 0 of 292,992 events
populated). The reason: `[aws:cloudtrail]`'s `INDEXED_EXTRACTIONS = json`
setting parses JSON fields in Splunk's structured-data phase, which runs
**before and instead of** the `TRANSFORMS` phase. A `TRANSFORMS-*` stanza on
a sourcetype that also sets `INDEXED_EXTRACTIONS = json` is accepted without
error by Splunk and simply never fires. There is no config in
`transforms.conf` that fixes this while `INDEXED_EXTRACTIONS = json` stays
set, and turning that setting off would give up the declarative JSON field
extraction the whole ingestion design depends on.

**What was done instead:** nothing needed to be built to recover the raw
value, because Splunk's own automatic JSON key extraction at search time
(a separate mechanism from `INDEXED_EXTRACTIONS`, controlled by the system
default `AUTO_KV_JSON = true`) still makes the same raw key available under
the prefix `extracted_`, confirmed populated for all 34,429 events
(`evidence/11_eventtype_collision_extraction_counts.json`,
`extracted_eventType_populated = 34429`). No field written in this phase's
CIM mapping (`conf/props.conf`'s `FIELDALIAS`/`EVAL` lines) depends on
`eventType` at all; `eventName` (the CloudTrail field that actually carries
the API call name, e.g. `StopLogging`, `CreateAccessKey`) is aliased to
`command` instead, and carries equivalent, non-colliding information.

## CIM mapping: what it is, and what it honestly is not

Field aliases, eventtypes, and tags in `conf/props.conf`, `conf/eventtypes.conf`,
and `conf/tags.conf` were **hand-written by reading the real raw JSON field
names in the corpus and the real CIM data model definitions shipped in
`Splunk_SA_CIM` 8.5.0**, not copied from a vendor add-on. No AWS, Azure, or
O365 Technology Add-on is installed on this host (confirmed: `ls
/home/kali/splunk/etc/apps/` shows no `Splunk_TA_aws`, `Splunk_TA_o365`, or
similarly named directory), and Splunkbase's official add-ons require a
Splunkbase login this environment does not have.

This means: **compliance with the CIM `Change` data model here is asserted
against the published CIM schema and hand-written, not validated by any
vendor add-on, and not certified by Splunk.** It can legitimately say "these
field mappings match the field names and expected structure documented in
`Splunk_SA_CIM/default/data/models/Change.json`, read directly," and it can
say what fraction of ingested events actually populate each mapped field
(see the coverage table below, run live against real data). It cannot say
"this is what the vendor's tested add-on does," because no vendor add-on was
available to compare against.

### Why the `Change` model, and specifically `Auditing_Changes`

`Change`'s base object `All_Changes` constrains on `tag=change`; its child
`Auditing_Changes` adds `tag=audit` on top (both read directly from
`Change.json`). This is CIM's general home for audit-trail/management-
activity events from any product, which is exactly what CloudTrail
management events, Azure AD/Monitor audit events, and O365 Management
Activity events all are: records of "who did what to what, and did it
succeed," not authentication/login events. There is **no `Cloud_Infrastructure`
model in this CIM version** (confirmed: no such file exists among the 26
files in `Splunk_SA_CIM/default/data/models/`); `Authentication` is the
right model for actual sign-in telemetry (Azure AD sign-in logs
specifically), which is a different log stream from the audit/management
events this phase ingested, and was correctly not used here.

### CIM field coverage, per sourcetype, real numbers

CloudTrail (34,429 events, `evidence/07_cloudtrail_cim_coverage.json`):

| CIM field | Populated | Coverage |
|---|---|---|
| `user` | 34,322 | 99.7% |
| `src` | 34,429 | 100% |
| `dvc` | 34,429 | 100% |
| `vendor_account` | 34,398 | 99.9% |
| `vendor_region` | 34,429 | 100% |
| `command` | 34,429 | 100% |
| `status` | 2,839 | 8.2% |
| `object` | 10 | 0.03% |

`status` is genuinely sparse: it is aliased from CloudTrail's `errorCode`
field, which is only present when a call fails. An absent `errorCode` is
left null here rather than force-set to `"success"`, so CIM's own base
model calculated field (`if(isnull(status)...,"unknown",status)`) supplies
the fallback, not a guess made up in this project's own config. `object` is
even sparser: it is aliased from `requestParameters.name`, present only when
the specific API call's request body happens to carry a `name` parameter
(e.g. `StopLogging` against a named trail). Both are reported as measured,
not implied to be near-complete.

Azure (724 events, `evidence/08_azure_cim_coverage.json`):

| CIM field | Populated | Coverage |
|---|---|---|
| `command` | 724 | 100% |
| `object_category` | 724 | 100% |
| `vendor_account` | 724 | 100% |
| `dvc` | 712 | 98.3% |
| `user` | 446 | 61.6% |
| `status` | 155 | 21.4% |

`user` (aliased from the raw `identity` field) is genuinely under half
populated: many Azure Monitor audit events carry an empty
`properties.initiatedBy` object instead of a named actor (system-initiated
or JIT-provisioned actions with no human in the loop), and `identity` is
absent on those. `status` (aliased from the nested `properties.result`
field) is similarly sparse; most sampled events simply do not carry that
nested key.

O365 (9,169 events, `evidence/09_o365_cim_coverage.json`):

| CIM field | Populated | Coverage |
|---|---|---|
| `user` | 9,169 | 100% |
| `command` | 9,169 | 100% |
| `object_category` | 9,169 | 100% |
| `status` | 7,281 | 79.4% |
| `object` | 7,959 | 86.8% |
| `src` | 4,640 | 50.6% |

O365 has the most complete coverage of the three, consistent with its flat,
non-nested event shape (`UserId`, `Operation`, `ResultStatus`, `ObjectId`,
`ActorIpAddress` are all top-level fields, no dotted-path extraction
needed). `src` (aliased from `ActorIpAddress`) is missing on roughly half
the events; this was not investigated further in this phase (out of the
scope of "prove the parse," not a claim that it is fully explained).

## A trap found during this build that the research did not predict

The research this phase started from anticipated the `INDEXED_EXTRACTIONS`
+ `TRANSFORMS` collision (the `eventType` problem above) and a possible
dotted-field-name `FIELDALIAS` problem. Neither of those was the actual
first failure hit while proving the CIM mapping. The first attempt at
verifying CIM field coverage returned **0 populated for every single
`FIELDALIAS`-derived field**, including simple, non-dotted ones like
`sourceIPAddress AS src`.

The cause: this project's app (`cloud_detection_lab`) had no
`metadata/local.meta` file, so Splunk's default knowledge-object scoping
applied: `FIELDALIAS`/`EVAL` definitions in an app's `local/props.conf` are
**private to that app's context by default**. A search run against the
default `search` app context (which is what a plain REST API call to
`/services/search/jobs` uses, and what a user searching from Splunk Web's
default context uses) does not see them, even though `btool` shows the
stanza is deployed and syntactically valid. The fix, confirmed by direct
comparison of the two API paths:
```
# does NOT see this app's FIELDALIAS (default search-app context)
POST /services/search/jobs

# DOES see it (explicit app namespace)
POST /servicesNS/admin/cloud_detection_lab/search/jobs
```
Rather than requiring every search anywhere to specify this app's
namespace, `conf/metadata/local.meta` sets `export = system` (the same
pattern already used by the `splunk-ingest-pipeline` project on this host,
confirmed by reading its own `metadata/local.meta`), which makes the
knowledge objects globally visible from any app context. This required a
Splunk restart to take effect (metadata/knowledge-bundle changes are not
picked up by a hot config reload the way some props.conf edits are), which
is disclosed here plainly since restarting was otherwise avoided in this
phase except where a config change genuinely required it. This was proven,
not assumed: `evidence/12_fieldalias_works_after_export_system_fix.json`
shows `user`/`src` populated after the fix, and
`tests/test_live_parse_proof.py::test_cloudtrail_cim_user_field_is_populated_for_most_events`
was run against the pre-fix state and confirmed to fail (0/34429), then
against the post-fix state and confirmed to pass, before being left in the
suite as a permanent regression check.

## Reproduction

Splunk Enterprise 10.4.2 was already installed at `/home/kali/splunk`
before this phase started but was not running when this phase began; it was
started (not "restarted", it was down) to do any of this work at all, and
later genuinely restarted twice: once because a new index
(`indexes.conf`'s `cloud_lab` stanza) requires a restart to actually be
created, and once because the `metadata/local.meta` fix above needed the
knowledge-object bundle reloaded. No other start/stop/restart happened.

1. Deploy the app config (already done on this host; shown for
   reproducibility elsewhere):
   ```
   mkdir -p /home/kali/splunk/etc/apps/cloud_detection_lab/local
   mkdir -p /home/kali/splunk/etc/apps/cloud_detection_lab/metadata
   cp conf/*.conf /home/kali/splunk/etc/apps/cloud_detection_lab/local/
   cp conf/metadata/local.meta /home/kali/splunk/etc/apps/cloud_detection_lab/metadata/
   /home/kali/splunk/bin/splunk restart
   ```
2. Select the files:
   ```
   python3 src/select_cloud_files.py
   ```
3. Ingest them into the new index:
   ```
   python3 src/ingest_cloud_lab.py
   ```
   Real output from this run: `ingested ok: 147`, `failed: 0`, `skipped
   (out of scope, e.g. aws_cloudtrail_ocsf): 34`.
4. Run the tests:
   ```
   python3 -m pytest tests/ -v
   ```

## Tests

`tests/test_select_cloud_files.py` (11 tests): pure unit tests of the
classification and exclusion logic, no live Splunk needed. Each shape
(`aws_cloudtrail`, `aws_cloudtrail_ocsf`, `azure_monitor`, `o365_management`)
has a positive test, plus the specific negative case the task brief named
(the Splunk search-export "preview" shape) and a check that excluding one
file does not accidentally exclude its real-data siblings in the same
directory. Proven able to fail: `_is_splunk_export_shape()` was temporarily
forced to `return False`, and
`test_rejects_splunk_search_export_preview_shape` failed with
`AssertionError: assert 'o365_management' is None` (the preview-wrapped
object was wrongly classified as real O365 data), then passed again once
the change was reverted.

`tests/test_live_parse_proof.py` (5 tests): live-Splunk tests against the
already-ingested `cloud_lab` index, auto-skipped if Splunk is unreachable.
Checks: all three sourcetypes have events; CloudTrail's `_time` matches
`eventTime` for every event; Azure's 7-digit fractional format matches for
at least 99% of events; the `eventType` collision is real (0 populated) and
`extracted_eventType` is the working substitute (100% populated); the
CloudTrail CIM `user` field is populated for over 99% of events. Proven
able to fail: the last test was run against the pre-fix app-scoping bug
(before `metadata/local.meta` existed) and failed with `AssertionError: only
0/34429 CloudTrail events have a populated CIM user field`, confirming the
test actually catches that class of regression, not just the specific bug
found this time.

## What is NOT evidenced here

- **No precision/false-positive measurement of anything**, because this
  phase does not write detections. That is explicitly the next phase's job.
- **OCSF CloudTrail (34 files) is not ingested at all**, by decision, not
  oversight. See the section above.
- **`azure:monitor:aad`'s CIM mapping was checked against one export
  shape** (Azure Monitor Activity Log / Azure AD audit, `operationName`/
  `resourceId` fields). A real Azure AD sign-in export (a different field
  shape entirely, and the right fit for CIM's `Authentication` model, not
  `Change`) was not part of this corpus and is not covered.
- **O365's "assume UTC" question was answered empirically for THIS corpus
  and THIS Splunk server's local timezone setting**, not against a
  documented Microsoft specification. If O365's `CreationTime` really is
  always UTC (Microsoft's own documented behavior, not independently
  re-verified here), then this deployment's indexed `_time` for O365 events
  is currently off by this server's UTC offset (7 or 8 hours, depending on
  daylight saving), because no explicit `TZ =` was set. This is disclosed
  as a real, present gap, not a hypothetical one.
- **The 2 O365 events with an invalid `:65` seconds value** landed at a
  specific time (`17:08:35`) that this phase did not fully explain from
  Splunk's fallback-parsing behavior.
- **CIM field coverage numbers are exact counts against the specific
  corpus files ingested here**, not a claim about coverage against a real
  production CloudTrail/Azure/O365 tenant's full event-type variety. A
  production tenant emits many more distinct `eventName`/`operationName`/
  `Operation` values than this labelled attack-technique corpus contains.
- **No vendor Technology Add-on comparison exists on this host** to check
  this hand-written mapping against, for the reason stated in the CIM
  section above (no Splunkbase login available in this environment).

## Directory layout

```
conf/props.conf        Three sourcetypes, every Magic-8 setting reasoned, the
                        eventType collision and OCSF decision documented inline.
conf/eventtypes.conf    Three eventtypes, one per sourcetype, feeding tags.conf.
conf/tags.conf          tag=change, tag=audit on each eventtype (Auditing_Changes fit).
conf/indexes.conf       The new cloud_lab index definition, nothing else touched.
conf/app.conf           App metadata for the deployed Splunk app.
conf/metadata/local.meta  export=system, the fix for the app-scoping trap above.
src/select_cloud_files.py  Content-based file classifier + exclusion list + manifest writer.
src/ingest_cloud_lab.py    Reads the manifest, runs `splunk add oneshot` per file into cloud_lab.
src/splunk_search.py       Small REST API helper used by tests and ad-hoc verification.
data/manifest.csv       Real output of select_cloud_files.py (path, platform, technique_id, bytes).
evidence/*.json          Real saved search results backing every number in this README.
tests/test_select_cloud_files.py   Pure unit tests, no Splunk needed.
tests/test_live_parse_proof.py     Live-Splunk regression tests against cloud_lab.
```
