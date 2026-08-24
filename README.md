# cloud-detection-lab

Two-phase project. Phase 1 (below, unchanged) got cloud audit-log data (AWS
CloudTrail, Azure Monitor/AAD audit events, O365 Management Activity)
correctly parsed into a local Splunk instance and mapped onto Splunk's
Common Information Model (CIM). Phase 2 (see "Phase 2: detections" further
down) writes detections against that indexed data, scores them for recall
against the labelled captures, and, the actual point of the project, scores
every detection against every OTHER technique's capture to measure
overfitting.

## Phase 1, ingestion

This phase's job was narrow: get the three sourcetypes parsed correctly and
prove the parse is correct with real numbers from a running search. It did
not write detections.

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

---

# Phase 2, detections

Phase 1 proved the data is parsed correctly. Phase 2 writes detections
against it, and, the actual point of this phase, measures how much each
detection overfits to the one capture it was built for by running it
against every OTHER labelled technique's capture in the same index.

The research this phase was built from
(`/home/kali/director/projects/wshearer-site/research/cloud-detection-methodology.md`)
made one correction that reshaped the whole plan: **scoring a detection
against ATT&CK labels only measures recall.** A search for `eventName=*`
would score 100% recall and be worthless. Recall alone is not a quality
measurement; the off-target/overfitting measurement below is what actually
says something about whether a detection is specific or just broad.

## Method

1. Write each detection as a Sigma rule first (`detections/sigma/*.yml`),
   modeled on real detections read directly from Splunk's own 318 cloud
   detections at `_corpora/security_content/detections/cloud/` (Apache-2.0),
   not invented from scratch. Every Sigma rule was actually run through
   `sigma-cli` (real tool, `sigma-cli` 3.1.0 / `pySigma` 1.5.0 /
   `pysigma-backend-splunk` 2.1.0, installed in a throwaway venv since this
   host's system Python is externally managed) to produce the base SPL, not
   hand-translated and merely labeled "converted." Full raw conversion
   output for all 12 rules: `evidence/13_sigma_conversion_raw_output.txt`.
2. Wrap the converted SPL in the schema security_content itself uses on all
   318 of its cloud detections: a stable `id`, `description`, the `search`,
   `mitre_attack_id`, a required non-blank `known_false_positives`, a
   `target_technique_id`/`target_dataset` pointing at the exact labelled
   capture it targets, a `specificity_note` (this project's Pyramid-of-Pain
   self-assessment), and a trailing `` `<name>_filter` `` macro so a
   deploying site can allowlist without touching detection logic. These are
   `detections/spl/*.yml`. The macros themselves are real, deployed Splunk
   knowledge objects (`conf/macros.conf`, each an initially-empty
   `search *` no-op), not just referenced and left undefined; every
   detection's COMPLETE search, macro included, was run directly against
   the live Splunk instance and confirmed to return real result rows (see
   `evidence/14_full_production_search_run.json`), not just the trimmed
   form the scoring harness uses.
3. Score recall: for each detection, does its search fire on
   `host=<target_technique_id>` (the technique it was built for). Phase 1
   already tags every ingested event's `host` field with its source
   ATT&CK technique ID (`src/ingest_cloud_lab.py`'s `-hostname
   technique_id`), so this is a direct, no-extra-tooling-needed live
   search, not a simulated replay.
4. Score off-target firing: run the SAME matching logic against `stats ...
   by host` across the WHOLE index, so one search reveals every technique
   the detection fires on, not just the one it targets. `src/score_detections.py`
   does this for all 12 detections in one pass and writes
   `evidence/detection_scoring.json`.

## Detections written

All 12 target real, distinct fields in the actual ingested data (verified
by reading raw capture JSON directly before writing each detection, see
the "what contradicted the research" section below for two cases where the
first attempt was wrong and had to be fixed after live testing).

| id | platform | target technique | Sigma or SPL-only | logic |
|---|---|---|---|---|
| `4a1e2b8c` | AWS | T1562.008 | Sigma | `eventName` is StopLogging or DeleteTrail |
| `2a0e7f4b` | AWS | T1110.003 | Sigma (base rule + correlation) | >5 failed ConsoleLogin for one userName in 10m |
| `6f3b9d25` | AWS | T1580 | Sigma (base rule + correlation) | >20 DISTINCT AccessDenied eventNames for one principal in 15m |
| `8c3f5a12` | AWS | T1098 | Sigma | `eventName`=DeletePolicy |
| `6d4b9f21` | AWS | T1556.006 | Sigma | CreateVirtualMFADevice or EnableMFADevice |
| `9a4e7c21` | AWS | T1530 | Sigma (`keywords` type) | PutBucketAcl + raw match on the S3 global-group URI, see below for why a field match does not work here |
| `b18d2f47` | Azure | T1621 | Sigma (base rule + correlation) | >3 sign-in failures with resultType 500121 (MFA denied) for one identity in 10m |
| `a07c1e36` | Azure | T1110.003 | Sigma (base rule + correlation) | >5 DISTINCT identities failing with resultType 50126 from one IP in 10m |
| `7a5c3e19` | Azure | T1098.003 | Sigma | "Add member to role" targeting a built-in privileged role name |
| `8e2c6a19` | O365 | T1098.002 | Sigma | Operation=New-ManagementRoleAssignment |
| `2c9f7e15` | O365 | T1114.003 | Sigma | New-InboxRule/Set-InboxRule/Set-Mailbox with a forwarding parameter |
| `4d1a8c26` | O365 | T1136.003 | Sigma | Operation starts with "Add service principal" |

Every rule converted through `sigma-cli` cleanly except for one construct
that does not exist in modern Sigma at all, and one field-name mismatch
found only by testing live, both covered below.

### Where Sigma did not express a detection cleanly, and what was done instead

**The deprecated pipe-count syntax.** The first draft of the 4
threshold/aggregation detections (console-login failures, AccessDenied
burst, Azure password spray, Azure MFA-denied burst) used
`condition: selection | count(field) by other_field > N`, syntax that
looks like standard Sigma but is not: running it through `sigma-cli`
raised `Error: The pipe syntax in Sigma conditions has been deprecated and
replaced by Sigma correlations. pySigma doesn't supports this syntax.`
(exact error text, `evidence/13_sigma_conversion_raw_output.txt` shows the
before/after). The fix is Sigma's real, current mechanism for this: a
**Sigma Correlation** (a second YAML document, `type: event_count` or
`type: value_count`, with `group-by`, `timespan`, and `condition:` fields,
referencing a base event rule by name), a feature that shipped in pySigma
in 2024 with real Splunk-backend support. All 4 detections now use this
form. `value_count` (distinct-value counting, e.g. distinct identities per
IP) was used instead of `event_count` (raw event counting) wherever the
detection's actual intent was diversity, not volume, since those are
genuinely different Sigma correlation types with different real meanings,
not interchangeable.

**The S3 bucket-made-public detection cannot use a field match.** The
first draft matched a single fixed field
(`requestParameters.accessControlList|contains`). Live testing against
the real T1530 capture showed this MISSES every one of the 8 labelled
events. `PutBucketAcl`'s grant target legitimately lives under a different
JSON key depending on how the call was made: one of five different
possible header-derived keys
(`requestParameters.accessControlList.x-amz-grant-read` /
`-read-acp` / `-write` / `-write-acp` / `-full-control`, only one
populated per event, confirmed directly: 7 of 8 labelled events use this
shape across different header names) or a completely different XML-body
shape (`requestParameters.AccessControlPolicy.AccessControlList.Grant`,
the 8th event). Splunk's own security_content detection for this exact
scenario
(`_corpora/security_content/detections/cloud/detect_new_open_s3_buckets_over_aws_cli.yml`)
enumerates the five header-key names explicitly; tested here against the
same capture, that approach catches 7 of 8 and misses the XML-body event,
a blind spot its own `known_false_positives` text does not mention. This
project's detection instead uses Sigma's `keywords` detection type (a
logsource-wide free-text search for the literal group URI strings),
which catches all 8 but is coarser, stated as a real precision tradeoff in
`detections/spl/aws_s3_bucket_made_public.yml`'s `sigma_field_note` field,
not hidden.

**The `{}` vs `[]` multivalue mismatch (Azure and O365).** Two Sigma rules
used JSON-path array syntax borrowed from generic JSON tooling
(`properties.targetResources[].modifiedProperties[].newValue`,
`Parameters[].Name`). Splunk's `INDEXED_EXTRACTIONS=json` flattens nested
JSON arrays using `{}` multivalue notation, not `[]`, confirmed by a live
search against the real indexed field name before either SPL detection was
written (`properties.targetResources{}.modifiedProperties{}.newValue`,
`Parameters{}.Name`, both confirmed populated). `sigma-cli`'s Splunk
backend does not correct this automatically (it passes the `[]` syntax
through as a literal, quoted field name, which would silently never
match); both `detections/spl/*.yml` files document this gap in a
`sigma_field_note` field and use the corrected `{}` field name in the
actual search that runs.

## Recall

12 of 12 detections fire on the technique they were built for
(`evidence/detection_scoring.json`, `evidence/16_scoring_run_output.txt`
for the raw run). Real on-target event counts, not just a hit/miss flag:

| detection | target | on-target events |
|---|---|---|
| AWS CloudTrail Logging Stopped or Deleted | T1562.008 | 7 |
| AWS Console Multiple Failed Logins for One User | T1110.003 | 27 (sum of `event_count` across windows that crossed >5) |
| AWS IAM AccessDenied Burst From One Principal | T1580 | 114 (sum of `value_count` across windows that crossed >20) |
| AWS IAM Policy Deleted | T1098 | 116 |
| AWS New Virtual MFA Device Registered | T1556.006 | 2 |
| AWS S3 Bucket ACL Granted to AuthenticatedUsers or AllUsers | T1530 | 8 |
| Azure AD Multiple Denied MFA Requests for One User | T1621 | 28 (sum of `event_count` across windows that crossed >3) |
| Azure AD Distributed Password Spray | T1110.003 | 31 (sum of `value_count` (distinct identities) across windows that crossed >5) |
| Azure AD Privileged Directory Role Assigned | T1098.003 | 6 |
| O365 Exchange Management Role Assigned | T1098.002 | 1 |
| O365 Mailbox Forwarding Rule or Forwarding Address Set | T1114.003 | 80 |
| O365 Service Principal or Credential Added | T1136.003 | 31 |

**Total: 12/12.** This number alone is close to meaningless on its own,
per the research's central correction; it is reported here because it is
a real, necessary precondition (a detection with 0 recall is definitionally
broken), not because it is the deliverable.

## Off-target results

The actual deliverable. `src/score_detections.py` runs each detection's
real matching logic (for the 4 correlation detections, the REAL threshold,
per host, not just the base event filter, see the correctness note below)
against the entire `cloud_lab` index and reports every technique host it
fires on besides its own target.

| detection | target | off-target hosts | off-target events |
|---|---|---|---|
| AWS CloudTrail Logging Stopped or Deleted | T1562.008 | none | 0 |
| AWS Console Multiple Failed Logins for One User | T1110.003 | none | 0 |
| AWS IAM AccessDenied Burst From One Principal | T1580 | T1526 (26) | 26 |
| AWS IAM Policy Deleted | T1098 | none | 0 |
| AWS New Virtual MFA Device Registered | T1556.006 | none | 0 |
| AWS S3 Bucket ACL Granted to AuthenticatedUsers or AllUsers | T1530 | none | 0 |
| Azure AD Multiple Denied MFA Requests for One User | T1621 | none | 0 |
| Azure AD Distributed Password Spray | T1110.003 | none | 0 |
| Azure AD Privileged Directory Role Assigned | T1098.003 | none | 0 |
| O365 Exchange Management Role Assigned | T1098.002 | none | 0 |
| O365 Mailbox Forwarding Rule or Forwarding Address Set | T1114.003 | T1110 (93), T1114 (93), T1556 (93) | 279 |
| O365 Service Principal or Credential Added | T1136.003 | T1098.003 (1), T1110 (4), T1114 (4), T1556 (4) | 13 |

**9 of 12 detections have zero off-target hits.** These are the specific
ones: a fixed AWS/Azure/O365 API call name or a small enumerated set of
them, not a broad pattern. This is expected for a static field-equality
match against a small, cleanly-separated attack-simulation corpus, and it
is the easy case; a genuinely production-scale benign corpus would be a
harder test (see "what this project cannot claim" below).

**3 of 12 have real off-target hits, and each has a different, plainly
stated cause:**

1. **AWS IAM AccessDenied Burst (T1580) fires on T1526's capture too
   (26 events, one 15-minute window).** Investigated directly: T1526's
   capture is itself a burst of `Describe*`/enumeration AWS API calls (a
   security-scanning tool's normal behavior), and some portion of those
   calls return `AccessDenied`. This is not a bug, it is a genuine
   near-neighbor: T1580 (cloud infrastructure discovery) and T1526
   (a security-scanner technique) are behaviorally adjacent, both
   "enumerate lots of things via the API," so a detection built to catch
   one plausibly catches some of the other. This is exactly the kind of
   honest overlap a single-capture recall number would never reveal.

2. **O365 Mailbox Forwarding Rule (T1114.003) fires on T1110, T1114, and
   T1556's captures, 93 events each, an identical count across all
   three.** Investigated directly: each of those three captures contains a
   real `Set-Mailbox` call with a populated `ForwardingAddress` parameter
   pointing at a real mailbox address
   (`bpatel@rodsoto.onmicrosoft.com`), not an artifact of the search
   logic. The identical 93-event count across three different technique
   directories, and the shared `rodsoto.onmicrosoft.com` /
   `splunkresearch.com` tenant naming seen across many captures in this
   corpus, suggests these labelled attack-simulation datasets share
   overlapping setup/session activity across technique boundaries (the
   same lab environment was very likely reused to generate multiple
   technique captures, and mailbox-forwarding setup from one scenario
   ended up recorded inside another scenario's capture file). This is
   reported as a real property of the corpus discovered by this
   measurement, not explained away: a detection built purely from one
   labelled capture cannot assume that capture contains ONLY the labelled
   technique's activity.

3. **O365 Service Principal Created (T1136.003) fires on T1098.003,
   T1110, T1114, and T1556's captures (1 to 4 events each).** Same
   underlying cause as #2, smaller in volume: real
   `Add service principal*` operations recorded inside other techniques'
   capture files, most plausibly because privilege-escalation chains in
   these captures genuinely involve creating a service principal as one
   step, and T1098.003 (privileged role assignment) is a
   directly-adjacent, plausible next step from T1136.003 in a real attack
   chain, not just a labelling coincidence.

**A correctness note on how this scoring was actually done.** An early
version of `src/score_detections.py` computed off-target hits for the 4
correlation/threshold detections by dropping their `bin`/`stats`/`where`
threshold pipeline entirely and substituting a flat `stats count by host`,
which measured raw base-event counts, not whether the real threshold was
crossed. This produced a materially wrong, inflated off-target table (for
example, it reported the AWS console-login-failures detection firing on
4 off-target hosts including T1078 and T1621 (25 events total), the
Azure password-spray detection firing on T1110.001 (30 events), and the
AccessDenied-burst detection firing on 5 off-target hosts totaling 508
events, versus the corrected 1 host / 26 events shown in the table
above). Caught by manually re-checking one flagged host (T1110.001,
single-account password guessing) against the Azure spray detection's
real `dc(identity)>5`-per-IP-per-10-minute condition directly: that host
has only 1 distinct identity from its one source IP, so it can never
cross the threshold, meaning the reported off-target hit was a
scoring-harness artifact, not a real detection behavior. The harness was rewritten to
apply the actual threshold logic per host (add `host` to the correlation's
`group-by`, keep the real `where` clause, then aggregate), and the numbers
above are from that corrected version, live-verified again via
`tests/test_detection_scoring.py::test_azure_password_spray_does_not_false_fire_on_single_target_bruteforce`
and `::test_off_target_hits_are_real_not_harness_artifacts`. This is
disclosed in full because getting an overfitting measurement itself wrong
would be a worse failure than the overfitting it is trying to catch.

## Coverage

**11 of 45 ATT&CK techniques with cloud telemetry in this corpus have a
detection (24.4%).** 12 detections cover 11 distinct techniques (AWS and
Azure each have a T1110.003 detection). The live-indexed `cloud_lab` data
carries **45** distinct technique IDs (confirmed directly:
`index=cloud_lab | stats dc(host)`), not the 44 the task brief stated;
this is a small, real discrepancy from the brief's number and is reported
as measured, not silently corrected to match. A low coverage number is the
expected result for 12 detections against 45 techniques and is stated
plainly: this is a portfolio-scale detection set, not a production-scale
one, and no claim is made otherwise.

Technique IDs with a detection: T1098, T1098.002, T1098.003, T1110.003,
T1114.003, T1136.003, T1530, T1556.006, T1562.008, T1580, T1621.

## Tests

`tests/test_detection_schema.py` (8 tests, no Splunk needed): every SPL
detection has the required schema fields, a non-blank
`known_false_positives` that is not a bare "none"/"n/a", a search ending
in a `` `<name>_filter` `` macro reference, and a `mitre_attack_id` that
actually contains its own `target_technique_id`; every Sigma document is
valid YAML with the fields a base rule or correlation rule needs; no Sigma
rule uses the deprecated pipe-count syntax; every correlation rule
references a base rule that actually exists.

Proven able to fail:
- `test_no_sigma_rule_uses_the_deprecated_pipe_count_syntax`: reverted
  `aws_console_login_multiple_failures.yml`'s condition to the original
  `selection | count(eventID) by userIdentity.userName > 5` form and
  re-ran; failed with
  `AssertionError: ... condition 'selection | count(eventID) by
  userIdentity.userName > 5' uses deprecated pipe syntax`, then reverted
  the file back and re-ran clean.
- `test_every_spl_detection_has_non_blank_known_false_positives`: set
  `aws_iam_policy_deleted.yml`'s field to the literal string `"none"` and
  re-ran; failed with `AssertionError: ... known_false_positives is a
  non-answer ('none')`, then restored the file and re-ran clean.

`tests/test_detection_scoring.py` (5 tests, live Splunk, auto-skipped if
unreachable): the saved scoring evidence covers all 12 detections; all 12
have a recall hit; a direct, independent live re-check that the Azure
password-spray detection's real threshold does NOT fire on T1110.001 (the
specific false off-target hit the harness bug above produced); every
off-target hit in the saved evidence is reproducible by an independent
fresh live search, not just trusted from the JSON file; every detection's
COMPLETE production search (including the `fillnull`/`stats`/filter-macro
tail, not just the pre-aggregation matching logic) returns actual result
rows when run exactly as written.

Proven able to fail:
- `test_every_detection_has_recall_hit_on_its_target_technique`: flipped
  one saved `recall_hit` value to `false` in a copy of
  `evidence/detection_scoring.json` and re-ran; failed with
  `AssertionError: detections with no recall hit on their target
  technique: ['AWS CloudTrail Logging Stopped or Deleted']`, then restored
  the file and re-ran clean.
- `test_full_production_search_returns_results_on_target_technique`:
  removed the `| fillnull value="-" errorCode` line from
  `aws_cloudtrail_stop_delete_disable_logging.yml` (reproducing the real
  null-BY-field bug described below) and re-ran; failed with `assert 0 >
  0` (the full search's real output row count dropped from 3 to 0), then
  restored the file and re-ran clean. This is the same live bug this
  project actually hit and fixed, not a synthetic example.

Full suite: 29 passed (16 from Phase 1, unchanged, plus 13 new), raw output
in `evidence/15_full_test_suite_run.txt`.

## A real bug found and fixed: `stats ... by <field>` silently drops null rows

6 of the 12 detections group their final `stats` output by a field that is
absent on some or all matching events (`errorCode` on a successful
CloudTrail call, `object`/`ActorIpAddress` when a nested field is not
populated). Splunk's `stats ... by <field>` **silently excludes any row
where a BY field is null**, unlike a plain `table` or `where`. This zeroed
the actual output of `aws_cloudtrail_stop_delete_disable_logging.yml`
completely: 7 events matched the real filter logic, 0 rows survived the
final `stats`, confirmed by running the search pipe-by-pipe live and
watching the row count drop from 7 to 0 at exactly the `stats` line. This
is the same problem Splunk's own security_content detections defend
against with `| fillnull` immediately before their final `stats` (seen
directly in
`_corpora/security_content/detections/cloud/detect_new_open_s3_buckets_over_aws_cli.yml`'s
`| fillnull` line); the same fix (`| fillnull value="-" <field>...` ahead
of `stats`) was applied to all 6 affected detections here, and
`evidence/14_full_production_search_run.json` shows every detection now
returns real, non-empty output when run as a complete, real search. This
did not affect the recall/off-target numbers above (`score_detections.py`
strips the cosmetic `rename`/`stats` tail before scoring, so the
underlying match logic was never wrong), but it would have made every
affected detection's actual Splunk alert output silently empty in
production, which is a materially worse failure than a wrong recall
number, since nothing about running the search would have looked like an
error.

## What this project CANNOT claim

- **No precision or false-positive-rate number is reported, on purpose.**
  The research is explicit about why: the `attack_data` corpus is built to
  contain labelled attacks, not a genuine day-in-the-life benign cloud
  audit-log baseline. Any FP number computed only against this corpus
  would be optimistic by construction, closer to "recall reported twice"
  than a real precision measurement. This project reports recall,
  off-target firing against OTHER labelled techniques (a real, useful
  overfitting signal, but not the same thing as a benign baseline), and
  states plainly that it stops there.
- **The base-rate fallacy (Axelsson, ACM TISSEC 2000) is not addressed by
  anything measured here.** Cloud audit logs at real volume are
  overwhelmingly benign automation; even a detection with a clean
  off-target table above says nothing about what its absolute
  false-positive count would look like against a real tenant's full event
  volume, because this corpus's benign-to-malicious ratio is nowhere close
  to a real tenant's. A detection that looks specific against 45
  techniques' worth of labelled captures could still fire constantly
  against normal production automation this corpus does not contain any
  example of.
- **9 of 12 detections showing zero off-target hits is the easy result,
  not proof of quality.** The corpus is cleanly separated by construction
  (each technique's capture was generated to exercise that technique), so
  a static field-equality match naturally avoids collision with a
  different technique's cleanly-separated capture. A genuinely noisy
  production environment, with schema drift, multiple simultaneous benign
  processes touching the same API calls, and non-attack-simulation
  traffic, is a materially harder test this project does not have data for.
- **Coverage is 11 of 45 techniques (24.4%), and no claim is made that
  this is close to complete detection coverage of the cloud ATT&CK
  surface.** This is a portfolio-scale detection set built to demonstrate
  method (Sigma-first authoring, real conversion tooling, recall AND
  off-target scoring, honest documentation of blind spots), not a
  production security program's detection library.
- **The 3 detections with off-target hits were investigated and explained
  by direct evidence (a real shared `ForwardingAddress` value, a real
  `AccessDenied`-heavy enumeration burst, a real `Add service principal`
  event), but the underlying cause (these labelled captures may share
  setup/session activity across technique boundaries) was not
  independently verified beyond this project's own direct reads of the
  raw events.** If the `attack_data` corpus's generation process is
  documented elsewhere (its own repository, not fetched here), that would
  be the authoritative source for whether this cross-technique overlap is
  expected/by-design or a labelling artifact; this project states what it
  found by direct measurement and stops there.
- **The four correlation-based detections use fixed thresholds (`>5`,
  `>20`, `>3`), not learned per-entity baselines.** The research
  identifies "previously unseen X" baselining (a `lookup` against a
  maintained table, used in 31+ of security_content's 318 cloud
  detections) as the more robust noise-reduction pattern; this project
  does not implement that pattern (it would need a baseline-building
  scheduled search and a maintained lookup table, out of this phase's
  scope), and states that gap directly rather than implying the fixed
  thresholds here are equivalent.

## Anything that contradicted the research or Phase 1

1. **The research's going-in plan named "score them against the ATT&CK
   labels" as if a single number were the deliverable; this was already
   corrected by the research itself before any detection was written**
   (see "How this research CORRECTS the going-in assumption" in
   `cloud-detection-methodology.md`), and this build followed the
   corrected plan (recall + off-target + documented blind spots as three
   separate lines, not one collapsed score) from the start. No
   contradiction found here, noted because the brief specifically asked.
2. **A genuine, load-bearing gap the research did not predict: Sigma's
   documented `condition: selection | count() by field > N` pattern (the
   form that appears in older Sigma tutorials and examples across the
   web) is REJECTED by the current, real `pySigma` parser (1.5.0).**
   Neither the task brief nor the research doc anticipated this; it was
   found only by actually running the conversion tool rather than trusting
   that Sigma syntax written by hand would convert. Sigma Correlations
   (the real, current replacement) is a 2024 pySigma feature, and using it
   correctly required a genuine two-document-per-rule restructuring, not a
   one-line fix.
3. **The task brief's stated technique count (44) does not match the live
   count in the already-ingested index (45), confirmed directly**
   (`index=cloud_lab | stats dc(host)` = 45). Reported as measured, the
   same way Phase 1 reported its own file-count discrepancy against the
   brief rather than silently matching the brief's number.
4. **Splunk's own security_content detection for the S3 public-bucket
   scenario has an undocumented blind spot** (misses the XML-body
   `PutBucketAcl` shape, 1 of 8 labelled events for that exact technique),
   confirmed by testing that detection's exact field-enumeration approach
   against the same labelled capture this project used. Not a contradiction
   of anything this project assumed, but a finding worth recording since
   the research explicitly said to compare against and cite security_content's
   real patterns rather than assume they are complete.
