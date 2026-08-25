# splunk-detection-lab

A Splunk detection-engineering lab built against real, publicly-sourced
captured attack telemetry (OTRF/Mordor Security-Datasets) and a real benign
Windows Server 2022 baseline, with ATT&CK ground truth preserved end-to-end
so every detection is *scored*, not just asserted.

Built under a hard time constraint: the local Splunk install is a 60-day
Enterprise Trial (started with this environment; expect it to lapse around
2026-09-05). **Splunk Free (what the license becomes after the trial) has
scheduled searches and alerting disabled entirely.** Everything in this repo
that depends on scheduled saved searches / alert actions was built and
evidenced *before* that lapse — see `evidence/` for the proof.

## What this is NOT

- Not Splunk Enterprise Security. ES is a paid product and was never
  installed or implied here — all detections are hand-written SPL saved
  searches with the built-in `logevent` alert action, which ships free with
  every Splunk license tier that has alerting enabled at all.
- Not a live-attack lab. No offensive tooling was run in this environment.
  All "attack" data is pre-captured, publicly published telemetry from the
  OTRF (Open Threat Research Forge) Security-Datasets project, analyzed
  after the fact.

## The data

Source (read-only, never modified): `../ai-triage-engine/data/raw/`, 389MB,
330 `.evtx` files total. Two genuinely different things live under that one
number:

| Source | Format on disk | Events | Ground truth |
|---|---|---|---|
| `otrf/captures/*.zip` (5 files) | zipped JSON-lines (OTRF's own format, already flat JSON, not `.evtx`) | 50,859 | `attack_mappings` in a matching sidecar `otrf/metadata/*.yaml` — one ATT&CK technique per capture (atomic = single technique executed end-to-end) |
| `otrf/compound_captures/*.zip` (2 files, APT29 Evals Day1/Day2) | zipped JSON-lines | ~783K (196K + 587K) | **No per-technique ground truth published anywhere by OTRF** for these (15+ technique, multi-day campaigns; the only sidecar files present are the 5 atomic-capture YAMLs) |
| `evtx_baseline/win2022-evtx/win2022-evtx/*.evtx` (330 files) | real binary `.evtx` | 242,133 (94 non-empty channels) | None — this is a benign Windows Server 2022 baseline host, used entirely as the negative/benign class |

**Decision: APT29 compound captures are excluded from this project.**
Two independent reasons, either one sufficient alone:
1. No per-event or single-primary ATT&CK technique mapping exists for them
   anywhere in this dataset (confirmed: no metadata YAML, and OTRF's own
   published compound-capture docs give only per-Channel/per-EventID counts,
   never a technique join key — this is the same conclusion
   `../ai-triage-engine/src/ingest/normalize_compound.py` reaches, read for
   reference, not modified). Scoring a detection against them would mean
   inventing ground truth this project's constraints explicitly forbid.
2. Practically: uncompressed they run to ~2.1GB combined (196K + 587K JSON
   events) against a 500MB/day trial license quota that was already at
   459MB/500MB after ingesting the 5 atomic captures + benign baseline (see
   `evidence/`). Ingesting them risked breaking the license before Phase 2's
   scheduled alerts could be evidenced.

### What "attack" labels actually claim — read before trusting any count

An atomic capture's `attack_mappings[0]` technique applies to the ENTIRE
capture, not to every individual event in it. `empire_persistence_...`
carries 40,569 total events but only 2 of them are the actual Sysmon
EventID-13 registry `SetValue` that constitutes T1547.001 — the rest is
session noise (process starts, other registry activity, security auditing)
that happened to occur during that same captured session. Every scoring
number in `FINDINGS.md` is stated at the right unit (capture-level
TP/FN, event-level FP) for exactly this reason — see
`src/score_detections.py`'s module docstring for the full rationale.

## Phase 1 — Ingest

### The EVTX-on-Linux problem, and what was tried

Splunk Enterprise on Linux has no native EVTX (binary Windows Event Log)
parser. Splunk's own supported path for `.evtx` is a Windows universal
forwarder reading the live Windows Event Log API — not applicable here
(this is offline captured `.evtx` files, no Windows host in the loop, and
the task is analysis of existing data, not new infrastructure).

**Tried and rejected:** pointing a `monitor://` input directly at a `.evtx`
file. Splunk indexes it as an opaque, mis-segmented binary/text blob — EVTX's
binary chunk/record framing does not line up with any text line-breaking
rule a `props.conf` LINE_BREAKER can express. This is exactly the "guessed
sourcetype on a binary blob" failure mode the project's own constraints
call out to avoid, so it was abandoned in favor of an honest conversion step.

**Chosen:** convert to JSON-lines first, on the Linux host, using the `evtx`
PyPI package (github.com/omerbenamram/evtx, aka pyevtx-rs) — Rust-backed,
dual MIT/Apache-2.0 licensed, versions 0.12.x with prebuilt wheels. This is
the same library already used, tested, and documented in
`../ai-triage-engine/src/ingest/parse_evtx.py` (read for reference and
field-mapping rationale only — never imported or modified; this project's
`src/convert_evtx.py` is a standalone reimplementation of the same
flattening approach, using the field-name-parity evidence already verified
by that project's own tests against the same real data). OTRF's atomic
captures need no such conversion — they already ship as JSON-lines (see
`src/convert_otrf.py`); only labeling and technique-tagging happens there.

### Sourcetype and field extraction — explicit, not automatic

One custom sourcetype, `mordor:winlog:json`, defined in `conf/props.conf`
and deployed to `/home/kali/splunk/etc/apps/splunk_detection_lab/local/`.
Per the task's explicit ask, NONE of Splunk's automatic sourcetype/KV
detection is relied on:
- `INDEXED_EXTRACTIONS = json` — declarative, JSON-spec-driven field
  extraction at index time (not `KV_MODE=auto` heuristic key=value guessing;
  `KV_MODE = none` is set explicitly to make sure the two mechanisms never
  double-extract).
- `TIME_PREFIX`/`TIME_FORMAT` explicitly target the `@timestamp` JSON field
  (chosen over the also-present `EventTime` field because `@timestamp` is
  uniformly ISO-8601-with-`Z` in BOTH sources — verified directly — while
  `EventTime` is ISO-8601 in the benign source but
  `YYYY-MM-DD HH:MM:SS` second-precision, no offset, in the OTRF source).
- `TRANSFORMS-rename_event_type` (`conf/transforms.conf`) handles one real
  field-name collision found during detection development (see "What broke"
  below).

Dedicated index: `detection_lab` (`conf/indexes.conf`), not `main`.
`label` (`attack`/`benign`) and `technique_id` are written by the
conversion scripts as plain top-level JSON keys, so `INDEXED_EXTRACTIONS=json`
makes them real indexed fields automatically — ground truth survives the
whole pipeline as a first-class, filterable field, not something bolted on
after the fact.

### What broke during ingest (documented, not hidden)

1. **`MAX_TIMESTAMP_LOOKAHEAD`/`%Z` format mismatch.** First `TIME_FORMAT`
   attempt used `%9Q%Z` for `2020-09-21T07:15:27.705Z` — `%Z` does not match
   a bare literal `"Z"` in Splunk's strptime, so timestamp extraction
   silently failed and every event landed at *ingest* time (2026) instead of
   its real 2019-2022 timestamp. Fixed by literal-matching `Z` in the format
   string (`%Y-%m-%dT%H:%M:%S.%QZ`).
2. **`MAX_DAYS_AGO` default (2000 days, ~5.5 years) silently rejected
   correctly-parsed historical timestamps.** Even after fixing (1), events
   from 2019-2020 (the OTRF captures) were still landing at ingest time.
   `splunkd.log` had the answer: `DateParserVerbose ... matching timestamps
   (Mon Sep 21 07:15:27 2020) outside of the acceptable time window`. Fixed
   by setting `MAX_DAYS_AGO = 3000` in `props.conf`, wide enough to cover
   the oldest capture (2019-03) from ingest time.
3. **`EventType` field-name collision with Splunk's reserved `eventtype`
   knowledge-object concept.** Real Sysmon events carry an `EventType` JSON
   field (e.g. `"SetValue"`, `"CreateKey"`) — confirmed present in `_raw` —
   but `| table EventType` (any case) silently returns empty instead of
   erroring. Splunk's search-time layer treats `eventtype` as reserved.
   Every detection SPL in this project therefore avoids relying on
   `EventType` (uses `TargetObject`/`EventID` instead, which is sufficient);
   `conf/transforms.conf` was written to rename it to `sysmon_event_type` at
   index time.

   **That rename does not work, and this correction is worth more than the
   original claim.** Verified 2026-08-23:
   `index=detection_lab | stats count(sysmon_event_type), count` returns 0
   populated out of 292,992 events. `INDEXED_EXTRACTIONS = json` parses in the
   structured-data phase, which runs before and instead of the TRANSFORMS
   phase, so the stanza's regex never sees the event. The two settings conflict
   and Splunk gives no warning about it.

   Nothing in the project depended on the rename: every detection uses
   `EventID` and `TargetObject`. That is exactly why it went unnoticed, and it
   is the same class of silent failure as the three bugs above.
4. **A metadata/manifest JSON file got accidentally oneshot-ingested as an
   event file** on the first ingest pass (`_conversion_manifest.json` sat
   alongside the real per-capture JSON files and matched the bulk-ingest
   glob). Caught by exact event-count verification against the conversion
   scripts' own reported counts (293/293 didn't match). Fixed by moving
   manifests to a sibling `data/converted/_manifests/` directory (structural
   fix in `src/convert_*.py`, not just a one-off cleanup) and redoing a
   clean ingest.
5. **SPL backslash-in-quoted-wildcard escaping is inconsistent depending on
   which shell/HTTP layer sends it.** `TargetObject="*CurrentVersion\Run*"`
   (single literal backslash) returned zero results from one calling
   convention but matched correctly when the exact same logical pattern was
   sent as `TargetObject="*\\Run\\*"` (SPL requires `\\` for a literal
   backslash inside a quoted string — every detection SPL in this repo uses
   that form). This cost real debugging time and is worth flagging for
   anyone else programmatically building SPL with Windows paths.

### Reproduction — ingest from scratch

```bash
cd splunk-detection-lab
python3 -m venv .venv && source .venv/bin/activate
pip install evtx pyyaml requests

# 1. Convert the 5 OTRF atomic captures (JSON-lines, labeled + technique-tagged)
python3 src/convert_otrf.py \
  --captures-dir ../ai-triage-engine/data/raw/otrf/captures \
  --metadata-dir ../ai-triage-engine/data/raw/otrf/metadata \
  --out-dir data/converted/attack

# 2. Convert the benign evtx-baseline (.evtx -> JSON-lines, labeled benign)
python3 src/convert_evtx.py \
  --src-dir "../ai-triage-engine/data/raw/evtx_baseline/win2022-evtx/win2022-evtx" \
  --out-dir data/converted/benign

# 3. Deploy the Splunk app (index/sourcetype/saved-search definitions)
cp conf/indexes.conf conf/props.conf conf/transforms.conf conf/savedsearches.conf \
   $SPLUNK_HOME/etc/apps/splunk_detection_lab/local/
$SPLUNK_HOME/bin/splunk restart

# 4. Ingest (oneshot per converted file; do NOT glob the _manifests/ dir)
for f in data/converted/attack/*.json data/converted/benign/*.json; do
  $SPLUNK_HOME/bin/splunk add oneshot "$f" -index detection_lab \
    -sourcetype mordor:winlog:json -auth admin:<password>
done

# 5. Verify
python3 src/splunk_search.py "index=detection_lab | stats count by label"
# expect: attack=50859, benign=242133
```

### Ingest verification (evidence/)

- `evidence/counts_by_sourcetype.json` — 292,992 events, 1 sourcetype
  (`mordor:winlog:json`), matches raw event count exactly.
- `evidence/counts_by_label_capture.json` / `counts_by_technique.json` — per-
  capture, per-technique counts, matching `src/convert_otrf.py`'s own
  reported counts exactly (40569/1297/884/1907/6202 for the 5 techniques,
  242133 for benign).
- `evidence/field_extraction_proof.json` — a real search returning parsed
  `TargetObject`/`Details`/`technique_id` fields (not a raw-text blob),
  proving indexed JSON extraction actually works, not just that data landed.

## Phase 2 — Detections

6 hand-written SPL detections (see `conf/savedsearches.conf` for the exact
deployed saved-search stanzas, `evidence/detection_dev/*.spl` for the raw
SPL filter fragments used to build and test them). Every detection maps to
one ATT&CK technique **verified against a real OTRF metadata YAML in this
dataset**, never invented:

| ID | ATT&CK ID | Technique | SPL signal |
|---|---|---|---|
| D1 | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Sysmon EventID 13 (`SetValue`) where `TargetObject` is a named value under `...\Run\...` |
| D2 | T1053.005 | Scheduled Task/Job: Scheduled Task | Sysmon EventID 1, `Image=*schtasks.exe`, command line references `powershell` + `hidden` |
| D3 | T1069.001 | Permission Groups Discovery: Local Groups | Sysmon EventID 1, `net.exe`/`net1.exe` with `localgroup ... administ*` |
| D4 | T1087.001 | Account Discovery: Local Account | Sysmon EventID 1, `net.exe`/`net1.exe` with `user` but NOT `localgroup` (distinguishes from D3) |
| D5 | T1123 | Audio Capture | Sysmon EventID 10 (ProcessAccess) targeting `AUDIODG.EXE` |
| D6 | T1059.001 | Command and Scripting Interpreter: PowerShell | Sysmon EventID 1, `ParentImage=*powershell.exe` spawning `net.exe`/`net1.exe`/`schtasks.exe` (deliberately cross-cutting — the enabling behavior behind D2-D4's captures, scored against all 3) |

All 6 are saved searches AND scheduled (`enableSched=1`) with a real,
license-free alert action (`logevent`, Splunk-native — writes a new indexed
event to the dedicated `detection_lab_alerts` index every time the search
fires, with `alert.digest_mode=0` so it fires once per matching result row).
See `FINDINGS.md` for full scoring and `evidence/` for proof they actually
fired on schedule.

## Phase 3 — Evidence

See `evidence/` for: ingest counts, field-extraction proof, per-detection
dev/test SPL and results, the scoring JSON, and scheduled-alert firing
proof (`fired_alerts` snapshots, `splunkd.log` excerpts showing
`sendmodalert`/`logevent` invocations, and the resulting indexed alert
events in `detection_lab_alerts`).

## Phase 4 - Robustness scoring

The scoring above answers "did each detection fire on the capture it
targets." It does not answer "how hard is it for an attacker to make that
detection stop firing." That is a different, separate question, and it is
scored against a published rubric instead of asserted in prose.

Each of the 6 detections is scored against MITRE CTID's "Summiting the
Pyramid" (STP), an Apache-2.0 methodology built on top of David Bianco's
Pyramid of Pain that grades a detection analytic 1 to 5 on how much an
adversary has to change to evade it, plus a separate K/U/A letter for how
tamper-resistant the telemetry source is. Full scores, reasoning, and the
worked evasion demonstration are in `FINDINGS.md`'s "Robustness scoring"
section. Summary: D1 (the registry Run-key detection) scores highest at
Level 4; D2, D3, and D4 (all keyed on literal command-line text) score at
Level 1, the lowest tier STP defines; D5 and D6 sit at Level 2.

The Level 1 score for D2 is not just asserted. `src/evasion_demo.py` takes
a copy of the real captured `schtasks.exe` event D2 and D6 both fire on,
edits only its `CommandLine` field the same way FINDINGS.md's 2026-08-24
correction tested by hand, and re-runs D2's and D6's real match logic
against the edited copy. Two of the four tested edits stop D2 from firing
while D6 (which never reads `CommandLine`) keeps firing on the exact same
edited event:

```
$ python3 src/evasion_demo.py
transformation                                                              D2 fires   D6 fires
-------------------------------------------------------------------------------------------------
original (unedited)                                                         True       True
-W hidden -> -windowstyle hidden (tested: does NOT evade D2)                True       True
interpreter renamed, same directory (tested: does NOT evade D2, ...)        True       True
-W hidden -> -WindowStyle 1 (tested: evades D2)                             False      True
interpreter copied to C:\Users\Public\svc.exe (tested: evades D2)           False      True
```

See `evidence/robustness/screenshots/evasion_demo_run.png` for the real
terminal output and `evidence/robustness/evasion_results.json` for the raw
data. `evidence/robustness/stp_scores.csv` holds all 6 scores in the exact
column structure MITRE's own published scored-analytics CSV uses.

## Repo layout

```
conf/               props.conf, transforms.conf, indexes.conf, savedsearches.conf
                     (exact copies of what's deployed under
                     $SPLUNK_HOME/etc/apps/splunk_detection_lab/local/)
src/                 convert_evtx.py, convert_otrf.py, splunk_search.py,
                     score_detections.py, score_robustness.py, evasion_demo.py
tests/               pytest — scoring logic + ATT&CK metadata extraction +
                     robustness scoring + evasion demonstration
evidence/            ingest counts, field-extraction proof, detection dev/
                     test SPL + results, scoring JSON, alert-firing proof,
                     robustness/ (STP scores CSV, evasion results, screenshots)
data/converted/      generated by src/convert_*.py — NOT checked in (.gitignore),
                     regenerate from ../ai-triage-engine/data/raw per the
                     reproduction steps above
```

## Constraints honored

- No offensive tooling run; all attack data is pre-captured, analyzed after
  the fact.
- `../ai-triage-engine/` read only, never modified.
- No paid Splunk apps (Enterprise Security was never installed or implied).
- No credentials/hashes/keys appear in this repo's evidence in plaintext —
  none were present in the source captures' relevant fields to begin with
  (the OTRF captures used are discovery/persistence/collection techniques,
  not credential-access techniques); if any had appeared they would be
  marked `[REDACTED]`.
