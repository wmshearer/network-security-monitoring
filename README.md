# soar-playbooks

Automated playbooks triggered by the detection alerts already produced by
`splunk-detection-lab` in this portfolio. This reads that lab's Splunk
instance and its ATT&CK reference data; it does not modify either.

## Terms, defined once, up front

- **SOAR** (Security Orchestration, Automation and Response): a class of
  tool that receives a security alert, runs a scripted sequence of steps
  against it (enrich, decide, respond), and records the outcome, without a
  human doing each step by hand.
- **Playbook**: the scripted sequence itself. One playbook here enriches
  and produces a verdict, a second one recommends a response.
- **Orchestration**: the plumbing that ties the trigger, the playbooks,
  and the logging together into one run. In this project that plumbing is
  a plain Python script, not a separate platform (see "Platform decision"
  below).
- **Enrichment**: looking up an indicator against an outside source to add
  context, for example asking a threat-intel service whether an IP
  address is known to scan the internet.
- **IOC** (Indicator of Compromise): a concrete value from an alert, an
  IP, a file hash, a registry path, a process name, believed relevant to
  an intrusion.
- **False positive**: an alert that fired but was not actually malicious.
  SOAR playbooks exist partly to cut down how much human time false
  positives cost, by doing the first pass of enrichment automatically.

## What this project actually does

1. An external poller reads new rows from Splunk's `detection_lab_alerts`
   index over the REST API, tracks which ones it has already processed,
   and hands each new one to two playbooks.
2. Playbook 1 pulls the raw event behind the alert, extracts whatever
   indicators are genuinely present in it, and enriches them against
   real, keyless, free-tier sources. It also runs a real, working call
   path for a source that needs a paid-tier key, which is skipped and
   labeled as skipped here because no key was obtained.
3. Playbook 2 recommends a response (isolate the host, or escalate to an
   analyst) and logs it as a `SIMULATED_ACTION`, never a real one.
4. Every alert processed, every indicator extracted, every source call
   (made or skipped and why), and every verdict is written to a JSON
   record in `evidence/runs/`.

There is no live enterprise network, EDR agent, identity provider, or
firewall behind this lab. Section "What this cannot claim" at the bottom
says plainly what that rules out.

## Platform decision, and why

This project runs as plain Python (`src/run_pipeline.py`), not inside a
self-hosted SOAR engine like Shuffle or Tracecat, even though both were
evaluated and both would run fine here (Docker works without sudo on this
machine, confirmed live: `docker run --rm hello-world` pulled and ran
cleanly as the plain user).

The reason is what a container would actually add. Shuffle and Tracecat
both ship webhook triggers, a workflow canvas, and built-in case storage.
None of that changes what gets demonstrated here: this portfolio's own
real alerts, run through indicator extraction and a documented decision
rule, against real keyless enrichment, with an explicit
decision-versus-action boundary. Standing up a container platform for
that would cost roughly an hour of Compose setup and produce a workflow
canvas screenshot, not a different result. Splunk's own SOAR product
ships 90-plus pre-built playbooks and Tracecat ships 100-plus connectors
covering the standard patterns (phishing triage, isolation, account
disable, ticketing) already. Re-deriving those patterns as "playbooks"
would mostly be re-publishing content the vendors already publish. The
part that is not already shipped anywhere is this portfolio's specific
detections, wired to a trigger that survives this specific Splunk
instance's license downgrade, producing this specific measured result.
That is what this project builds, and Python is enough to build it.

If a future version of this project wants a workflow canvas for
demonstration purposes, Tracecat (AGPL-3.0, self-hosted via Docker
Compose, confirmed working without sudo) is the documented next step, not
Shuffle: Shuffle's backend is also AGPLv3, not Apache-2.0, so there is no
licensing reason to prefer it, and Tracecat's built-in case management
maps directly onto "enrich, decide, log a case" without adding a second
tool.

## The trigger, and how it survives the Splunk Free change

This Splunk instance is running on an Enterprise trial license
(`/home/kali/splunk/etc/splunk-enttrial.lic` on disk) that converts to
Splunk Free in roughly ten days from when this project was built.
Splunk's own documentation states plainly that **alerting and monitoring
are disabled on Splunk Free**. That specifically means the scheduler that
fires a saved search's alert action, the exact mechanism that would call
a webhook the instant an alert fires, stops working. Ad-hoc search and
the REST API are not disabled on Free.

So this project's trigger is `src/poller.py`, an external script that
queries `index=detection_lab_alerts` through Splunk's REST search API
(`/services/search/jobs`, `exec_mode=oneshot`) on demand. It does not
depend on Splunk's scheduler existing at all. It tracks which alert rows
it has already handed to the playbooks (by Splunk's own per-event `_cd`
bucket:offset identifier) in `data/poller_state.json`, so re-running it
never reprocesses the same alert twice, proven in `tests/test_poller.py`.

The honest tradeoff: this design means "alert observed, up to
POLL_INTERVAL late" rather than "reacted the instant the alert fired."
That is a weaker latency claim than a live webhook would give. It is also
the only design confirmed to still work after the Splunk Free conversion,
so it is the one built here from the start rather than bolted on as an
emergency fix in ten days.

Credentials: `SPLUNK_URL`, `SPLUNK_USER`, `SPLUNK_PASS` must be set as
environment variables before running anything in this project. There is
no default value and no fallback password anywhere in this repo's source.
`src/splunk_client.py` raises `MissingCredentials` immediately if any of
the three are unset, before any network call is attempted.

```
export SPLUNK_URL="https://localhost:8089"
export SPLUNK_USER="<your admin user>"
export SPLUNK_PASS="<your admin password>"
python3 src/run_pipeline.py
```

## Playbook 1: what was actually enriched, and against which live sources

First, what this portfolio's detections actually carry. Before writing any
enrichment code, the raw Sysmon events behind D1 through D6 were inspected
directly (`data/converted/attack/*.json` under `splunk-detection-lab`,
read only). All six detections match on Sysmon EventID 1 (process
creation), EventID 10 (process access), or EventID 13 (registry
SetValue). None of those event types populate a source or destination IP
in this dataset, and Sysmon's `Hashes` field is only populated on EventID
7 (image load) and EventID 23 (file delete) events, which none of D1-D6
match on. So the indicators this pipeline can genuinely extract from
these alerts are: **process image path, parent process image path,
registry target path, and hostname**. It cannot extract an IP or a file
hash from these six detections, because they are not there. The code
reports this explicitly rather than fabricating an IP to have something
to enrich.

Sources, and what actually happened with each one on the real run:

| Source | Needs a key? | Called live on the real run? | Why |
|---|---|---|---|
| **GreyNoise Community API** | No. Genuinely keyless, confirmed by a live unauthenticated call during development (`evidence/screenshots/04-greynoise-live-keyless-call.png`), a real HTTP request with no Authorization header that returned a real 200-class response body. | No, on the real 1,433-alert run. The call path is real and unit-tested, but GreyNoise only accepts IP addresses, and D1-D6 never produce an IP indicator (see above). | Recorded as skipped, with the specific reason, on every one of the 1,433 alerts: `"skipped: no IP-shaped field populated on this event"`. |
| **AbuseIPDB** | Yes, free registration required per its own docs. | No. `ABUSEIPDB_API_KEY` was left unset, per this project's constraint against signing up for any service. | Recorded as skipped: `"skipped: ABUSEIPDB_API_KEY not set in environment"`, and would also be skipped for lack of an IP indicator even if a key were supplied. |
| **VirusTotal** | Yes, free registration required per its own docs. | No. `VT_API_KEY` was left unset, same reason. | Recorded as skipped: `"skipped: VT_API_KEY not set in environment"` where a hash indicator would apply (never, for D1-D6), and `"skipped: no Hashes field populated"` otherwise. |
| **MITRE ATT&CK technique context** | No key, but also not a live lookup. | Yes, on every alert, but this is a local, offline join against the ATT&CK Enterprise STIX bundle already on disk (`cloud-detection-coverage/data/enterprise-attack.json`, read only). It resolves a technique ID like `T1547.001` to its name and tactic. Labeled `"local ATT&CK lookup"` everywhere it appears in output, never presented as a live threat-intel call. | Adds technique context to the verdict record for readability, does not affect the malicious/benign decision. |

If a key is later supplied (`export VT_API_KEY=...` /
`export ABUSEIPDB_API_KEY=...`), the code calls the real API immediately,
no code change needed, because the key lookup happens at call time from
the environment, not at import time.

Verdict rule, applied identically to every alert (`decide_verdict` in
`src/playbook_enrich.py`):

1. If any source that was actually **called** (not skipped) returned a
   positive classification, `malicious`, confidence `high`.
2. Else if **no source was callable at all** for this alert (its
   indicators are not IP or hash shaped, and/or no key is configured),
   `unresolved`, confidence `none`.
3. Else (a source was called and came back clean), `benign`, confidence
   `low`.

On the real run this project produced, every one of the 1,433 alerts
landed on rule 2: `unresolved`. That is not a bug and not a weak result
being hidden; it is the correct, honest outcome given what this
portfolio's six detections actually carry and which sources have keys.
`evidence/screenshots/03-sample-enrichment-and-action.png` shows one full
record end to end.

## Playbook 2: the simulated-action boundary

Playbook 2 (`src/playbook_response.py`) maps each detection to a
recommended response and logs it as a `SIMULATED_ACTION` record:

- D1 (registry Run key persistence) and D2 (scheduled task with encoded
  PowerShell) recommend `isolate_host`: persistence findings are the
  class of alert that most directly justifies pulling a host offline
  pending investigation.
- D3 (local admin group enumeration) and D4 (local user enumeration)
  recommend `escalate_to_analyst`, not `isolate_host`: enumeration alone
  is common in benign admin activity, and auto-isolating on
  discovery-only evidence is an overreaction most SOCs would not
  automate.
- D5 (process access to AUDIODG.EXE, audio capture) recommends
  `isolate_host`: this specific detection had zero false positives
  against splunk-detection-lab's full benign baseline (see that project's
  FINDINGS.md), so it is treated as high confidence.
- D6 (PowerShell spawning a recon tool) recommends `escalate_to_analyst`:
  enabling behavior for other techniques, not itself confirmed malicious
  action.
- If Playbook 1's verdict for that alert is `malicious`, the
  recommendation is upgraded to `isolate_host` regardless of the table
  above.

This playbook does not call an EDR API, does not call an identity
provider, and does not call a firewall. There is none reachable from this
lab. Every record it produces carries the literal string
`"label": "SIMULATED_ACTION"` and a `reasoning` field explaining the
decision. `tests/test_playbook_response.py::test_simulated_action_never_claims_a_real_action_verb`
asserts the reasoning text never contains phrasing like "isolated host"
or "successfully executed", specifically to keep this playbook from
drifting toward implying it did something it did not do.

## The measured result

Real numbers from the run recorded at `evidence/runs/run_*.json`
(`evidence/screenshots/02-run-summary.png` shows the same numbers
rendered from that file):

- **1,433 alerts polled**, matching `splunk-detection-lab`'s full
  six-detection alert history end to end (D1: 36, D2: 18, D3: 36, D4: 34,
  D5: 1,258, D6: 51).
- **1,433 new alerts processed** on a clean run (poller state reset first
  so nothing was skipped as already-seen).
- **0 extraction failures**: every alert's underlying raw event was
  successfully retrieved from Splunk.
- **1,227 indicators extracted** across the run: 924 hostname, 161
  process image, 106 parent image, 36 registry path. No IP and no hash
  indicators, for the reason explained above.
- **Verdicts: 1,433 unresolved, 0 malicious, 0 benign.** Honest given the
  indicator kinds available and the lack of any configured API key; see
  "What this cannot claim."
- **Simulated actions: 1,312 isolate_host, 121 escalate_to_analyst.**
- **3,733 enrichment source calls recorded, all skipped, none actually
  called**: 1,433 GreyNoise Community skips (no IP present), 1,433
  AbuseIPDB skips (no key), 1,345 VirusTotal skips (mix of no-hash and
  no-key; hash-branch skip count differs slightly from 1,433 because the
  no-key skip is only recorded once per alert where the hash branch would
  have applied). GreyNoise's call path was proven live and working
  separately, against a test IP outside the pipeline
  (`evidence/screenshots/04-greynoise-live-keyless-call.png`), since the
  pipeline itself never had an IP indicator to feed it.
- **Elapsed time: 164 seconds** for the full 1,433-alert run (two Splunk
  REST queries per alert: one to re-fetch the matching raw event, one
  implicit in the poller's initial index scan).

## Tests

`tests/` has 20 assertions across four files, all with real fixtures, no
mocked-and-forgotten stubs. Each test was proven able to fail before being
left in its passing state: the relevant line of source was broken, the
test suite was run to confirm the exact test failed with the expected
assertion error, then the source was restored and the suite was re-run to
confirm a clean pass.

| Test file | What it proves | How it was proven able to fail |
|---|---|---|
| `test_poller.py` (3 tests) | The `_raw` line format `action.logevent` actually writes is parsed correctly, including a quoted `search_name` value containing spaces and parentheses; and previously-seen alerts are correctly excluded by `_cd`. | `_parse_logevent_raw` was temporarily short-circuited to always return `{}`. All 3 tests failed (`KeyError` / wrong detection value). Restored, all 3 passed. |
| `test_enrichment.py` (8 tests) | Indicator extraction only returns fields that are actually populated (rejects Splunk's `"-"` empty placeholder); IP/hash presence is detected correctly; sources are skipped with the right reason when no key or no applicable indicator exists; the local ATT&CK lookup resolves a known technique and returns `None` for an unknown one. | The `"-"` placeholder filter (`if val and val != "-"`) was changed to `if val`. The test asserting `ParentImage: "-"` is excluded failed, now including a phantom `parent_image` indicator. Restored, passed. |
| `test_playbook_enrich.py` (5 tests) | The verdict decision rule: unresolved when nothing is callable, malicious when a real source flags positive (GreyNoise noise flag, AbuseIPDB score >= 50), benign when called but clean, and a low AbuseIPDB score does NOT get flagged malicious. | The AbuseIPDB malicious threshold (`score >= 50`) was changed to `score >= 0`. The low-score test, which exists specifically to guard this threshold, failed by asserting `malicious` instead of `benign`. Restored, passed. |
| `test_playbook_response.py` (4 tests) | Persistence detections recommend `isolate_host`; discovery detections recommend `escalate_to_analyst`; a malicious verdict upgrades any detection to `isolate_host`; and the reasoning text never contains a real-action verb phrase. | D3's mapping was changed from `escalate_to_analyst` to `isolate_host`. The discovery-recommends-escalate test failed. Restored, passed. |

Run it: `source .venv/bin/activate && python3 -m pytest tests/ -v`.
`evidence/screenshots/01-pytest.png` shows the real, passing run: 20
passed in 0.26s.

## What this cannot claim

- It cannot claim any host was actually isolated, any account actually
  disabled, or any IP actually blocked. There is no EDR, no identity
  provider, and no firewall reachable from this lab. Every response
  decision is logged as `SIMULATED_ACTION` and nothing else, on purpose.
- It cannot claim a live-fired, instant-reaction trigger. The poller
  design that survives Splunk Free's licensing change trades that away:
  it observes alerts up to a poll interval late, not the instant they
  fire.
- It cannot claim this portfolio's real detections produce IP or file
  hash indicators, because they do not. Every "unresolved" verdict on the
  real run reflects that fact honestly rather than a bug in the
  enrichment logic. The GreyNoise Community call path is real and proven
  live-working, but it was never exercised inside the actual pipeline run
  because none of D1-D6's alerts ever gave it an IP to look up.
- It cannot claim AbuseIPDB or VirusTotal were exercised at all. No API
  key was obtained for either, per this project's constraint against
  signing up for any service. Both are wired to read a key from the
  environment and will call the real API the moment one is supplied, but
  as shipped, both sources show 0 real calls in every run record.
  If it turns out a supplied key still produces zero calls because none
  of D1-D6 carry a hash or IP indicator, that would be additional
  evidence of the same underlying fact, not a new problem.
- It does not catch a live phishing email in real time. None of this
  portfolio's alert sources (splunk-detection-lab's six detections) are
  phishing-shaped. A phishing playbook, if added later, would need a
  synthetic or static sample email as its trigger and should say so.
- The measured "malicious: 0" is not evidence this pipeline is bad at
  finding malicious activity. Every one of these 1,433 alerts came from
  intentionally-run attack simulations (Mordor/Empire/Metasploit captures
  replayed into Splunk), so a real, working malicious-indicator source
  would very plausibly have flagged some of them, if these particular
  detections carried IP or hash indicators to feed it. They do not, and
  that is the honest finding this project reports rather than hides.

## Repository layout

```
src/
  models.py             dataclasses shared across the pipeline
  splunk_client.py      REST client, credentials from environment only
  poller.py             the trigger: polls detection_lab_alerts, dedupes
  enrichment.py         indicator extraction + all enrichment source calls
  playbook_enrich.py    Playbook 1: fetch raw event, enrich, decide verdict
  playbook_response.py  Playbook 2: recommend + log SIMULATED_ACTION
  run_pipeline.py        ties the above together, writes the run record
tests/                  20 tests across 4 files, see "Tests" above
evidence/
  runs/                 real JSON run records from src/run_pipeline.py
  screenshots/          termshot.py renders of real command output
data/
  poller_state.json     which alert _cd values have already been processed
```
