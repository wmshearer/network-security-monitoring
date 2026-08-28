# GUI / Splunk evidence: what was attempted, what actually happened

## What the task asked for

Run a detection in Splunk Web against real captured telemetry, then run the
same detection against a different incident's telemetry, and screenshot the
Web UI search results for both.

## What actually happened

1. Confirmed `splunkd` was running and the CLI session was authenticated
   (`/home/kali/splunk/bin/splunk search '...'` returned real results from an
   existing index).
2. Ingested the two real Sysmon logs cited in this repo's own detection
   `tests:` blocks (`T1195.001/npm/shai_hulud_workflow_sysmon.log` and
   `T1195.002/3CX/3cx_windows-sysmon.log`) into the lab's `ingest_lab` index
   via `splunk add oneshot`.
3. The oneshot ingested each multi-line XML log file as a single merged
   event instead of one event per `<Event>...</Event>` line, because the
   ad-hoc sourcetypes used had no line-breaking rule. Running the actual
   `tstats ... from datamodel=Endpoint.Filesystem` search from
   `shai_hulud_workflow_file_creation_or_modification.yml` against this data
   would not exercise the real matching logic; it would just fail to parse.
4. Added a `props.conf` at `/home/kali/splunk/etc/apps/search/local/props.conf`
   defining `LINE_BREAKER` for two new project-specific sourcetypes
   (`scd_shai_hulud_xml`, `scd_3cx_xml`), so as not to touch any existing
   production sourcetype. This required a `splunk restart` to take effect.
5. The restart invalidated the only authenticated session available to this
   task. The admin password is intentionally not stored anywhere this
   project can read (see `memory/splunk-lab-local-credential.md` in the
   director repo: it was deliberately removed after being found hardcoded
   in five files across three repos). Re-authentication was not possible
   without a human supplying `SPLUNK_PASS`.
6. Per this task's own instruction ("if the Splunk session has expired and
   you cannot authenticate, say so plainly and fall back to terminal
   evidence"), that is exactly what happened here. **No Splunk Web
   screenshot was captured, and none was fabricated.**
7. The `props.conf` change was reverted
   (`rm /home/kali/splunk/etc/apps/search/local/props.conf`) once it was
   clear it would not be used, to leave the shared instance as close to its
   prior state as possible.
8. `ingest_lab` still contains a handful of malformed (single-merged-event)
   test events from step 2, under `source=scd_project_shai_hulud_v2` /
   `scd_project_shai_hulud_v3` / `scd_project_3cx_v2` / `scd_project_3cx_v3`.
   The admin role available to this task's CLI session did not have
   `delete_by_keyword` capability, so these could not be removed. They are
   harmless (a lab-only scratch index, clearly source-tagged, no real
   secrets), but are disclosed here rather than left silently in place.

## Fallback actually delivered

`scripts/04_replay_detections_against_telemetry.py` re-implements the exact
match condition from two incident-bound detections' `search:` fields
(`shai_hulud_workflow_file_creation_or_modification.yml` and
`hunting_3cxdesktopapp_software.yml`) in Python, and runs it directly against
the same two raw Sysmon log files Splunk would have searched. It is not a
Splunk execution; it is a faithful, auditable substitute, and the script's
docstring says so.

The real terminal window running that script and its output for the
tally script are captured with `termcap.sh` (a real qterminal window on the
live X display, photographed, not a fake terminal rendering):

- `04_replay_incident_bound_cross_test.png`
- `03_classification_tally.png`

Both show a real command producing real output on this machine. Neither is
a Splunk Web screenshot, and this file says so plainly rather than implying
otherwise.
