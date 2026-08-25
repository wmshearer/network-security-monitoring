# IR: Apache ActiveMQ Exploit to LockBit 3.0 Ransomware

An end-to-end incident response investigation of a real, documented multi-stage
intrusion: CVE-2023-46604 (Apache ActiveMQ OpenWire RCE) used as initial access,
through to LockBit 3.0 ransomware deployment. Full writeup:
[`reports/IR_REPORT.md`](reports/IR_REPORT.md).

## What this is

Splunk's own Apache-2.0-licensed simulated reproduction of the intrusion
documented by The DFIR Report
(<https://thedfirreport.com/2026/02/23/apache-activemq-exploit-leads-to-lockbit-ransomware/>),
ingested into a real Splunk instance, investigated with real SPL, and used to
write and score real Sigma/SPL detections. The dataset lives in this
portfolio's shared corpus at
`../_corpora/attack_data/datasets/apt_simulations/ActiveMQ_exploit_Lockbit_Ransomware/`
and is not copied into this repo (95MB, three raw Windows XML event logs).

## Layout

```
detections/sigma/   6 Sigma rules for the confirmed attack stages
detections/spl/     Same 6, converted to real SPL via sigma-cli
evidence/           Real search output, screenshots, scoring results
reports/IR_REPORT.md  The full IR report
splunk_app/          Copy of the deployed Splunk app config (index/props/metadata)
src/ingest.sh         Re-runnable ingest script
src/splunk_search.py  REST API search helper used by tests
tests/                pytest suite, live against the real Splunk index
```

## Reproducing this

```bash
# 1. Deploy the Splunk app config (index, props.conf with the TZ fix)
cp -r splunk_app/local splunk_app/metadata $SPLUNK_HOME/etc/apps/ir_activemq_lockbit/
$SPLUNK_HOME/bin/splunk restart

# 2. Ingest
SPLUNK_AUTH=admin:yourpassword src/ingest.sh \
  ../_corpora/attack_data/datasets/apt_simulations/ActiveMQ_exploit_Lockbit_Ransomware

# 3. Run the tests
SPLUNK_PASS=yourpassword python3 -m pytest tests/ -v
```

## The one real ingest gap

43,104 of 43,105 PowerShell-Operational events made it into the index. Direct
investigation (duplicate-content hashing, malformed-event check, length-limit
check, timestamp-collision check) did not resolve which single event was
dropped or why, within the time budgeted for it. Reported as-is in
`reports/IR_REPORT.md` and pinned by `tests/test_ingest.py`, not glossed over.

## The real timezone bug this project found and fixed

`Splunk_TA_windows`'s shipped `props.conf` gives `Microsoft-Windows-
Sysmon/Operational` an explicit `TIME_PREFIX`/`TIME_FORMAT`/`TZ`, but the
`Security` and `PowerShell-Operational` XmlWinEventLog sources have no
timestamp configuration at all. Without a local override, both fell back to
Splunk's index-time timestamp (today's date, four months off from the real
2026-04-24 event data). Adding `TIME_PREFIX`/`TIME_FORMAT` fixed the date but
first landed every event exactly 7 hours off from true UTC, because the format
string's literal `Z` is matched as a character, not treated as a UTC marker;
without an explicit `TZ = UTC`, the local search-head timezone was applied to a
string that is actually UTC. An eyeball spot-check of one event looked
plausible and missed this; an SPL query comparing `_time` against a
UTC-forced `strptime` of the raw string caught it across all 73,512 events.
Full account in `splunk_app/local/props.conf`'s comments and
`evidence/02_timestamp_verification.txt`.

## Cross-project result: do the existing 6 detections fire here?

1 of 6 fires as a genuine true positive when run unmodified against this data.
Full account, including a real backslash-escaping mismatch between this
project's XML-sourced fields and `splunk-detection-lab`'s JSON-sourced fields,
in `evidence/08_existing_detections_cross_check.txt` and
`reports/IR_REPORT.md`.
