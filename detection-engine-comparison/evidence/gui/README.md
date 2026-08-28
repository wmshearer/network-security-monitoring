# GUI / real-window evidence

All images captured from real running applications on this machine's own X
display, never mocked up. Terminal captures use
`wshearer-site/tools/termcap.sh` (photographs a real qterminal window, not
a rendered fake). No credentials, passwords, or hashes are visible in any
image.

| Image | What it shows |
|---|---|
| `01-sigma-base-vs-correlation-compile.png` | Real `sigma convert` output, wide terminal: the base rule compiles to a row-returning `SELECT *`; the correlation rule (same directory, base + correlation file together) compiles to a `GROUP BY ... HAVING` aggregate. |
| `02-zircolite-correlation-aggregate-result.png` | Real Zircolite run against a 12-event synthetic fixture (see `evidence/13_zircolite_correlation_synthetic_fixture_note.txt` for why it is synthetic and what it is/is not used to claim). Shows `Converted 1 rules` (the base rule was folded into the correlation, not run separately) and `Events: 12` processed but `1 events across 1 rules` matched: the one match is the aggregate row, not any of the 12 underlying ticket requests. |
| `03-zircolite-xml-truncation-bug.png` | Real Zircolite run against the actual corpus file `unusual_number_of_kerberos_service_tickets_requested/windows-xml.log` (170.3 KB, 159 real events) using native `-x/--xml-input` mode: reports `Total events processed: 1 (0 filtered out)` with no warning, silently dropping 158 of 159 events. See `evidence/10_zircolite_xml_truncation_repro.txt` for the root cause. |
| `04-yara-false-positive.png` | Real YARA run against a real, unmodified event extracted from `rubeus/windows-security.log`: EventCode=4688 (process creation of the Splunk Universal Forwarder's own `splunk-netmon.exe`, unrelated to Kerberos) is flagged by the substring-only rule because `New Process ID: 0x177c` contains the literal text `0x17`. |
| `05-splunk-web-login-blocked.png` | Real headless-Chromium screenshot of `http://localhost:8000/`, the actual running Splunk Enterprise instance's login page (visible copyright footer confirms it is genuinely live and licensed). This documents the actual blocker: Splunk authentication was unavailable in this session (`SPLUNK_PASS` unset, no stored credential; see `evidence/05_splunk_auth_attempt.txt`), so no stateless-vs-threshold or field-mapping screenshot from inside Splunk Web could be produced. This image is the evidence FOR that limitation, not a substitute for the blocked screenshots. |
| `06_engine_capability_chart.png` | matplotlib chart generated from `evidence/*` result files (never hand-typed) summarizing what each engine expressed natively, by workaround, or not at all. See the chart's own generating script, `scripts/05_generate_capability_chart.py`. |

## What was NOT captured, and why

Splunk Web screenshots of the stateless-vs-threshold contrast and the
live field-mapping zero-match were the single most valuable pieces of
evidence requested for this project and could not be produced: Splunk
authentication was never available in any session that worked on this
project (`SPLUNK_PASS` was never set; the previous stored password was
found leaked in five files across three repos and intentionally burned, see
`memory/splunk-lab-local-credential.md`). No credential guessing or
brute-forcing was attempted, consistent with this environment's global
rules. `evidence/05_splunk_auth_attempt.txt` and
`evidence/17_field_mapping_silent_mismatch.txt` record what was confirmed
statically instead (pipeline source code, the corpus's own published
macro and test-fixture metadata) and exactly what a live run would still
need to confirm.
