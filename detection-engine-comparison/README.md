# Detection engine comparison: T1558.003 Kerberoasting

**One technique, five ways to try to detect it, and a catalog of what each
engine cannot say, or says wrong without telling you.**

Technique under test: **T1558.003, "Steal or Forge Kerberos Tickets:
Kerberoasting"** (confirmed at https://attack.mitre.org/techniques/T1558/003/).
An attacker with any valid domain account can request a Kerberos service
ticket (TGS) for any account with a Service Principal Name, then crack the
ticket's encrypted portion offline. Detection usually looks for the
ticket's encryption type (RC4, a weaker cipher many tools request on
purpose) and/or an unusual volume of ticket requests from one account.

## Headline findings (read this first)

1. **A bare Sigma rule cannot express "N ticket requests in T minutes."**
   Correlation is a separate Sigma rule TYPE layered on a base rule, and it
   compiles to an aggregate query (`GROUP BY ... HAVING`) that returns
   counts, not matching events. Confirmed by direct compilation with
   `sigma-cli`, not just by reading the spec. See FINDINGS.md #2.

2. **Zircolite silently loads a base+correlation rule pair as ONE rule**,
   folding the base rule into the correlation's own SQL at compile time.
   It DOES evaluate the correlation correctly end to end (proven with a
   synthetic fixture) -- but two files in, one compiled rule out, with no
   warning that the base rule never runs separately. See FINDINGS.md #3.

3. **Zircolite's own native XML reader silently processes 1 of 159 real
   events** from this corpus's actual on-disk file format (one `<Event>`
   per line, no wrapping root element), reporting a clean, zero-error,
   wrong success. See FINDINGS.md #4 and `evidence/gui/03-zircolite-xml-truncation-bug.png`.

4. **YARA produced a real false positive**: an unrelated Windows process-
   creation event (the Splunk Universal Forwarder's own monitoring
   process) was flagged as a kerberoasting event because its Process ID,
   `0x177c`, contains the substring `0x17` that a weak YARA rule was
   looking for. YARA cannot bind a string match to a specific field. See
   FINDINGS.md #5 and `evidence/gui/04-yara-false-positive.png`.

5. **A silent field-mapping mismatch was found (confirmed statically, not
   live)**: pySigma's Splunk pipeline hardcodes `source="WinEventLog:Security"`;
   this corpus's own published test metadata says its data is
   `source=XmlWinEventLog:Security`. One spelling would return zero
   matches on data the other spelling catches, and a zero-match result is
   indistinguishable from a true negative. Splunk authentication was
   unavailable to confirm this live; see "What could not be done" below.
   FINDINGS.md #6.

6. **Absence-of-event is structurally impossible for a Sigma correlation
   rule**, proven by compiling `condition: {lt: 1}` and running the exact
   resulting SQL live against a case it should catch: it returns zero
   rows, because SQL `GROUP BY` never emits a row for an empty group. No
   SigmaHQ source states this explicitly; it is demonstrated here from the
   rule model, not cited. FINDINGS.md #7.

## What each engine is, in this project

| Engine | Role here |
|---|---|
| **Sigma (pySigma 1.5.0 / sigma-cli 3.1.0)** | A compiler. Turns a rule into a query string for a target backend. Cannot itself evaluate a rule against data. |
| **Zircolite** | An evaluator. Loads events into SQLite and runs Sigma-compiled queries as real SELECTs. |
| **Splunk / SPL** | Compiled and hand-authored only in this project. Splunk Enterprise is installed and running locally, but authentication was unavailable (see below), so no SPL query here was ever executed against live data. |
| **YARA 4.5.8** | A byte/string pattern matcher with no event model. Used here by flattening one event to text and matching substrings. |
| **Suricata 8.0.6** | Installed but out of scope: no Kerberos TGS-REQ/AS-REQ pcap for T1558.003 exists on disk (the one candidate pcap was already found mislabelled LDAP-only traffic by a sibling project and discarded). No traffic was generated to fill this gap. |

## Per-engine capability table

Status legend: **native** = expressed directly, no workaround. **workaround**
= expressed, but only by stepping outside the plain rule. **SILENT WRONG**
= produced a different result than expected, with no error to flag it.
**impossible** = cannot be expressed in this engine at all.

| Capability | Sigma (compiled) | Zircolite (evaluator) | SPL (compiled, not executed) | YARA |
|---|---|---|---|---|
| Single-event field match (`TicketEncryptionType=0x17`) | native | native | native | workaround (substring proxy for a field) |
| N ticket requests per principal in T minutes | workaround (separate correlation rule type; aggregate output) | workaround (evaluates the aggregate correctly, but silently drops the base rule as a separate artifact) | native (`stats`/`eventstats` in one search; published reference even does a 3-sigma anomaly calc) | impossible (no event stream, no grouping, no time window) |
| Field-bound comparison (not text-blob substring) | native | native | native | impossible (demonstrated false positive: `0x177c` matched as `0x17`) |
| Absence of a qualifying event for one principal | impossible (proven: compiled `HAVING event_count < 1` can never match) | impossible (inherits the same unsatisfiable SQL) | workaround (`stats` can enumerate a wider universe and filter to `count=0`; not executed live) | impossible (no "count of matches is zero" construct; a zero-hit scan is indistinguishable from a scan that never ran) |
| **Worst silent-wrong result found** | n/a (a compiler, cannot itself return a wrong live result) | **XML truncation: reports "159 events" file as "1 event processed," zero errors** | **Field-mapping mismatch: one source-string spelling silently returns 0 matches where another returns hits (confirmed from pipeline source + corpus metadata, not live)** | **False positive: unrelated process-creation event flagged as a kerberoasting hit** |

See `evidence/gui/06_engine_capability_chart.png` for the same table as a
generated chart (built from `evidence/19_capability_matrix_source.json`,
which cites every cell's evidence file).

## What could not be done, stated plainly

**Splunk authentication was never available in this project.** The local
Splunk Enterprise instance (`http://localhost:8000`, licensed through
2029-10-15) is genuinely running -- confirmed with a real screenshot,
`evidence/gui/05-splunk-web-login-blocked.png` -- but its current admin
password is intentionally not stored anywhere (the previous one was found
leaked in five files across three repos and was intentionally burned; see
`memory/splunk-lab-local-credential.md`). No credential guessing or
brute-forcing was attempted. This means:

- No SPL query in this project was ever run against real Splunk data.
  Every SPL claim here is either a `sigma-cli`-compiled query string or a
  hand-authored query taken from the published reference detection,
  never an observed search-job result.
- The most requested piece of evidence for this project -- a screenshot of
  the stateless-vs-threshold contrast inside Splunk Web, and a screenshot
  of the field-mapping mismatch actually returning different hit counts --
  could not be produced. `evidence/17_field_mapping_silent_mismatch.txt`
  records exactly what was confirmed statically instead (pipeline source
  code, the corpus's own published macro and test-fixture metadata) and
  what a live run would still need to confirm.
- No attack traffic was generated to work around this or any other gap.
  All analysis in this project used pre-existing captured data already on
  disk under `_corpora/attack_data` (Apache-2.0 licensed) and
  `_corpora/security_content` (Apache-2.0 licensed).

## Layout

```
rules/
  sigma/                          base rule + volumetric correlation rule
  sigma_base_only/                base rule alone (used by tests/scripts to isolate its behavior)
  sigma_negation_test/            base rule + a {lt: 1} "absence" correlation, for FINDINGS.md #7
  spl/                            pySigma-compiled SPL, hand-authored reference SPL, absence-of-event SPL
  yara/                           the closest possible YARA expression, plus one weaker variant kept only for the false-positive demonstration
scripts/
  02_convert_xml_to_jsonl.py      works around Zircolite's XML-input truncation (FINDINGS.md #4)
  03_run_yara_per_event.sh        splits a multi-event text log so YARA matches can't blur across events
  04_prove_correlation_cannot_express_absence.py   live SQLite proof for FINDINGS.md #7
  05_generate_capability_chart.py generates evidence/gui/06_engine_capability_chart.png from real evidence
evidence/
  01-19_*.txt / *.json            raw command output, one file per run, never hand-edited
  gui/                            real screenshots: qterminal captures + one real Splunk Web + one generated chart
tests/
  pytest suite pinning every claim above; SKIPs (not fails) when Splunk auth or a corpus file is absent
```

## Running it

```
# Sigma compilation (needs detection-as-code's venv, already built)
/home/kali/director/projects/detection-as-code/.venv/bin/sigma convert -t sqlite -p sysmon rules/sigma/

# Zircolite evaluation (same venv; Zircolite is vendored there, not pip-installed)
/home/kali/director/projects/detection-as-code/.venv/bin/python \
  /home/kali/director/projects/detection-as-code/vendor/Zircolite/zircolite.py \
  -e data/volumetric.jsonl -j -r rules/sigma/ -o /tmp/out.json

# YARA
yara -s rules/yara/kerberoasting_rc4_stringmatch.yar <event file>

# Tests (system python3 has everything needed: lxml, yaml, yara-python)
python3 -m pytest tests/ -v
```

## Effort notes

No single step in this project ran longer than a few minutes; nothing was
capped. The Splunk-auth attempt was stopped after two refused attempts
(see `evidence/05_splunk_auth_attempt.txt`) rather than escalated into
guessing, per this environment's standing rule against credential
brute-forcing.
