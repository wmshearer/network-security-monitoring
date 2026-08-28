# FINDINGS

Every number below is traced to a named evidence file under `evidence/`.
Nothing here was typed from memory or estimated; each figure was
recomputed from the saved raw output cited next to it. Where a claim was
NOT confirmed by a live run (Splunk), that is stated explicitly rather than
implied.

Technique: **T1558.003, "Steal or Forge Kerberos Tickets: Kerberoasting"**,
confirmed directly from https://attack.mitre.org/techniques/T1558/003/
(page title fetched 2026-08-27: "Steal or Forge Kerberos Tickets:
Kerberoasting, Sub-technique T1558.003 - Enterprise | MITRE ATT&CK").

## 1. The corpus's own field values do not match the reference detection's filter

The reference published Splunk detection
(`_corpora/security_content/detections/endpoint/kerberoasting_spn_request_with_rc4_encryption.yml`)
filters `TicketOptions` to one of `0x40810000`, `0x40800000`, `0x40810010`.

The single-event log
(`kerberoasting_spn_request_with_rc4_encryption/windows-xml.log`, 1 event)
has `TicketOptions=0x40810000` -- matches.

The volumetric log
(`unusual_number_of_kerberos_service_tickets_requested/windows-xml.log`, 159
events) has `TicketOptions=0x60810010` on **all 159 events**, a fourth value
the reference filter never lists. Recomputed directly:

```
grep -oP "Name='TicketOptions'>\K[^<]+" .../windows-xml.log | sort | uniq -c
    159 0x60810010
```

See `tests/test_corpus_ground_truth.py::test_volumetric_log_ticket_options_does_not_match_reference_detection_filter`.

Consequence: **the base rule fires zero times on the volumetric log**, not
because the volumetric case is inherently hard to express, but because this
specific dataset's field values don't match the filter this project's base
rule (adapted from the published detection) uses. Confirmed with Zircolite:
`evidence/11_zircolite_base_only_on_jsonl.txt` shows `Total events
processed: 159 ... Detections: None`.

This also means: the `ServiceName` values in this dataset are all
`krbtgt`-family variants (`krbtgt`, `krbtgt1`...`krbtgt8`, `kr1btgt`, etc,
30 unique values), not real SPN-bearing service accounts, and
`TargetUserName` is one of two machine accounts
(`AR-WIN-2$@ATTACKRANGE.LOCAL`: 111 events, `AR-WIN-DC$@ATTACKRANGE.LOCAL`:
48 events) rather than a human user. This looks more like a TGT-renewal /
service-ticket-sweep synthetic test dataset than a textbook SPN-targeted
kerberoasting run. This is reported as observed, not asserted as the
dataset's intended design (that intent was not independently confirmed).

## 2. A bare Sigma rule cannot express the volumetric case; correlation is a separate rule type

Compiling `rules/sigma/kerberoasting_rc4_base.yml` alone
(`evidence/06_sigma_base_rule_sqlite.txt`):

```
SELECT * FROM <TABLE_NAME> WHERE (EventID=4769 AND TicketEncryptionType='0x17'
  AND (TicketOptions='0x40810000' OR TicketOptions='0x40800000' OR TicketOptions='0x40810010'))
  AND (NOT ServiceName LIKE '%$' ESCAPE '\')
```

A plain `SELECT *`: row-returning, one output row per matching event.

Compiling the SAME base rule together with a second file,
`kerberoasting_rc4_volumetric_correlation.yml` (an `event_count`
correlation, `group-by: TargetUserName`, `timespan: 5m`, `condition: {gte:
10}`), from `rules/sigma/` as a directory
(`evidence/07_sigma_correlation_sqlite.txt`):

```
SELECT TargetUserName, COUNT(*) AS event_count FROM (
  SELECT * FROM logs WHERE (EventID=4769 AND TicketEncryptionType='0x17'
    AND (TicketOptions='0x40810000' OR TicketOptions='0x40800000' OR TicketOptions='0x40810010'))
    AND (NOT ServiceName LIKE '%$' ESCAPE '\')
) AS subquery GROUP BY TargetUserName HAVING event_count >= 10
```

This is a `GROUP BY ... HAVING` aggregate: it returns `(TargetUserName,
event_count)` rows, not matching events. Confirmed identically for the
Splunk backend (`evidence/08_sigma_correlation_splunk.txt`):

```
source="WinEventLog:Security" EventCode=4769 TicketEncryptionType="0x17"
  TicketOptions IN (...) NOT ServiceName="*$"
| bin _time span=5m
| stats count as event_count by _time TargetUserName
| search event_count >= 10
```

This confirms, live and by direct compilation (not by reading the spec
alone), the primary-source claim in
https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md
and https://sigmahq.io/docs/meta/correlations.html: correlation is a
SEPARATE Sigma rule type layered on a base rule by `rules:` reference, not
a capability of a plain detection rule. A pipeline built to consume
row-returning event matches from a base rule receives a structurally
different shape (an aggregate count row) the moment a correlation is
introduced, with no schema-level warning that the shape changed.

## 3. Zircolite: what it actually does with a correlation rule (headline result)

**Zircolite DOES evaluate a Sigma correlation rule end to end and returns a
correct aggregate result.** This was not obvious in advance; the honest
possible outcomes were "evaluates it," "errors," or "silently skips it,"
and the answer is the first one, with one important caveat.

Proof (`evidence/13_zircolite_correlation_synthetic_fixture.txt`, and
`evidence/gui/02-zircolite-correlation-aggregate-result.png` for a real
screenshot of the same run): a hand-built, clearly-labelled-as-synthetic
12-event fixture, all one `TargetUserName`, all matching the base rule's
filter. Zircolite reports "Total events processed: 12" and one detection:

```json
{"TargetUserName": "testuser@ATTACKRANGE.LOCAL", "event_count": 12}
```

**The caveat, and the real finding**: pointing Zircolite at the directory
containing BOTH `kerberoasting_rc4_base.yml` and
`kerberoasting_rc4_volumetric_correlation.yml` produces the log line
`Converted 1 rules` / `1 rules loaded` -- not 2. Inspecting the saved
ruleset JSON (Zircolite's own `ruleset-rules-sigma-*.json` written at run
time) shows only the correlation rule survives as a compiled artifact; the
base rule's filter is folded into the correlation's own SQL subquery at
pySigma's compile stage, and the base rule never separately runs as its own
row-returning rule alongside the correlation. This is pySigma's compilation
behavior (confirmed identically whether Zircolite or `sigma-cli` directly
compiles the two-file directory: both say "Converted 1 rules" / one query),
not a Zircolite-specific bug, but Zircolite is the tool that actually
executes it and its own summary line ("1 rules loaded") is easy to read as
"both my rules ran" when only one compiled artifact exists.

**Running the base+correlation pair against the real 159-event volumetric
corpus produces zero detections**
(`evidence/12_zircolite_correlation_on_jsonl.txt`). This is the CORRECT
answer for this data (see finding 1: `TicketOptions` never matches the
filter), not a second bug. It is called out explicitly so it is not
mistaken for a failure of the correlation mechanism itself, which the
finding above (the synthetic fixture) proves works.

## 4. Zircolite's native XML reader silently truncates this corpus's actual file format (second headline result)

Independent of the correlation question: pointing Zircolite's native
`-x/--xml-input` mode directly at
`unusual_number_of_kerberos_service_tickets_requested/windows-xml.log`
(170.3 KB, 159 real events, confirmed by `grep -c "." file` = 159) produces:

```
[+] Total events processed: 1
[+] Executing ruleset ...
Detections: None
```

No warning, no error. `evidence/10_zircolite_xml_truncation_repro.txt` and
`evidence/gui/03-zircolite-xml-truncation-bug.png` (real screenshot). Root
cause, confirmed by reading Zircolite's own source
(`zircolite/streaming.py`, `stream_xml_events`) and reproducing outside
Zircolite entirely with a bare `lxml.etree.iterparse` call: this corpus's
`windows-xml.log` files are one complete `<Event>...</Event>` XML document
PER LINE with no wrapping root element across the whole file (verified:
each of the 159 lines independently parses as a standalone well-formed XML
document). `lxml.etree.iterparse(..., recover=True)` treats the whole file
as ONE XML document stream; after the first top-level `</Event>` closes, it
has nothing further to parse as a sibling top-level element without a
wrapping root tag (e.g. `<Events>...</Events>`), so it silently stops.
Zircolite has a "No `<Event>` documents found" warning path but it only
triggers when ZERO events are seen, not when the count is implausibly low
for the file size.

**This means: running Zircolite's own documented XML input mode against
this corpus's actual on-disk file format produces a confident, clean,
zero-error, wrong answer that looks exactly like "no correlation fired,"
when the real cause is "158 of 159 events were never read."** This project
worked around it (`scripts/02_convert_xml_to_jsonl.py`, converts to
Zircolite's `--json-input` format, which correctly processes all 159
events, confirmed in `evidence/11_zircolite_base_only_on_jsonl.txt`) but
did not patch Zircolite itself, per the project's scope (no sibling/vendor
tool is modified).

## 5. YARA cannot bind a match to a field, and this produces a real false positive

`rules/yara/kerberoasting_rc4_stringmatch.yar` is the closest possible YARA
expression of the base rule. YARA has no event model at all: no
timestamped stream, no schema, no typed field comparison, only byte/text
pattern matching over whatever blob it is given.

True positive (`evidence/14_yara_true_positive.txt`): both rules in the
file correctly match the real single-event kerberoasting log.

False positive (`evidence/14_yara_false_positive.txt`,
`evidence/15_yara_false_positive_run.txt`,
`evidence/gui/04-yara-false-positive.png`): scanning
`rubeus/windows-security.log`, split into 458 individual per-event files
(`scripts/03_run_yara_per_event.sh`), the intentionally weak substring-only
rule (`Kerberoasting_RC4_Encryption_Type_Substring_Only`, condition: the
bare text `0x17` present anywhere) matched **9 events** the anchored rule
correctly rejected. Rechecking each by its own `EventCode` field:

- 8 of 9 are genuinely unrelated: EventCode 4688 (process creation) or 4689
  (process termination) events whose Process ID or Creator Process ID
  happens to start with the hex digits `17` right after `0x`
  (`0x177c`, `0x1738`, `0x1704`, `0x17a0`). One concrete example: an event
  containing `New Process ID: 0x177c`, `New Process Name:
  C:\Program Files\SplunkUniversalForwarder\bin\splunk-netmon.exe` -- the
  Splunk Universal Forwarder's own monitoring process, nothing to do with
  Kerberos, RC4, or ticket requests. YARA cannot tell "0x17 inside a
  Process ID field" from "0x17 as the value of the TicketEncryptionType
  field"; it only sees "the substring 0x17 occurred somewhere in this
  text," which is true in both cases.
- 1 of 9 (event_00344) is a real EventCode 4768 (AS-REQ / TGT request, not
  TGS/service-ticket request) whose own `Ticket Encryption Type` field
  genuinely equals `0x17`. This is correctly excluded from the false-
  positive count: it is real RC4 use, just for a TGT, which is outside
  this project's kerberoasting (TGS-specific) definition, so the anchored
  rule's rejection of it is the CORRECT behavior, not a gap.

Corrected false-positive count: **8 of 458 events in this one file**,
recomputed with a field-by-field check
(`evidence/14_yara_false_positive.txt`'s "Correction" section), not the
initial uncorrected 9.

## 6. Silent field-mapping mismatch: pySigma's Splunk pipeline vs this corpus's own stated convention (static finding, not live-confirmed)

pySigma's `splunk_windows` pipeline (`sigma/pipelines/splunk/splunk.py`,
`pysigma-backend-splunk` 2.1.0, source saved at
`evidence/04_pysigma_splunk_pipeline_source.py`) hardcodes:

```python
generate_windows_logsource_items("source", "WinEventLog:{source}")
```

Compiling `rules/sigma/kerberoasting_rc4_base.yml` with `-p
splunk_windows` (`evidence/02_sigma_convert_splunk.txt`) always emits
`source="WinEventLog:Security"`, never any other spelling.

The published reference detection this rule is adapted from uses a macro,
`wineventlog_security`
(`_corpora/security_content/macros/wineventlog_security.yml`), whose
definition ORs four conventions:

```
eventtype="wineventlog_security" OR Channel="security"
  OR source="XmlWinEventLog:Security" OR source="WinEventLog:Security"
```

This corpus's own published test fixture for that exact detection
(`_corpora/security_content/detections/endpoint/kerberoasting_spn_request_with_rc4_encryption.yml`,
`tests:` block) states its data would be ingested as
`source: XmlWinEventLog:Security`, `sourcetype: XmlWinEventLog` -- the
convention the pySigma-compiled query does not match.

**What this means, stated precisely**: if this corpus's data were ingested
into Splunk following the corpus's own documented convention, the
pySigma-compiled query's `source="WinEventLog:Security"` clause would not
match any of it, while the macro-based reference query would. Both queries
read as equally plausible SPL text; only one would return anything against
this data, and the other would silently return zero matches, structurally
indistinguishable from "no kerberoasting activity" from the query text
alone.

**What this finding is NOT**: it was not confirmed by a live Splunk
search. Splunk authentication was unavailable in every session that worked
on this project (`SPLUNK_PASS` unset, no stored credential; the previous
credential was found leaked in five files across three repos and
intentionally burned -- see `memory/splunk-lab-local-credential.md`). No
credential guessing or brute-forcing was attempted. `evidence/05_splunk_auth_attempt.txt`
records the two auth attempts made (both refused) and the conclusion. The
finding above is confirmed from pipeline source code and the corpus's own
published metadata, which does not require a live connection, but the
live hit-count comparison itself is explicitly unconfirmed and left as a
next step if Splunk access ever becomes available.

Zircolite could not be used to reproduce this same mechanism: the `source`
field this bug depends on is Splunk ingestion metadata, not part of the
raw Windows event itself, so it does not exist in the JSONL Zircolite
consumes. That gap is stated rather than papered over with a fabricated
Zircolite repro.

## 7. Absence-of-event / negation: demonstrated impossible for the Sigma correlation mechanism, not found stated in a primary source

The task's own research pass had not found a SigmaHQ source stating this
limitation explicitly. This project checked the correlation specification
directly
(https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md)
and confirms: `lt` (count must be lesser than the given value) IS a
documented, valid condition operator, with no stated caveat about being
unable to match empty groups. **So this section is a demonstrated
argument from the rule model, not a citation of a stated limitation.**

Compiling an `event_count` correlation with `condition: {lt: 1}`
(`rules/sigma_negation_test/`, `evidence/18_negation_sqlite_compile.txt`)
succeeds without error or warning:

```
SELECT TargetUserName, COUNT(*) AS event_count FROM (
  SELECT * FROM logs WHERE EventID=4769 AND TicketEncryptionType='0x17'
) AS subquery GROUP BY TargetUserName HAVING event_count < 1
```

Running that EXACT compiled SQL against a real, live in-memory SQLite
database (`scripts/04_prove_correlation_cannot_express_absence.py`), seeded
with a principal ("bob") who has a real event that does NOT qualify (0
qualifying RC4 requests, exactly the case an absence rule should catch),
returns **zero rows**. Confirmed live, not simulated:

```
Rows returned by the compiled 'absence' query: []
```

This is not a bug in this particular query; it is a structural fact about
SQL `GROUP BY`: a group with no rows in the filtered subquery is never
materialized, so `HAVING event_count < 1` is unsatisfiable by construction,
for any input data. A Sigma correlation rule can never express "this
principal made zero qualifying requests," only "this principal made fewer
than N qualifying requests, among principals who made at least one."

By contrast, `rules/spl/kerberoasting_rc4_absence_of_event.spl` shows the
SPL-side construct that has no Sigma-correlation equivalent: `stats` can
enumerate a wider universe of principals (from a broader search) and then
filter to `count=0`, expressing absence directly. This SPL query was
**not executed live** (same Splunk auth blocker as finding 6); it is
presented as the structural contrast, not an executed result.

## 8. Suricata: scoped out

No Kerberos TGS-REQ/AS-REQ pcap for T1558.003 exists on disk in this
environment. The one Kerberoast-labelled pcap
(`rubeus-kerberoast-cmdline-parameter.pcap`) was already found by
`ad-attack-analysis` to be mislabelled LDAP-only traffic with zero Kerberos
frames and discarded
(`/home/kali/director/projects/ad-attack-analysis/data/captures/README.md`).
No capture was invented to fill this gap; Suricata is excluded from this
project's comparison for this stated reason.

## 9. Licences

- `attack_data`: Apache License, Version 2.0 (`_corpora/attack_data/LICENSE`, verified on disk).
- `security_content`: Apache License, Version 2.0 (`_corpora/security_content/LICENSE`, verified on disk).

## What was NOT done, stated plainly

- No SPL query in this project was ever executed against live Splunk data.
  Splunk authentication was unavailable throughout
  (`evidence/05_splunk_auth_attempt.txt`). All SPL claims are either
  compiled-text claims (from `sigma-cli`) or static source/metadata
  claims, never observed search-job results.
- The field-mapping mismatch (finding 6) and the SPL negation query
  (finding 7) are therefore confirmed only up to what pipeline source code
  and corpus metadata can show; the live hit-count comparison is an
  explicitly open next step.
- No attack traffic was ever generated. All analysis used pre-existing
  captured data already on disk under `_corpora/attack_data`.
- Suricata and any live-network technique variant are out of scope (see
  finding 8).
