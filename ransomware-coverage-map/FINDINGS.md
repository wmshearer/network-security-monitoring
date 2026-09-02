# Findings

Every number below is re-derivable from a named file in `evidence/` or
`matrix/`, produced by a numbered script in `scripts/`. None was hand-typed
into this document; where a number appears here it was copied out of a
script's own printed output or a JSON file after the fact. `tests/` pins the
highest-stakes numbers so a later change cannot silently drift this document
out of sync with the code.

Glossary, defined once here: **capture** means one family's raw, already-
public `.log` file(s) under `attack_data/datasets/malware/<family>/`, each a
sequence of Windows Sysmon/Security/PowerShell event-log entries recorded
while that family's real sample ran inside an isolated "attack range" lab
(these files pre-date this project; nothing here executed anything).
**Detection** means a Splunk `security_content` YAML file under
`detections/endpoint/`, each one SPL (Splunk's own query language, not
regex) intended to fire when a specific behaviour appears in ingested log
data. **Literal** means an exact string (a process name, a command-line
fragment, a registry path) written into a detection's own SPL, as opposed to
a paraphrase of what the detection is "about".

## 1. The anchor finding: shadow-copy deletion (T1490) is absent from three of seven captures

Command run, reproduced verbatim in
[`evidence/gui/t1490_anchor_finding.png`](evidence/gui/t1490_anchor_finding.png)
(a real terminal window, not a styled HTML page):

```
grep -rliE "vssadmin|wbadmin|bcdedit|shadowcopy" <family_dir>
```

| Family | Files with T1490 evidence |
|---|---|
| conti | 0 |
| ryuk | 0 |
| lockbit_ransomware | 0 |
| revil | 1 |
| prestige_ransomware | 1 |
| chaos_ransomware | 2 |
| ransomware_ttp | 5 |

This table was handed to this project as an already-verified finding and is
re-derived here two independent ways: directly by grep (screenshot above,
and pinned by `tests/test_findings.py::test_t1490_anchor_finding_file_counts`,
which shells out to `grep` itself, not to any script in this repo) and by
this project's own pipeline
([`evidence/01_capture_grep/*__T1490.txt`](evidence/01_capture_grep/), one
file per family, each listing every matched line with its source file and
line number). Both agree.

**Why this shapes the whole project:** shadow-copy deletion is the single
most famous ransomware behaviour there is (it is why victims cannot restore
from Windows' built-in Volume Shadow Copy backups). A coverage map that
does not distinguish "this behaviour never happened in this capture" from
"this behaviour happened and nothing caught it" would paint the same red
cell for conti/ryuk/lockbit as for a real detection failure, and a reader
would reasonably conclude "our detections miss shadow-copy deletion for
LockBit." That would be **confidently wrong**, LockBit's capture never
exercises this behaviour at all, so no claim about detecting it is possible
from this evidence. This is why every cell in this project's matrix is one
of four states, not two (see `README.md`, "Cell taxonomy"), and why the
conti/ryuk/lockbit T1490 cells are GREY, not red, in
[`matrix/coverage_matrix.png`](matrix/coverage_matrix.png).

## 2. A false positive found and fixed during pattern development

An early draft of the T1490 grep pattern added `"shadow copy"` (with a
space) to the four terms above. That pattern matched conti's `inf1` capture
on the line at `windows-sysmon.log:2335`, a Sysmon EventID 1
(ProcessCreate) event whose `Description` field reads "Microsoft (R)
Volume Shadow Copy Service", `VSSVC.exe`, the normal Windows backup
service, starting up on its own, which happens on billions of unremarkable
Windows boots and has nothing to do with an attacker. Reported in full in
[`manifest/technique_manifest.json`](manifest/technique_manifest.json)
under `T1490`'s `note` field. The pattern was reverted to the exact
4-term grep in section 1 specifically to avoid this class of error. Two
further false positives of the same general shape (a benign artifact
containing a technique-suggestive string) are documented in section 5.

## 3. Every candidate row's technique ID, verified at attack.mitre.org

Checked individually by web search against `attack.mitre.org` on
2026-08-28. All ten technique IDs used as matrix rows were confirmed
correct as given; none needed correction:

| ID | Name (as given) | Verified name at attack.mitre.org | Status |
|---|---|---|---|
| T1486 | Data Encrypted for Impact | Data Encrypted for Impact | correct |
| T1490 | Inhibit System Recovery | Inhibit System Recovery | correct |
| T1489 | Service Stop | Service Stop | correct |
| T1491 | Defacement | Defacement | correct |
| T1491.001 | Internal Defacement | Defacement: Internal Defacement | correct |
| T1112 | Modify Registry | Modify Registry | correct |
| T1562 | Impair Defenses | Impair Defenses | correct |
| T1562.001 | Disable or Modify Tools | Impair Defenses: Disable or Modify Tools | correct |
| T1562.002 | Disable Windows Event Logging | Impair Defenses: Disable Windows Event Logging | correct |
| T1562.003 | Impair Command History Logging | Impair Defenses: Impair Command History Logging | correct |

No ID or name required correction. This differs from the brief's
expectation that the prior research pass's IDs be checked "because it did
not do this", checking them here found them already right; the value of
the check was confirming that, not finding an error.

## 4. security_content ships zero detections for T1562.003 across the entire corpus

```
grep -rl "T1562.003" security_content/detections/endpoint/*.yml
```
returns nothing. Pinned by
`tests/test_findings.py::test_t1562_003_has_zero_detections_in_security_content`,
which runs that exact grep independently of this project's own detection
index. This means the T1562.003 row is RED-TELEMETRY or GREY for every
family by construction, there is no detection anywhere in
security_content that could ever have fired, regardless of what any
capture contains. See `manifest/technique_manifest.json`'s note on
`T1562.003` for why the row is kept anyway: to make this absence visible
rather than quietly dropping the row.

## 5. Two more literal-extraction bugs found and fixed while building stage 3

Stage 3 ([`scripts/03_score_detection_logic.py`](scripts/03_score_detection_logic.py))
extracts literal strings out of each candidate detection's SPL and greps
them against the same raw captures stage 1 used, to distinguish GREEN
("this detection's own logic is present in the capture") from RED-LOGIC
("a detection exists for this family+technique, but its own terms never
occur here"). Two bugs in that extraction were caught by manually inspecting
extracted literals against raw log content before trusting any RED-LOGIC
verdict, per the instruction to never let a parsing defect default to a
real-looking answer:

- Escaped-quote truncation. `windows_security_account_manager_stopped.yml`'s
  SPL contains `Processes.process="*stop \"samss\"*"`. A naive
  quoted-string regex stopped at the first literal `"`, truncating the
  extracted literal to `stop \` (a backslash and nothing else useful),
  which correctly found no match in ryuk's capture even though the real
  literal `stop "samss"` does occur there (`ryuk/windows-sysmon.log:1843`,
  verified by direct `grep -F 'stop "samss"'`). This would have reported a
  real GREEN as a false RED-LOGIC. Fixed by making the quoted-value pattern
  escape-aware (`unescape_spl_string` in stage 3).
- Un-unescaped backslash-escaping. `ryuk_test_files_detected.yml`'s SPL
  contains `"Filesystem.file_path"=C:\\*Ryuk*`, SPL's own `\\` means one
  literal backslash. Passing the two literal backslash characters through
  unescaped produced a literal that never matches ryuk's raw Sysmon paths,
  which use one backslash per separator (confirmed:
  `grep -o ".\{5\}Ryuk.\{5\}"` on the raw file returns `rams\RyukReadM`,
  one backslash). Same fix (`unescape_spl_string`) resolves this.
- Wildcard treated as a literal character. After fixing the two bugs
  above, `ryuk|T1486`'s extracted literal was `C:\*Ryuk`, the interior `*`
  is an SPL wildcard ("any characters"), not a literal asterisk, meaning
  "a path starting with C: and containing Ryuk somewhere later"
  (`ProgramData\...\RyukReadMe.html` matches; a literal asterisk never
  occurs in a real path). Fixing this (translating interior `*` to a real
  regex wildcard in `grep_literal` rather than fixed-string search) flipped
  `ryuk|T1486` from RED-LOGIC to its correct value, GREEN.

Every one of these three bugs, if left in, would have under-counted GREEN
and over-counted RED-LOGIC, the direction of error that makes a detection
program look worse than it is, which is exactly the kind of error worth
catching before publishing rather than after.

## 6. An interpretive limitation that stood between two candidate RED-LOGIC cells and GREEN, now resolved (see section 13)

`lockbit_ransomware|T1486` and `chaos_ransomware|T1486` were originally
scored RED-LOGIC, both tracing to `ransomware_notes_bulk_creation.yml`'s
SPL: `file_name IN ("*\.txt","*\.html","*\.hta")`. The backslash before the
dot is not one of SPL's two defined escapes (`\"` and `\\`), so read
literally it means the detection only matches a filename containing an
actual backslash character immediately before "txt"/"html"/"hta", which no
real filename has. Both families' captures contain plainly-named `.txt`
ransom notes (lockbit: `cHpfiXA9s.README.txt`, confirmed present in
[`evidence/01_capture_grep/lockbit_ransomware__T1486.txt`](evidence/01_capture_grep/lockbit_ransomware__T1486.txt);
chaos: confirmed in
[`evidence/01_capture_grep/chaos_ransomware__T1486.txt`](evidence/01_capture_grep/chaos_ransomware__T1486.txt)).
Whether Splunk's live search-time wildcard matcher actually enforces that
literal backslash, or silently treats the unrecognized escape as a bare
dot, could not be determined without a live Splunk instance at the time
this section was first written. **This has since been tested directly. See
section 13 for the resolution: the strict reading was wrong, and both
cells are now GREEN.** This section is left in place, unedited except for
this note, so the reasoning that was actually available before the test is
visible alongside what the test found.

## 7. The conti column has no dedicated Splunk analytic_story

```
grep -rl "^name:.*conti" security_content/stories/*.yml    (case-insensitive)
```
returns nothing, there is no "Conti Ransomware" story file, unlike Ryuk,
LockBit, Prestige, Chaos, and REvil, each of which has one. Pinned by
`tests/test_findings.py::test_conti_has_no_dedicated_analytic_story`. One
detection (`conti_common_exec_parameter.yml`) is named after Conti and
tests against Conti-specific captured data, but its own `analytic_story:`
field lists only `Ransomware`, `Compromised Windows Host`, and `Hellcat
Ransomware`, never `Conti Ransomware`, and its `mitre_attack_id` is
`T1204` (User Execution), which is not one of this project's ten rows. This
project's own manifest therefore maps `conti` to `security_content_story:
null`, meaning the conti column can never score GREEN or RED-LOGIC (no
family-tagged detection exists to test): its only non-GREY cell,
`conti|T1486`, is RED-TELEMETRY.

## 8. Splunk built this exact artifact shape for other malware, but never for ransomware

`security_content/deprecated/mitre-map/` contains two subdirectories of
Navigator-format per-family coverage JSON:
`cisa-2021-top-malware-coverage/` (Qakbot, Remcos, AgentTesla, Azorult,
Trickbot) and `rats-stealer-detection-coverage/` (AsyncRAT, DarkCrystal
RAT, Warzone RAT, Amadey, PlugX, NjRAT, DarkGate). Verified by listing that
directory directly
(`find security_content/deprecated/mitre-map -iname "*_sec_content_mitre_coverage.json"`)
and confirming no filename contains a ransomware family name. Pinned by
`tests/test_findings.py::test_deprecated_mitre_map_never_included_a_ransomware_family`.
This directory is also marked `deprecated`, meaning Splunk stopped
maintaining even this narrower artifact (single-family Navigator layers,
not a cross-family matrix) for the malware types it did cover.

## 9. The falsifiable claim: does this project's headline hold? (superseded by section 13; kept for the record)

Stated claim: "Splunk's ransomware detection content, despite naming
specific families in its metadata, does not uniformly cover the same core
technique set across families." This requires at least one real
RED-LOGIC cell (a detection gap, not just an unobserved behaviour).

**This section records the tally as it stood before the live Splunk test
in section 13. It is now superseded. Read section 13 for the corrected
tally and conclusion; this section is preserved unedited (aside from this
note) so the "before" state is traceable.**

Original tally, from
[`matrix/coverage_matrix.json`](matrix/coverage_matrix.json)`["state_counts"]`,
reproduced by `scripts/04_build_matrix.py`:

| State | Count |
|---|---|
| GREEN | 11 |
| RED-LOGIC | 2 |
| RED-TELEMETRY | 5 |
| GREY | 52 |
| Total | 70 |

RED-LOGIC was non-zero (2 cells: `lockbit_ransomware|T1486`,
`chaos_ransomware|T1486`, both discussed with a caveat in section 6).
On this original tally the claim held, narrowly, with the caveat in
section 6 attached: if that caveat resolved in Splunk's favour, RED-LOGIC
would become zero and the honest conclusion would become "this is a
capture-completeness story, not a detection-gap story" for the technique
set actually tested here. That caveat has since been resolved in Splunk's
favour (section 13): RED-LOGIC is now zero, and the claim has failed.

RED-TELEMETRY (5 cells) was, and remains, a separate, unambiguous finding
unaffected by the caveat above: `conti|T1486`, `prestige_ransomware|T1486`,
`prestige_ransomware|T1112`, `revil|T1491.001`,
`ransomware_ttp|T1562.002` are all cases where the behaviour was observed
but Splunk ships no detection tagged to that exact family+technique pair at
all, a tooling gap on Splunk's side, not a logic bug in one rule.

## 10. Full per-cell matrix

Every cell state, one line each, from `matrix/coverage_matrix.json` (family
alphabetical, `ransomware_ttp` last and always labelled a reference
bucket). This reflects the **corrected** matrix, after the section 13
resolution; the only two lines changed from the original run are
`chaos_ransomware|T1486` and `lockbit_ransomware|T1486`, both RED-LOGIC to
GREEN:

```
chaos_ransomware   | T1112       GREY
chaos_ransomware   | T1486       GREEN
chaos_ransomware   | T1489       GREY
chaos_ransomware   | T1490       GREEN
chaos_ransomware   | T1491       GREY
chaos_ransomware   | T1491.001   GREY
chaos_ransomware   | T1562       GREY
chaos_ransomware   | T1562.001   GREY
chaos_ransomware   | T1562.002   GREY
chaos_ransomware   | T1562.003   GREY
conti              | T1112       GREY
conti              | T1486       RED-TELEMETRY
conti              | T1489       GREY
conti              | T1490       GREY
conti              | T1491       GREY
conti              | T1491.001   GREY
conti              | T1562       GREY
conti              | T1562.001   GREY
conti              | T1562.002   GREY
conti              | T1562.003   GREY
lockbit_ransomware | T1112       GREY
lockbit_ransomware | T1486       GREEN
lockbit_ransomware | T1489       GREY
lockbit_ransomware | T1490       GREY
lockbit_ransomware | T1491       GREY
lockbit_ransomware | T1491.001   GREY
lockbit_ransomware | T1562       GREY
lockbit_ransomware | T1562.001   GREY
lockbit_ransomware | T1562.002   GREY
lockbit_ransomware | T1562.003   GREY
prestige_ransomware| T1112       RED-TELEMETRY
prestige_ransomware| T1486       RED-TELEMETRY
prestige_ransomware| T1489       GREEN
prestige_ransomware| T1490       GREEN
prestige_ransomware| T1491       GREY
prestige_ransomware| T1491.001   GREY
prestige_ransomware| T1562       GREY
prestige_ransomware| T1562.001   GREY
prestige_ransomware| T1562.002   GREY
prestige_ransomware| T1562.003   GREY
revil              | T1112       GREY
revil              | T1486       GREY
revil              | T1489       GREY
revil              | T1490       GREEN
revil              | T1491       GREEN
revil              | T1491.001   RED-TELEMETRY
revil              | T1562       GREY
revil              | T1562.001   GREY
revil              | T1562.002   GREY
revil              | T1562.003   GREY
ryuk               | T1112       GREY
ryuk               | T1486       GREEN
ryuk               | T1489       GREEN
ryuk               | T1490       GREY
ryuk               | T1491       GREY
ryuk               | T1491.001   GREY
ryuk               | T1562       GREY
ryuk               | T1562.001   GREY
ryuk               | T1562.002   GREY
ryuk               | T1562.003   GREY
ransomware_ttp (reference bucket, not a family)
ransomware_ttp     | T1112       GREEN
ransomware_ttp     | T1486       GREEN
ransomware_ttp     | T1489       GREEN
ransomware_ttp     | T1490       GREEN
ransomware_ttp     | T1491       GREY
ransomware_ttp     | T1491.001   GREY
ransomware_ttp     | T1562       GREY
ransomware_ttp     | T1562.001   GREY
ransomware_ttp     | T1562.002   RED-TELEMETRY
ransomware_ttp     | T1562.003   GREY
```

## 11. Determinism

`scripts/04_build_matrix.py` was run twice from a clean rebuild of stages 1
and 3 and diffed byte-for-byte identical (no assign-vs-sum drift of the kind
found in the sibling `detection-brittleness` project). Pinned by
`tests/test_matrix_determinism.py::test_matrix_is_deterministic_across_two_full_rebuilds`.

## 12. Data richness caveat, made visible in the matrix itself

`ryuk`, `lockbit_ransomware`, and `prestige_ransomware` are each a single
`.log` file, Sysmon-only (verified against each family's own `.yml`
metadata: one `datasets:` entry, one `sourcetype`). These three families are
marked `confidence: LOW` in `matrix/coverage_matrix.json` and rendered with
a "(low confidence: thin capture)" label directly under their column header
in [`matrix/coverage_matrix.png`](matrix/coverage_matrix.png), not only in
this prose. A red cell in one of these three columns is weaker evidence of
a genuine gap than the same red cell in `conti`, `revil`, or
`chaos_ransomware`, each of which spans multiple files and, for `conti`,
three separate sourcetypes (Sysmon, Security, PowerShell).

## 13. Correction: the live Splunk test resolved section 6, and the project's headline claim failed

**This is the most important section in this document.** It records what
was claimed, what was assumed, what a live test found, a near-miss in the
test methodology worth learning from, and what the project's conclusion is
now.

### What the original claim was

The project's stated falsifiable claim was: "Splunk's ransomware detection
content, despite naming specific families in its metadata, does not
uniformly cover the same core technique set across families." Proving this
required at least one real RED-LOGIC cell, a case where a detection existed,
was tagged to the right family and technique, and still did not match what
that family's capture actually contained. The original pipeline run found
two: `lockbit_ransomware|T1486` and `chaos_ransomware|T1486`, giving an
original tally of 11 GREEN / 2 RED-LOGIC / 5 RED-TELEMETRY / 52 GREY (see
section 9). On that tally the claim held, narrowly, and the README said so.

### What the strict reading assumed

Both RED-LOGIC cells traced to one detection,
`ransomware_notes_bulk_creation.yml`, whose SPL reads
`file_name IN ("*\.txt","*\.html","*\.hta")`. SPL's own documentation
defines exactly two string escapes: `\"` (literal quote) and `\\` (literal
backslash). `\.` is neither. Read strictly against that specification, an
unrecognized escape is preserved literally, so the detection's own wildcard
would only match a filename with an actual backslash character immediately
before "txt", "html", or "hta", a character no real ransom-note filename
contains. Both families' captures contain plainly-named `.txt` notes
(lockbit: `cHpfiXA9s.README.txt`; chaos: confirmed by direct grep, see
section 6), so under the strict reading the detection's own logic could
never fire against either capture: RED-LOGIC. This project explicitly
flagged, rather than silently resolved, that the strict reading was an
assumption about SPL's specification, not a test of Splunk's actual
runtime, because no live Splunk instance was available at the time.

### What the live test showed

A live Splunk instance later became available and was used, once, to test
exactly this question (see
[`evidence/07_spl_backslash_resolved.txt`](evidence/07_spl_backslash_resolved.txt)
for the full transcript, Splunk Enterprise 10.4.2):

1. The detection's own literal SPL, run against a synthetic event with
   `file_name="cHpfiXA9s.README.txt"`:
   `search file_name IN ("*\.txt","*\.html","*\.hta")` **matched.**
2. The same event against the permissive, plain-dot form,
   `search file_name IN ("*.txt")`, also **matched.**
3. A negative control, `file_name="notes.pdf"`, against the same
   backslash-dot clause, **did not match**, confirming the matcher is doing
   real filtering, not matching every event indiscriminately.

**Splunk treats the backslash permissively. The strict reading was wrong.**
Splunk's search-time wildcard matcher does not enforce a literal backslash
for an escape sequence its own SPL grammar does not define; it silently
drops the backslash and matches the following character literally. Both
`lockbit_ransomware|T1486` and `chaos_ransomware|T1486` are GREEN.

### The near-miss: an empty result and a broken query look identical

The first attempt to test this used `where file_name IN (...)` instead of
`search file_name IN (...)`. That form does not wildcard-match at all in
SPL, and it returned **empty for both the strict reading and the permissive
reading**, an empty result that would have been read as confirming the
strict reading (no match, therefore the backslash is enforced), when the
real cause was that `where ... IN` never wildcard-matches at all,
regardless of the backslash. Only the plain-dot positive control caught
this: `search file_name IN ("*.txt")` is a form that must obviously match a
file literally named `*.txt`-shaped, and it returned nothing under the
`where` harness too. A result that should be trivially true coming back
false is the signal that the harness itself is broken, not that the
hypothesis under test is confirmed. Switching to `search` (which does
wildcard-match in SPL) fixed the harness, and only then were the three
results above (match / match / correctly-no-match) obtained. This is
recorded here because it is a specific, concrete instance of the same
failure mode this entire family of projects exists to catch: an absence of
evidence and a broken evidence-gathering method produce the exact same
empty result, and the only way to tell them apart is a control condition
that is known in advance to have to succeed.

### What the conclusion is now

With RED-LOGIC at zero, the original falsifiable claim does not hold. This
project is now a **capture-completeness story, not a detection-gap story**.
Restated: everywhere a targeted ransomware behaviour was actually present
in one of the seven captures, at least one Splunk detection's own literal
logic matched it (13 of 18 non-grey cells GREEN, corrected from 11 of 18).
The remaining 5 non-grey cells are RED-TELEMETRY, a tooling gap (no
detection tagged to that family+technique pair exists at all), never a
written-but-wrong detection. Zero cells are RED-LOGIC. The dominant finding
in the matrix, unaffected by any of this, is still the 52 GREY cells: most
of the candidate technique/family pairs were never exercised in the sample
captures at all, so no claim about Splunk's detection quality is possible
for the majority of this matrix in either direction, and shadow-copy
deletion (T1490) still has zero evidence in the Conti, Ryuk, and LockBit
captures (section 1), unchanged by this correction.

### Numbers before and after, side by side

| | GREEN | RED-LOGIC | RED-TELEMETRY | GREY | Claim |
|---|---|---|---|---|---|
| Original (section 9) | 11 | 2 | 5 | 52 | Held, narrowly, with a disclosed caveat |
| Corrected (this section) | 13 | 0 | 5 | 52 | Failed; capture-completeness story |

A falsifiable claim that was tested and failed, reported plainly, is worth
more as a portfolio artifact than one that was never really put at risk.
This section exists so that outcome is not buried under the corrected
numbers, but stated as the headline result of testing the claim.
