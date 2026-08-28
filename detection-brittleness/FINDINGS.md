# Findings

Every number below is traced to a specific evidence file. "Evidence file" means
raw output saved by a script in `scripts/`, never hand-typed. If you want to
check a number, open the cited file; the pytest suite in `tests/` does exactly
that automatically.

A word most of this document leans on: **survive**. A Sigma rule "survives" a
sample group if Zircolite, running that rule's compiled SQL unmodified,
returns at least one matching event when pointed at that group's raw
telemetry. "Fires in every group" means it survived all of the independently
captured sample groups scored for that technique.

## Headline numbers

| Technique | Distinct eligible rules (technique-tagged) | Fired in >=1 group | Fired in EVERY group scored |
|---|---|---|---|
| T1003.001 (LSASS Memory) | 71 | 22 | **0** |
| T1059.001 (PowerShell) | 208 | 21 | **1** |

Source: `evidence/03_matrix.json`, recomputed independently by
`tests/test_findings.py::test_matrix_numbers_recompute_from_raw_zircolite_output`
directly from the raw per-group Zircolite output in
`evidence/zircolite_raw/`, bypassing the matrix script itself as a
cross-check.

"Eligible rules" means Sigma rules in Zircolite's vendored
`rules_windows_merged.json` ruleset carrying an `attack.t1003.001` or
`attack.t1059.001` tag. That ruleset compiles some rules twice (once per
log-source variant, e.g. "X - Generic" targeting `Security` EventID 4688 and
"X - Sysmon" targeting Sysmon EventID 1, same rule id, same detection intent).
71 and 208 are counts of distinct rule IDs; the raw compiled-entry counts are
105 and 309 respectively (`evidence/03_matrix.json` records both).

## Why this matters: 0/22 is not the same claim as "brittle" until checked

The build instructions for this project are explicit that a near-0% survival
rate must be diagnosed before being reported as brittleness, because the same
pattern shows up when corpora simply differ in which event types they
captured (a plumbing problem, not a detection problem). `scripts/04_diagnose_misses.py`
does that diagnosis for every miss, by extracting each rule's target
EventID(s) from its compiled SQL and checking whether that EventID even
occurs in the raw sample data of the group where the rule missed.

Result, from `evidence/04_miss_diagnosis.txt`
(`tests/test_findings.py::test_miss_diagnosis_produces_both_cause_categories`):

| Cause | Count (individual rule-group miss pairs, both techniques combined) |
|---|---|
| **Telemetry absent** -- the rule's target EventID never occurs anywhere in that group's raw data | 36 |
| **Logic too narrow** -- the EventID is present, but the rule's field/value match still did not fire | 51 |
| Undetermined (this group's EventIDs could not be read) | 0 |
| Unknown (SQL parse failed) | 0 |

Both counts are non-zero and neither dominates completely, which is itself
informative: this is not a pure corpus-format artifact (that would show
~100% telemetry-absent) and it is not proof every rule is badly written
either (some genuinely never had eligible data to test against). It is a mix,
and the two causes require completely different fixes -- telemetry gaps are
closed by turning on more logging, logic gaps are closed by rewriting the
rule. Conflating them, as the build brief for this project warns, is exactly
the mistake this exists to avoid.

**These numbers were corrected once already during this project.** An
earlier run of this same diagnosis reported 60 telemetry-absent and 27
logic-too-narrow. That first result was wrong because of a bug in the
diagnosis script itself, described in full in "Bug found during this
project: the EVTX EventID extraction defect" below. Fixing it moved 24
rule-group miss pairs from telemetry-absent to logic-too-narrow; the total
number of misses, 87, did not change, because the fix only reclassifies
existing misses, it does not add or remove any.

## Bug found during this project: the EVTX EventID extraction defect

`scripts/04_diagnose_misses.py` decides TELEMETRY ABSENT vs LOGIC TOO NARROW
by checking whether a rule's target EventID occurs anywhere in the raw data
of the sample group where it missed. The first version of that check found a
group's EventIDs by running a text regex, `<EventID>(\d+)</EventID>`, over
every file in the group's staged sample directory.

That works for `attack_data`'s samples, which are XML text. It does not work
for `EVTX-ATTACK-SAMPLES` and `EVTX-to-MITRE-Attack`, whose samples are
native `.evtx` files: a **binary** format, not text. A text regex run against
binary bytes matches nothing. The function returned an empty set for both
EVTX groups every single time, and the diagnosis code, on seeing an empty
"EventIDs present" set, always concluded the rule's EventID was absent, never
that it could not tell. Every miss in those two groups was reported as
TELEMETRY ABSENT by construction, regardless of what actually happened in
the underlying capture.

Measured effect: of the 60 TELEMETRY ABSENT calls in the first run, 38 came
from the two EVTX groups, all of them unreliable. Zero LOGIC TOO NARROW calls
were ever produced for either EVTX group, because the empty set made that
branch of the code unreachable for those two groups specifically. Meanwhile
the 22 TELEMETRY ABSENT and 27 LOGIC TOO NARROW calls in the two `attack_data`
groups, which are XML and readable by the regex, were sound throughout; this
bug did not affect them.

**The fix:** `scripts/03b_extract_evtx_eventids.py` asks Zircolite itself
(already vendored and used by this project to score every sample; no new
parsing library was introduced) to decode each EVTX group's events to JSON,
using `--no-event-filter --keepflat -n`. `--keepflat` writes every parsed
event, not just events some Sigma rule already matched, so this reads the
full inventory of EventIDs genuinely present in the capture, not a
rule-matched subset. `--no-event-filter` matters for the same reason:
Zircolite's default run pre-filters events by (channel, EventID) before
matching, dropping any event whose EventID is not targeted by at least one
loaded rule; skipping that flag would have reintroduced a smaller version of
the same undercount, silently. `04_diagnose_misses.py` now reads this
inventory instead of parsing binary EVTX as text. If a future run of that
inventory script cannot determine a group's EventIDs (a corrupted file, a
missing corpus, an unexpected format), the diagnosis reports
`UNDETERMINED (could not read this group's EventIDs)` for every miss in that
group, rather than silently defaulting to TELEMETRY ABSENT again. A
regression test,
`tests/test_findings.py::test_evtx_groups_have_a_non_empty_eventid_inventory`,
fails if any staged EVTX group ever has an empty (as opposed to explicitly
null/UNDETERMINED) EventID list, which is the exact condition that let this
bug through undetected the first time.

**Before and after**, both from `evidence/04_miss_diagnosis.txt`:

| Cause | Before fix | After fix |
|---|---|---|
| Telemetry absent | 60 | 36 |
| Logic too narrow | 27 | 51 |
| Undetermined | (not a distinct outcome yet) | 0 |
| Total misses | 87 | 87 |

The total is unchanged, as it should be: this fix reclassifies existing
misses using better information, it does not change which rules fired or
missed (`evidence/03_matrix.json` and the raw Zircolite match output under
`evidence/zircolite_raw/` were not touched by this fix and are identical
before and after).

A second, smaller defect was fixed alongside this one, disclosed here rather
than only in the script's own comments: `rules_windows_merged.json` compiles
some Sigma rules into more than one SQL variant under the same rule id, one
per log-source (for example a "- Generic" variant against Windows Security
EventID 4688 and a "- Sysmon" variant against Sysmon EventID 1, same
detection intent). The original diagnosis script kept only the first
compiled variant it happened to read for a given rule id, and which variant
came first depended on filesystem glob order, not anything meaningful. A
rule's true target EventID set is the union of every variant's EventIDs,
since the rule fires if any variant matches; `load_rule_sql_by_id` in
`scripts/04_diagnose_misses.py` now collects every distinct SQL variant seen
for a rule id and unions their EventIDs, so this attribution no longer
depends on directory read order.

This bug is the same class of failure the whole project is built to surface
in Sigma rules: a piece of detection logic that returns a default answer
instead of an honest "I don't know" when its input is missing, and nobody
downstream notices because the default and the true answer often overlap. A
rule that returns zero matches because a field name did not exist in a log
source, and a script that returns zero EventIDs because it could not parse a
binary file, are the same shape of bug wearing different clothes.

## Worked example: a genuine telemetry gap (T1003.001, SnapAttack capture)

Rule **"HackTool - Generic Process Access"** (Sysmon variant, targets
Sysmon EventID 10, ProcessAccess) fired in `attack_data_atomic_red_team` (4
hits), `evtx_attack_samples` (1 hit), and `evtx_to_mitre_attack` (1 hit), but
not in `attack_data_snapattack`.

Checking `evidence/samples/T1003.001/attack_data_snapattack/snapattack.xml`
directly: the only EventIDs present in that capture are 11 (FileCreate), 13
(RegistryEvent), 4104 (PowerShell ScriptBlock) and 4688 (process creation).
EventID 10 (ProcessAccess) never occurs. The SnapAttack capture recorded this
intrusion technique through its *aftermath* (WerFault crash-dump artifacts
left on disk after LSASS crashed and a memory dump file was written), not
through direct process-access monitoring of LSASS. A ProcessAccess-keyed rule
had zero eligible events to test against in this capture, structurally,
regardless of how the rule was written. This is the same class of finding as
`ir-activemq-lockbit`'s D5 (Sysmon EventID 10 absent from the whole capture):
a detection that cannot be evaluated, positive or negative, because its
required telemetry was never collected.

## Worked example: a genuine logic gap (T1059.001)

Rule **"Base64 Encoded PowerShell Command Detected - Sysmon"** (targets
Sysmon EventID 1, process creation) fired in `attack_data_atomic_red_team`
and `evtx_to_mitre_attack`, but missed in `attack_data_snapattack`, even
though EventID 1 events are present in that capture
(`evidence/samples/T1059.001/attack_data_snapattack/snapattack.xml` has
EventID 1, 3, 4104, and 4688). The telemetry the rule needs exists; its
command-line substring/base64 pattern match simply did not match this
particular Cobalt Strike PowerShell invocation's exact command-line shape.
That is a real generalization failure, the same category as
`ir-activemq-lockbit`'s D3 (rule looked for `net localgroup administrators`,
attacker ran `net group "Admins Domain" /domain`): close in intent, wrong in
exact string.

## The one rule that survived every T1059.001 group

**"Non Interactive PowerShell Process Spawned - Sysmon"** (id
`f4bbd493-b796-416e-bbf2-121235348529`, level: low) fired in all three
T1059.001 groups: 117 events in `attack_data_atomic_red_team`, 1 in
`attack_data_snapattack`, 2 in `evtx_to_mitre_attack`
(`evidence/03_matrix.json`). It is a low-specificity, informational-adjacent
rule (flags any PowerShell process spawned non-interactively, i.e. with a
parent other than a shell or Explorer), not a tool- or payload-specific
detection. That it is the one survivor is consistent with a broader pattern
worth naming plainly: rules broad enough to survive tool substitution tend to
be the ones with the least specific alerting value, and rules specific enough
to be useful (naming a tool, a DLL, a flag) tend to be the ones that miss when
the tool changes. This project's sample size (21 firing rules) is too small
to call that a general law, but it is the direction the one data point here
points, and it matches the intuition behind the whole project.

## No rule survived all four T1003.001 groups: is that surprising?

Given 22 rules fired somewhere and the corpora differ substantially in which
EventIDs they even captured (SnapAttack: 11/13/4104/4688 only; Atomic Red
Team's five files span EventID 1/4688/10; EVTX-ATTACK-SAMPLES spans a wide
mix from 1 through 53504; EVTX-to-MITRE-Attack spans 1 through 5145), a rule
would need to (a) target an EventID present in all four groups, and (b) have
a value-level match broad enough to catch tool-specific command lines,
process names, or access patterns across at least 4 independently-authored
tool executions. No rule in this ruleset does both. That is a real, checked
result, not an assumed one: see the per-rule breakdown in
`evidence/03_matrix_summary.txt`, where the closest rules reach 3 of 4 groups
(`HackTool - Generic Process Access`, `LSASS Dump Keyword In CommandLine -
Generic`, `LSASS Process Memory Dump Files`), each missing its 4th group for
a diagnosed reason in `evidence/04_miss_diagnosis.txt`.

## Corpus overlap: the 203/342 figure

`tests/test_findings.py::test_203_of_342_attack_data_technique_folders_have_multiple_sources`
recomputes this directly from the directory tree at
`_corpora/attack_data/datasets/attack_techniques/`: 342 technique folders
total, 203 of them contain 2 or more distinct dataset subfolders (i.e. 2+
independently authored/dated captures of the same technique). **The figure
holds.** It was recomputed fresh for this project rather than trusted from
the task brief, and it matched.

## What was capped and why

- `EVTX-to-MITRE-Attack`'s "T1003-Credential dumping" folder groups ALL T1003
  sub-techniques (LSASS memory, SAM, NTDS/DCSync) under one folder by tactic,
  not by sub-technique. 11 of 19 files in that folder were excluded from the
  T1003.001 sample set after content inspection (not filename guessing)
  showed they target SAM registry hives or AD replication objects, not LSASS
  process memory. Every exclusion and its reason is recorded in
  `manifest/technique_manifest.json` under
  `excluded_from_folder_despite_technique_label`, and pinned by
  `tests/test_findings.py::test_manifest_records_excluded_files_with_reasons`.
- 5 files in `EVTX-ATTACK-SAMPLES/Credential Access/` were excluded from
  T1003.001 after content inspection contradicted their filenames: one
  (`sysmon_10_1_memdump_comsvcs_minidump.evtx`) targets `notepad.exe`, not
  `lsass.exe`, per its own `TargetImage` field, despite the filename; another
  (`CA_teamviewer-dumper_sysmon_10.evtx`) targets `TeamViewer.exe`. This is
  disclosed rather than corrected silently, because a reader auditing the
  manifest needs to see that filenames in this corpus are not always reliable
  ground truth.
- Every Zircolite run completed in under 25 seconds
  (`evidence/02_zircolite_run_summary.json`); none needed capping.
- T1548 (Abuse Elevation Control Mechanism) was considered as a third
  technique per the build brief's candidate list, but its `attack_data`
  subfolders are almost entirely Linux GTFOBins tool names (`gawk`, `make`,
  `openvpn`, `docker`, etc.), which are not comparable "same technique,
  different tool" executions in the sense this project measures (they are
  privilege-escalation vectors on Linux hosts, largely outside what the
  Windows-oriented Sigma ruleset and EVTX corpora here can evaluate). It was
  dropped rather than forced; T1003.001 and T1059.001 were judged sufficient
  for a rigorous two-technique result given the effort budget.
- T1078 (Valid Accounts) was reviewed and also dropped: its `attack_data`
  subfolders are dominated by cloud-control-plane telemetry (AWS/Azure/O365
  API logs), which the Windows Sysmon/Security-oriented Sigma ruleset used
  here cannot meaningfully evaluate, and neither EVTX corpus has a clean
  technique-labelled T1078 folder. Rather than force a mismatched comparison,
  this is reported as a technique that did not hold up for this project's
  method, per the build brief's instruction to drop a candidate honestly
  rather than pad the technique count.

## Secondary approach (field mutation): not run

The build brief's secondary approach, synthetic field mutation on top of
survivor rules, was not executed. Reason: of the 22 T1003.001 rules that
fired at all, none survived all four real independent groups to begin with,
so there is no "survives-real-data" rule set to layer synthetic mutation on
top of for that technique. T1059.001 has exactly one such survivor
("Non Interactive PowerShell Process Spawned - Sysmon"); mutating its
matching log records was judged low value for the effort budget given it is
already the least specific rule in the set (mutating a rule that matches on
parent-process absence alone would mostly test Zircolite's SQL engine, not
adversary-tradecraft realism). This is left undone rather than padded with a
synthetic result of marginal information value.

## GUI evidence

See `evidence/gui/` and the "GUI evidence" section of `README.md` for what
was captured: real matplotlib renders of the survival matrix, and the
generated ATT&CK Navigator layer loaded into and screenshotted from the real
live Navigator web app. Splunk Web was not used (its local admin password is
intentionally not stored anywhere accessible to this project, a deliberate
security decision from a prior incident, not a gap in this one), and this
project's scoring does not depend on Splunk at all.
