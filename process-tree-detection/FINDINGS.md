# Findings

Every number below is traced to a named evidence file under `evidence/`, produced by
a numbered script under `scripts/`. Nothing here was typed in by hand and left
unchecked. Where a claim in `README.md` needs a citation, it points back to a
section here.

## Terms used below

- **Process tree**: the record of which process on a computer started which other
  process, several generations back, the same way a family tree links parents to
  children to grandchildren.
- **Parent process**: the process that started another process. Every process on
  Windows (except the very first one at boot) has exactly one parent.
- **Sysmon**: System Monitor, a free Microsoft driver that logs detailed process
  activity on Windows. **EventID 1** is the Sysmon record written every time a new
  process starts; it names the new process (`Image`), its command line
  (`CommandLine`), and its immediate parent (`ParentImage`, `ParentProcessGuid`).
- **LOLBIN** (living-off-the-land binary): a legitimate, pre-installed Windows
  program that attackers can abuse to run their own code, useful to them because
  the program is already trusted and signed, so running it alone rarely looks
  suspicious.
- **Precision**: of everything a detector flagged, the share that was actually
  malicious. A precision of 1.0 means every flag was correct; 0.5 means half were
  wrong.
- **Recall**: of everything actually malicious, the share the detector flagged.
  This project does not claim a recall number (see Limitations): the malicious
  corpus is 7 specific attack captures, not a representative sample of all
  attacks, so "the fraction of attacks caught" is not a number this data supports.
- **False positive**: a detector flagging something that was not actually an
  attack. Measured here as an event count on the labeled benign corpus, not as a
  rate (see Limitations for why a rate is not supportable).

## 1. Tree reconstruction (`scripts/01_build_trees.py`)

Both corpora were streamed line by line (the malicious file is 2.2 GB; nothing was
loaded fully into memory), EventID 1 records were grouped by `ProcessGuid` and
linked by `ParentProcessGuid`, and per-process depth/ancestor chains were computed
by walking those links. Output: `evidence/trees_malicious.jsonl`,
`evidence/trees_benign.jsonl`.

| | Malicious | Benign |
|---|---|---|
| EventID 1 (process creation) records | 1,167 | 1,274 |
| Unique processes | 1,167 | 1,274 |
| Parents resolving to another process in this corpus | 810 (69.4%) | 1,273 (99.9%) |
| Max chain length (processes, root to leaf) | 10 | 9 |
| Cycles detected | 0 | 0 |

These numbers match the ones given at the start of this project exactly. "Max
chain length" is reported here as a count of processes in the longest chain
(root through leaf); this project's own per-node `depth` field is 0-indexed hop
count, so the deepest node's `depth` is 9 (malicious) / 8 (benign), one less than
the chain-length numbers above. Both conventions are recorded in
`evidence/trees_*.jsonl`'s `_summary` line (`max_chain_depth_nodes` and
`max_chain_depth_hops`) to avoid the ambiguity silently changing a number.

One data-cleaning step was necessary before this would work at all: the malicious
corpus (OTRF Security-Datasets / Mordor format) writes `ProcessGuid` values in
braces, e.g. `{47ab858c-...}`, while the benign corpus (NextronSystems
evtx-baseline) omits them, e.g. `CCEE75F4-...`. Both are the same kind of Windows
GUID; without stripping the braces and lowercasing both, the same process would
appear to have two different identities purely from which collection pipeline
produced it, and the tree would fracture at every parent/child boundary that
crossed a formatting difference (in practice, at none in this corpus, since GUIDs
are consistent within each file, but this was verified, not assumed).

## 2. Base Sigma's grammar and this ruleset's actual reach

**What is on disk.** This project reused the ruleset the sibling `detection-rule-lab`
project already scores against these same two corpora:
`vendor/Zircolite/rules/rules_windows_sysmon.json` in that project (read-only),
containing exactly **2,691** Zircolite-compiled Sigma rules
(`python3 -c "import json; print(len(json.load(open('rules_windows_sysmon.json'))))"`
returns `2691`). This is the same file and the same count the sibling project's own
`README.md` and `reports/findings.md` report, confirmed independently here.

**The ParentImage / "384" check.** The task description cited 384 rule files
matching on `ParentImage` and asked this project to verify that number against
whatever ruleset is actually on disk. There is no directory of individual `.yml`
Sigma source files vendored in this environment; Zircolite ships (and the sibling
project runs) a single compiled JSON file per ruleset variant instead. Grepping
that JSON two different ways gives two different, both defensible, counts:

- **329 rules** contain the substring `ParentImage` anywhere in their JSON record
  (title, description, tags, or the compiled SQL condition); the count was
  computed in Python by checking `'ParentImage' in json.dumps(rule)` per rule,
  since one rule is one JSON object spanning multiple lines and a plain
  line-based `grep -c` is not meaningful here.
- **327 rules** reference `ParentImage` specifically inside their *compiled SQL
  condition* (the `rule` field, e.g. `ParentImage LIKE '%\\sdclt.exe'`), which is
  the stricter and more meaningful count: these are the rules that actually key
  on parent-process lineage at match time.

Neither number is 384. This project cannot reproduce 384 from anything found on
this disk; it is reported here as an unverified figure rather than silently
adjusted to match, per the instruction to report what was actually counted. Two
other Sigma rule trees exist elsewhere among the director's projects
(`cloud-detection-coverage/data/sigma`, 4,265 `.yml` files, 406 matching
`ParentImage`; `detection-as-code/sigma_rules` and its sibling copy, 6 files
each, 1 matching) but none produces 384 either, and none is the ruleset the
malicious/benign corpora were actually scored against, so none was used further.

**The correlation-rule check.** `grep -rl "type: correlation"` across this entire
project, and across `/home/kali/director/projects/detection-rule-lab`, returns
**zero files** (exit code 1, no matches). The compiled ruleset JSON was also
checked in Python for a `correlation` key or a rule whose `type` field equals
`"correlation"`: zero of 2,691 rules. Sigma's correlation rule type (the
mechanism the base Sigma specification provides for reasoning across more than
one event) is not present anywhere in this environment's rule content.

**The one partial exception, and why it does not weaken the finding.** Two rules
in the 2,691 (`Potential Pikabot Discovery Activity`,
`RedSun - Conhost.exe Spawned by TieringEngineService.exe`) reference a field
called `GrandParentImage`. This looks like a second hop of lineage reasoning
inside a single-event rule, so it was checked carefully:
`GrandParentImage` does **not** appear anywhere in either corpus
(`grep -c "GrandParentImage"` on both raw JSONL files returns `0` for both),
confirming it is not a native Sysmon field. A web search traced it to Nextron
Systems' **Aurora** product, an ETW-based agent that enriches process-creation
events with extra fields (including `GrandParentImage`) *before* Sigma ever sees
them; this requires deploying Aurora, a separate tool from Sysmon. Against plain
Sysmon telemetry (what both corpora in this project are), those 2 rules'
`GrandParentImage` condition is always comparing against a NULL field and can
never fire. So even the one apparent counterexample in 2,691 rules (a) requires
non-standard, non-Sysmon tooling most environments do not deploy, and (b) is
hardcoded to exactly one extra hop, never more, and could not express this
project's Detector 1 (an auto-elevating binary's *grandchild*, found by walking
two `children` links, not a fixed field) or Detector 2 (chain length is
unbounded and varies per event).

## 3. Detector 1: UAC_BYPASS_PROXY_CHAIN (`scripts/03_score_tree_detectors.py`)

**Tradecraft basis.** MITRE ATT&CK **T1548.002** (Abuse Elevation Control
Mechanism: Bypass User Account Control), confirmed by fetching
`https://attack.mitre.org/techniques/T1548/002/` directly: the page names
`eventvwr.exe`, `fodhelper.exe`, and `sdclt.exe` as auto-elevating Windows
binaries (binaries Windows silently runs at high integrity without a UAC prompt)
that adversaries hijack. The documented technique redirects the auto-elevating
binary's lookup for a helper program so that it launches attacker-controlled code
instead; in the `sdclt.exe` case specifically, this is done by planting a registry
value that Windows consults when `sdclt.exe` tries to open Control Panel's
"Backup and Restore" applet via `control.exe`, so that `control.exe` launches the
attacker's payload at high integrity instead
([Penetration Testing Lab, "UAC Bypass - SDCLT"](https://pentestlab.blog/2017/06/09/uac-bypass-sdclt/),
cross-referenced against the MITRE page). The LOLBAS project
(`lolbas-project.github.io`, fetched live and saved to
`evidence/sources/lolbas_project.json`) independently tags `computerdefaults.exe`,
`eudcedit.exe`, `eventvwr.exe`, `iscsicpl.exe`, `odbcad32.exe`, and `wsreset.exe`
with MITRE ID T1548. The detector's auto-elevating binary list is the union of
both sources (8 binaries; see `evidence/tree_detector_results.json`), not a list
invented for this corpus.

**What the detector checks.** For every process whose image matches one of the 8
auto-elevating binaries, walk its `children`, then walk each child's `children`
(the grandchildren), and flag it if any grandchild is a shell or script
interpreter (`cmd.exe`, `powershell.exe`, `pwsh.exe`, `powershell_ise.exe`,
`wscript.exe`, `cscript.exe`, `mshta.exe`). This is **not** hardcoded to
`control.exe` as the middle hop, on purpose: the documented technique family
covers several possible hijacked intermediaries, and requiring a specific one
would fit only the sample found in this corpus rather than the general shape of
the technique.

**Result.**

| | Malicious hits | Benign hits (false positives) | Precision |
|---|---|---|---|
| UAC_BYPASS_PROXY_CHAIN | 2 | 0 | 1.0 |

**The case study, traced event by event.** The 2 hits are both
`sdclt.exe -> control.exe -> powershell.exe` chains from the same attack capture in
the malicious corpus, a Mordor/OTRF recording of MITRE's own APT29 evaluation
environment (hostname `SCRANTON.dmevals.local`, tagged `mordorDataset`). The
`control.exe` process in this chain runs
`"C:\Windows\System32\control.exe"  /name Microsoft.BackupAndRestoreCenter` (the
expected, benign-looking argument for the real Backup and Restore applet) but its
child is `powershell.exe`, which a legitimate `control.exe /name
Microsoft.BackupAndRestoreCenter` invocation never spawns. One PowerShell payload
reads pixel data out of a PNG (`monkey.png`) and executes the extracted bytes via
`IEX` (a steganographic payload-delivery technique); the other is a base64-encoded
`IEX` of a reverse-shell-style download-and-execute script. Both are visible only
by looking at `control.exe`'s *child*, two hops below `sdclt.exe`.

An existing rule in the 2,691-rule set, **"Sdclt Child Processes"**
(`da2738f2-fadb-4394-afa7-0a0674885afa`, `ParentImage LIKE '%\sdclt.exe'`), was
checked directly against the raw corpus and **does** fire, exactly twice, on the
`control.exe` events. It never fires on the `powershell.exe` payload-launch
events, because their `ParentImage` is `control.exe`, not `sdclt.exe`; a
single-hop rule anchored to "child of sdclt.exe" structurally cannot see one hop
further than that.

Checking further (`scripts/04_compare_single_hop_vs_tree.py`, re-running every
compiled rule's SQL against just these 2 `powershell.exe` events): **5 other
existing rules do match them**, but all 5 key on the PowerShell command line's
*content* (obfuscation/encoding heuristics: `Non Interactive PowerShell Process
Spawned`, `Suspicious Execution of Powershell with Base64`, `Change PowerShell
Policies to an Insecure Level`, `PowerShell Base64 Encoded FromBase64String
Cmdlet`, `Suspicious PowerShell Parameter Substring`), not on process lineage.
**The honest version of this project's claim is therefore narrower than "nothing
else catches this":** it is that no *lineage-based* single-hop rule in this
ruleset catches the payload-launch event, only content-based ones, and a
content-based detection would stop working against an attacker who avoids those
specific command-line patterns (a different encoding, a different flag set, a
compiled payload instead of a PowerShell one-liner), whereas the tree
detector's signal (an auto-elevating binary's grandchild is a shell) does not
depend on what the shell was told to run.

## 4. Detector 2: DEEP_CHAIN_TO_LOLBIN, reported as a negative result

**Tradecraft basis.** MITRE ATT&CK **T1218** (System Binary Proxy Execution):
adversaries proxy execution through trusted, signed binaries specifically to put
distance between the initial compromise and the payload, in the eyes of
defensive tooling that watches immediate parent-child pairs.

**What the detector checks.** Any process chain that reaches a LOLBAS-listed
binary (242 binaries, `evidence/sources/lolbas_project.json`, fetched live from
the LOLBAS project) at least 4 processes deep from its root ancestor.

**Result.**

| | Malicious hits | Benign hits (false positives) | Precision |
|---|---|---|---|
| DEEP_CHAIN_TO_LOLBIN | 145 | 55 | 0.725 |

**This does not clear the bar and is reported as a negative result, not tuned
after the fact to look better.** Breaking down what actually fired:

| LOLBIN reached | Malicious hits | Benign hits |
|---|---|---|
| conhost.exe | 100 | 26 |
| ngen.exe | 0 | 8 |
| cmd.exe | 12 | 4 |
| regsvr32.exe | 0 | 4 |
| others (9 more binaries, 1-8 hits each) | 33 | 13 |

`conhost.exe` (the Windows Console Host, spawned automatically whenever almost
any console application runs, whether malicious or not) accounts for 100 of 145
malicious hits and 26 of 55 benign hits: it is deep in the tree constantly, for
completely unrelated reasons, on both sides. `ngen.exe` (the .NET Framework's
native-image compiler, part of routine Windows Update / service maintenance)
accounts for 8 of the 55 benign false positives; it appears in the deepest chain
this project found in the entire benign corpus (9 processes,
`services.exe -> svchost.exe -> taskhostw.exe -> ngentask.exe -> ngen.exe ->
mscorsvw.exe`, visualized in `charts/process_tree_comparison.png`), which is
ordinary OS housekeeping, not an attack. Excluding just those two names still
leaves 41 malicious / 19 benign hits with no consistent pattern separating them
(`cmd.exe` and `rundll32.exe` fire on both sides in similar proportions).

**Conclusion for Detector 2: depth alone, even restricted to a curated
"documented LOLBAS binary" list, is not a usable detection signal on this
corpus.** LOLBAS documents "this binary is capable of abuse," not "this binary
running deep in a chain is suspicious"; most LOLBAS binaries are also ordinary
system machinery that legitimately runs at whatever depth the OS's own service
architecture puts it. This is reported the way the task asked negative results
to be reported: plainly, with the specific false-positive-driving names named,
rather than adjusted after the fact until the number looked acceptable. (Compare
to a sibling project's own documented negative result: a runtime probe that
produced 12,841 false positives on idle desktop use and was reported as
unusable rather than shipped.)

## 5. Comparison table (`scripts/04_compare_single_hop_vs_tree.py`, `evidence/comparison_table.json`)

| | Rules/detectors | Malicious hits/events matched | Benign hits (false positives) |
|---|---|---|---|
| Single-hop Sigma baseline (2,691 rules, this project's re-execution) | 2,691 | 6,283 events, 129 rules fired at all | 62 events |
| Tree Detector 1: UAC_BYPASS_PROXY_CHAIN | 1 detector | 2 | 0 |
| Tree Detector 2: DEEP_CHAIN_TO_LOLBIN | 1 detector | 145 | 55 (negative result, see section 4) |

The single-hop baseline row is not "0 for everything the tree detector finds":
129 of 2,691 rules fire on this corpus for many different, legitimate reasons
unrelated to process lineage. The specific, falsifiable claim this project
checked is narrower and is the one that held: **of the 2 exact events where
Detector 1's signal fires, no lineage-based single-hop rule in the 2,691-rule
set also fires on those same events**, even though a lineage-based single-hop
rule exists for the one hop closer to the root (`Sdclt Child Processes`).

## 6. Single-hop baseline: methodology and a disclosed reconciliation gap

Rather than install Zircolite's full dependency stack (which failed under this
environment's Python 3.14: `pysigma`/`pysigma-pipeline-sysmon` installed dist-info
metadata but not usable modules, and the sibling project's own venv was missing
`flatten_json`/`chardet`), this project re-executes the **exact compiled SQL**
already present in `rules_windows_sysmon.json` directly against a SQLite table
built from each corpus, using Python's stdlib `sqlite3`. This is the same SQL
Zircolite would run (pysigma's SQLite backend compiles Sigma to this SQL ahead of
time; the JSON file is that compiled output), re-executed without Zircolite's
process wrapper. A `REGEXP` SQL function was registered to support the 90 rules
using Sigma's `|re` modifier (stock SQLite has no built-in `REGEXP`).

**Reconciled against the sibling project's own live Zircolite run**
(`detection-rule-lab/reports/scoring-run.json`, read-only reference): this
project's method found 129 of 2,691 rules firing at all; the sibling's live run
found 135. Diffing the two rule-id sets found the gap was **9 rules** that fired
for the sibling but not here, and 1 rule that fired here but not for the sibling.
One cause was identified and fixed: 2 of the 9 rules key on `Channel='Security'`
(capital S), but roughly half of this corpus's Security-channel events are
written as `Channel='security'` (lowercase) by the OTRF/Mordor collection
pipeline; SQLite's `=` is case-sensitive for text, so this project's replay
missed them until `Channel` values were canonicalized to `Security` at load time
(confirmed as the sole difference: every other Channel value in both corpora is
consistent between the two files). The remaining **7 rules** (all
network/logon/access-rights rules: RDP/SMB logon from a public IP, workstation
lock, WMI login, WinRM session detection, process access rights) were not
individually root-caused further, given this project's 10-minutes-per-job effort
budget and that none references `ParentImage`, `ParentProcessGuid`, or any other
process-lineage field, so none affects the process-tree comparison this project
measures. Full detail, including the exact rule ids and titles on both sides:
`evidence/single_hop_vs_sibling_reconciliation.json`.

Three rules could not be evaluated by either method on the malicious corpus:
SQLite raised `Expression tree is too large (maximum depth 1000)` on 3 rules with
very large OR-chains (likely bulk hash/IP blocklists); this is a SQLite engine
limit unrelated to this project's code, affecting 3 of 2,691 rules (0.1%).

## 7. Licensing (re-confirmed)

- Detection rules (SigmaHQ, via the vendored Zircolite ruleset): **Detection Rule
  License 1.1**, which requires per-rule author attribution wherever matches are
  displayed. `da2738f2-fadb-4394-afa7-0a0674885afa` ("Sdclt Child Processes") and
  `40f9af16-589d-4984-b78d-8c2aec023197` ("Potential UAC Bypass Via Sdclt.EXE")
  are the two rules named above by title; their author fields are recorded in
  `evidence/single_hop_sdclt_case.json` alongside their hit counts.
- Malicious telemetry: OTRF Security-Datasets, **MIT** license.
- Benign telemetry: NextronSystems evtx-baseline, **Apache-2.0** license.
- LOLBAS project data (`evidence/sources/lolbas_project.json`): LOLBAS-Project,
  used here as a reference list of binary names and their documented MITRE
  technique tags, not redistributed as a rule set.

## 8. Limitations (read before trusting any number above)

1. **The malicious corpus is 7 specific attack captures, not a sample of "attacks
   in general."** A detector scoring well here says it works against those 7
   captures. It says nothing about detection rate against attacks not
   represented in this data, and this project makes no recall claim for that
   reason.
2. **The benign corpus is a small number of hosts over a bounded time window,
   not a fleet.** A false-positive count of 0 or 55 here is a count on this
   sample, not a rate that generalizes to a different environment's process mix.
3. **Detector 1's precision of 1.0 is on n=2 true positives.** A perfect score on
   two events is not strong statistical evidence on its own; it is reported
   alongside the exact mechanism (why a single-hop rule structurally cannot see
   this event) so the claim rests on the mechanism, not the sample size.
4. **This project checked one ruleset (Zircolite's compiled SigmaHQ Windows/
   Sysmon rules) and one detection engine's compiled SQL semantics.** A
   different Sigma backend, or hand-written non-Sigma detection logic, might
   express more than base Sigma's grammar allows; the claim here is scoped to
   "base Sigma correlation rules are absent from this environment and this
   compiled ruleset's single-event grammar cannot express variable-depth
   lineage," not "no detection tool anywhere can do this."
5. **The 384/ParentImage figure from the task brief could not be reproduced**
   from any ruleset found on this disk (see section 2); it is reported as
   unverified rather than forced to match.
6. **7 of the 2,691 rules' pass/fail status against this corpus is not fully
   reconciled** between this project's direct-SQL-replay method and the
   sibling project's live Zircolite run (see section 6); none of the 7 touches
   process-lineage fields, so this does not affect the tree-detection
   comparison, but it is an open, disclosed gap in the single-hop baseline's
   completeness.
