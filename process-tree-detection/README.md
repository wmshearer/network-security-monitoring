# Process-tree detection: what multi-hop reasoning sees that single-event rules cannot

## The finding, first

A real attack chain in this project's data goes `sdclt.exe -> control.exe ->
powershell.exe`. `sdclt.exe` is a Windows program that Windows lets run as
administrator without asking the user, and attackers can trick it into launching
their own code through `control.exe` (Windows Control Panel) instead of the
program it normally opens. This is a documented technique, MITRE ATT&CK
T1548.002.

There is already a detection rule in the 2,691-rule set checked here that
watches for exactly this: "Sdclt Child Processes," which flags any process
started directly by `sdclt.exe`. It fires. Twice, in this data. But it only
flags the `control.exe` step. It never flags the `powershell.exe` step, the one
where the attacker's code actually runs, because `powershell.exe`'s parent is
`control.exe`, not `sdclt.exe`. The rule can only see one link in the chain: a
process and its immediate parent. It cannot see a grandparent.

A detector built in this project that walks the process tree two generations
back (grandchild of a program Windows auto-elevates, is it a shell) catches both
`powershell.exe` events. Tested against 1,274 ordinary Windows processes with no
attack in them, it flags zero of them. That is the finding: **looking at more
than one event at a time catches something a same-ruleset, same-data, one-event
rule structurally cannot, at no cost in false alarms on this benign data.**

A second detector this project built, based on chain depth alone, did not hold
up. It is reported below as a negative result, because that is what actually
happened.

## Why this matters, for someone new to detection engineering

Most detection rules, including nearly all 2,691 checked in this project, look
at one event at a time: one process starting, with its own name, command line,
and immediate parent. That is what a **Sigma rule** is built to do. Sigma is a
shared, text-based format security teams use to write detection logic once and
run it on different tools. A rule written in Sigma says, in effect, "if a
process named X starts with a parent named Y, flag it."

That is useful, but it has a hard limit. A **process** is a running instance of a
program. A **parent process** is whatever process started it: opening a web
browser from your desktop makes the desktop's process the browser's parent.
Chain enough of these together (a document opens a script, the script opens a
command shell, the shell launches a downloader) and you get a **process tree**,
the same way a family tree links parents to children to grandchildren. A rule
that only reads one event's own parent field can see one link in that chain. It
cannot see two links back, and it cannot ask "how deep is this chain" or "how
many children does this process have," because none of that fits in one event.

This project asks a specific, checkable question: on real data, what does
looking at more than one event (walking the tree, not just reading one row) let
a detector see that single-event Sigma rules in this exact ruleset cannot?

## Two terms that come up throughout

- **Sysmon** (System Monitor) is a free Microsoft tool that logs detailed
  process activity on Windows: every time a program starts, Sysmon writes an
  event (called **EventID 1**) recording the program's name, its command line,
  and its parent's name. This project's evidence is built entirely from EventID
  1 records.
- **LOLBIN** (living-off-the-land binary) is a legitimate program that already
  ships with Windows, which attackers can abuse to run their own code, because
  the program is trusted and signed, so running it does not look suspicious by
  itself. `control.exe` and `powershell.exe` are both examples.

## What was measured

| | Value |
|---|---|
| Malicious corpus | 834,226 total events, 1,167 process-creation (EventID 1) records |
| Benign corpus | 110,095 total events, 1,274 process-creation records |
| Parents resolving to another process in the same corpus | 69.4% malicious, 99.9% benign |
| Deepest process chain found | 10 processes (malicious), 9 processes (benign) |
| Sigma rules checked | 2,691 (the SigmaHQ Windows/Sysmon ruleset, as compiled and run by the sibling `detection-rule-lab` project) |
| Rules that reference a parent process at all | 327-329, depending on how the check is run (see FINDINGS.md); not the 384 originally cited, which this project could not reproduce from anything on disk |
| Rules using Sigma's built-in multi-event mechanism ("correlation" rules) | 0 |

The benign side matters as much as the malicious side. Anyone can build a
detector that looks impressive against attack data alone; the only way to know
if it is actually usable is to run it against ordinary, non-attack activity and
count how often it goes off anyway. That count is called a **false positive**: a
detector flagging something that was not actually an attack. This project's
benign data reconstructs cleanly (99.9% of processes' parents are known, chains
up to 9 processes deep), so a false-positive count from it is a real, checkable
number, not a guess.

## The two detectors this project built and tested

Both are documented on `attack.mitre.org` and cross-referenced against the
LOLBAS project (a public catalog of Windows programs known to be abusable this
way), not invented to fit this one dataset. Full sourcing and reasoning for each
is in `FINDINGS.md`.

**Detector 1: UAC_BYPASS_PROXY_CHAIN.** Looks for a program Windows
auto-elevates (like `sdclt.exe`) whose child's child (two hops down) is a shell
or script interpreter. Result: 2 hits on malicious data, 0 on benign. Both hits
are the real `sdclt.exe -> control.exe -> powershell.exe` chain described above.

**Detector 2: DEEP_CHAIN_TO_LOLBIN.** Looks for any process chain that reaches a
LOLBAS-listed program at least 4 processes deep. Result: 145 hits on malicious
data, but also 55 hits on benign data, a precision of 0.725. This is reported as
a **negative result**. Most of the benign hits are `conhost.exe` (a normal part
of running almost any command-line program) and `ngen.exe` (routine .NET
maintenance that Windows runs on its own, unrelated to any attack). Depth alone,
even limited to a list of binaries known to be abusable, is not a reliable
signal here. See `FINDINGS.md` section 4 for the full breakdown.

## The comparison table

| | Rules/detectors | Hits on malicious data | Hits on benign data (false positives) |
|---|---|---|---|
| All 2,691 single-event Sigma rules | 2,691 | 6,283 events, 129 rules fired at all | 62 events |
| Tree Detector 1 (UAC bypass proxy chain) | 1 | 2 | 0 |
| Tree Detector 2 (deep chain to LOLBIN) | 1 | 145 | 55 (negative result) |

The honest version of the headline claim, stated precisely: of the 2 events
where Detector 1 fires, no rule in the 2,691-rule set that keys on **process
lineage** (parent/child relationships) also fires on those same events, even
though a lineage-based rule exists for the step one hop closer to the root.
Five other rules do catch those events, but only by reading the PowerShell
command line's content for known obfuscation patterns, a different and less
durable kind of signal than tracking who spawned whom. Both claims (the exact
positive result and its precise boundary) are in `FINDINGS.md`, with every
number traced to the evidence file that produced it.

## The visual

`charts/process_tree_comparison.png` renders two real process trees side by
side, drawn from this project's actual reconstructed data: the malicious
`sdclt.exe` chain (with the exact node a single-event rule flags and the exact
node only the tree detector flags marked), next to the deepest chain found in
the benign corpus, nine ordinary Windows processes deep, ending in a routine
.NET compilation step. Nothing in that image is a mockup; every label, box, and
arrow comes from the evidence files in `evidence/`.

## Repository layout

```
process-tree-detection/
  README.md          # this file
  FINDINGS.md         # every number, traced to its evidence file, with sourcing
  scripts/            # numbered 01-06, run in order, read-only against the source corpus
  evidence/            # raw output; never hand-edited
  evidence/gui/         # terminal captures and the rendered diagram
  charts/              # the process-tree comparison diagram (graphviz)
  tests/                # pytest; skips (not fails) if the source corpus is absent
```

## Running it

Requires read access to
`/home/kali/director/projects/detection-rule-lab/data/events/{malicious,benign}.jsonl`
and the vendored Zircolite ruleset in that same project (both read-only; this
project never writes to it).

```bash
python3 scripts/01_build_trees.py both
python3 scripts/02_score_single_hop.py
python3 scripts/03_score_tree_detectors.py
python3 scripts/04_compare_single_hop_vs_tree.py
python3 scripts/05_render_tree_diagram.py
python3 scripts/06_print_summary.py
python3 -m pytest tests/ -v
```

## What this project does not claim

- **No recall number.** The malicious corpus is 7 specific attack captures, not
  a representative sample of attacks in general. A detector that scores well
  here says nothing about how many real-world attacks it would catch.
- **A false-positive count on this data is not a false-positive rate
  everywhere.** The benign corpus is a small number of hosts over a bounded
  window. Zero false positives here is a real, checked number on this sample;
  it is not a guarantee for any other environment's process mix.
- **This project checked one ruleset and one detection engine's compiled SQL.**
  It found that base Sigma's multi-event mechanism (correlation rules) is
  absent from this environment and that this ruleset's rules cannot express
  variable-depth lineage. It does not claim no detection tool anywhere can do
  this; other engines and hand-written logic may express more than base Sigma
  does.
- **The 384-rule figure from the original task brief could not be reproduced**
  from any ruleset found on this disk. This is disclosed, not silently
  corrected to match. See `FINDINGS.md` section 2.

## Licensing

Detection rules are SigmaHQ, licensed under Detection Rule License 1.1, which
requires per-rule author attribution wherever a match is shown; author names
for every rule discussed here are in `evidence/single_hop_sdclt_case.json`.
Malicious telemetry is OTRF Security-Datasets (MIT license). Benign telemetry
is NextronSystems evtx-baseline (Apache-2.0 license). The LOLBAS binary list
used by Detector 2 is from the LOLBAS project, used here as a reference list,
not redistributed as a rule set.
