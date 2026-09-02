# YARA rule engineering: false positives, cost, and YARA-X

**YARA** is pattern-matching software used by security teams to find files
that match a set of rules ("if this file contains string X or byte pattern
Y, flag it"). Public YARA rulesets are widely shared and reused; this
project asks three questions about that practice using only clean,
legitimate files already on this machine. **No malware sample of any kind
was downloaded or used anywhere in this project.**

## What was found, in order of how surprising it was

**1. Cloning a popular public ruleset and compiling everything you find gives
a near-worthless detector, and the maintainers already knew it.**
`Yara-Rules/rules`, scanned in full against ordinary Kali system binaries,
flagged 98.75-99.50% of files as suspicious. That number is almost entirely
four rules (`domain`, `url`, `ip`, `contains_base64`) in a `utils/`
directory that the project's OWN maintained index file
(`index.yar`) never includes. Scope the ruleset to exactly what
the maintainers ship and the rate drops by roughly 10x, to 6.8-19%. This is
the difference between "clone the repo" (what most blog posts and forum
answers say to do) and "use what the project actually intends", and it is
a ten-times difference in outcome.

**2. The two professional rulesets tested (ReversingLabs, Elastic) were
essentially silent on a clean corpus of 8,115 files, and when they weren't
silent, they were right.** `reversinglabs` matched 0 files across every
corpus tested. `signature-base` and Elastic's `protections-artifacts` each
matched 3 files out of 3,239 in `/usr/bin` and 0 everywhere else. Those 3
matches were not false positives: they correctly identified Kali's own
`dsniff`/`sshmitm`/`webmitm` MITM toolkit, `aircrack-ng`, `masscan`, and
`sliver-client` as exactly what they are: real offensive security tools
that happen to be installed on this machine. A near-zero false-positive rate
that is also a 100% true-positive rate on the handful of things it did flag
is a genuinely strong result.

**3. Three different ways of writing "match this exact sequence of bytes"
cost the same; asking YARA to parse a file's structure costs roughly
double.** A literal string, an equivalent regex, and an equivalent hex
pattern with wildcards all compile to the identical Aho-Corasick automaton
(confirmed with `yara -S`) and scan a 3,239-file corpus in statistically
indistinguishable time (1.83-1.90 seconds, repeated 7 times each). A `for`
loop over `elf.sections` checking the same underlying fact takes 3.64
seconds, not because loops are slow, but because it never touches YARA's
string-matching engine at all (`number of strings: 0` in `yara -S`'s own
output) and instead pays the cost of parsing the ELF section table.

**4. YARA-X agrees with YARA 4.x on 99.99% of scans it CAN run, and where the
two engines disagree on what compiles at all, the gap is large and
specific.** Restricted to rule files that compile under both engines,
14,869 of 14,871 sampled file-scans across four public rulesets produced
identical results. But compilation itself is a different story: YARA-X's
compiler is measurably more forgiving of missing `import` statements (it
compiled a 931-rule file that yara-python rejected outright) and measurably
stricter about undeclared external variables. On the one ruleset large
enough to time meaningfully, YARA-X scanned the same files roughly 15x
faster than yara-python.

**5. A rule counter I wrote for this project had two real bugs, both found
by cross-checking against yara-python's own count rather than trusting my
own code.** See "Method notes" below. This is not a finding about YARA,
it is a finding about not trusting a tool you just wrote.

## The three questions, answered

### Q1: do public YARA rules fire on clean files?

Yes, at very different rates depending on the ruleset and how it is scoped.
Full numbers, per-corpus breakdown, and the manual inspection of exactly
which rules fired and why are in **[FINDINGS.md](FINDINGS.md)**. Chart:
`evidence/chart_q1_false_positive_rate.png`.

### Q2: what makes a ruleset slow?

Not the choice between literal/regex/hex for an equivalent pattern (measured
as no real difference). A construct that requires YARA to parse file
structure (the `elf` module) rather than scan raw bytes does cost more,
roughly double in this test. Separately, and unplanned: merging thousands of
rule files into one compiled ruleset costs more per file than the simple sum
of scanning each file's rules alone, because the shared pattern-matching
automaton grows. Full method, the real `yara -S --print-stats` output, and
the variance across repeated runs are in **[FINDINGS.md](FINDINGS.md)**.
Chart: `evidence/chart_q2_cost_by_construct.png`.

### Q3: does YARA-X agree with YARA 4.x?

Almost entirely yes, on the files it can compile. Where the two engines
genuinely differ, it is in what compiles at all (module support, strictness
about undeclared variables) and in raw speed, not in what a compiled rule
matches. Full compile-portability tables, the two genuine scan
disagreements found (both explained), and the confirmed claims from YARA-X's
own documentation are in **[FINDINGS.md](FINDINGS.md)**.

## The corpus (all legitimate, no malware)

| Corpus | Files | What it is |
|---|---|---|
| `/usr/bin` | 3,239 | ordinary Kali system binaries |
| `/usr/lib/x86_64-linux-gnu` | 1,683 | shared libraries, top level only |
| OpenWrt 24.10.8 firmware | 2,181 | extracted squashfs, from the sibling `firmware-analysis` project |
| OWASP IoTGoat firmware | 1,012 | extracted rootfs, from the sibling `firmware-binary-analysis` project |

**IoTGoat is a deliberately vulnerable *training* image (MIT licence), not
malware.** It ships one intentional backdoor script, documented in the
sibling project. No reader should infer a malware sample was used anywhere
in this project.

## Ruleset licences (the split is itself a finding)

| Repo | Licence | Open source? |
|---|---|---|
| `Yara-Rules/rules` | GPLv2 | Yes |
| `reversinglabs/reversinglabs-yara-rules` | MIT | Yes |
| `Neo23x0/signature-base` | **Detection Rule License (DRL) 1.1** | **No**, custom licence, requires attribution |
| `elastic/protections-artifacts` | **Elastic License 2.0** | **No**, source-available, forbids hosted/managed-service resale |

The common advice ("just grab signature-base") points at a non-OSI, custom
licence. None of the four rulesets are vendored into this repository; all
are cloned at runtime by `scripts/01_fetch_rulesets.sh` into a gitignored
`.rulesets/` directory.

## Repository layout

```
yara-rule-engineering/
  README.md            # this file
  FINDINGS.md           # every number, traced to an evidence file
  rules/                # the controlled Q2 cost-experiment rules (own authorship)
  scripts/               # numbered, idempotent, runnable in order
  evidence/              # raw captured output, one file per run, never hand-edited
    gui/                 # real GUI/terminal screenshots
  tests/                 # pytest, pins every claim in FINDINGS.md; skips (not fails) if evidence/rulesets are absent
```

## Running it yourself

```bash
cd yara-rule-engineering
python3 -m venv .venv          # or use the provided .venv
.venv/bin/pip install -r requirements.txt

bash scripts/01_fetch_rulesets.sh        # clones the 4 public rulesets (network required)
.venv/bin/python3 scripts/00_build_corpus.py
.venv/bin/python3 scripts/02_compile_rulesets.py
.venv/bin/python3 scripts/03_compile_rulesets_yarax.py
.venv/bin/python3 scripts/03b_check_module_support.py
.venv/bin/python3 scripts/04_scan_clean_corpus.py
.venv/bin/python3 scripts/05_diff_yara_vs_yarax.py
.venv/bin/python3 scripts/06_cost_experiment.py
.venv/bin/python3 scripts/07_generate_charts.py

.venv/bin/python3 -m pytest tests/ -v
```

Scripts are numbered in run order and idempotent (re-running just re-fetches
or recomputes). `yara` CLI 4.5.8 must be installed system-wide for the
`yara -S`/`--print-stats` capture step; everything else runs from the venv.

## Method discipline

Every number in this README and in `FINDINGS.md` is read back from a file in
`evidence/`, never typed in from memory. Where a number looked surprising
(the 400-fold difference between the naive and scoped `yara-rules` runs, the
99.99% engine-agreement rate, the identical Q2 timings), it was re-derived
from the raw JSON a second time before being written down, and two real bugs
in my own tooling (a symlink double-count in the corpus builder, and a
rule-declaration counter that silently lost content on a regex-literal edge
case) were caught this way, not by inspection. Where a GUI screenshot could
not be captured reliably (a second Cutter shot on an ARM32 non-PIE binary,
see FINDINGS.md), that failure is reported plainly instead of substituted
with a different image passed off as equivalent.
