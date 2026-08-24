# Phase 2 findings: STP robustness score vs Zircolite behavioural result

## The question

splunk-detection-lab published a Summiting the Pyramid (STP) Analytic Robustness
score for each of its 6 SPL detections, reasoned by hand from the rule's logic:
D1=4, D2=1, D3=1, D4=1, D5=2, D6=2 (source:
`/home/kali/director/projects/splunk-detection-lab/evidence/robustness/stp_scores.csv`).
A score of 1 means the rule matches attacker-chosen literal text with no
relationship to the technique; a score of 4 means the rule matches something the
technique cannot avoid touching.

This phase asks: does an independent tool, actually running the detections
against real captured data, agree that the low-scored rules (D2/D3/D4) behave
differently from the high-scored rule (D1)? Zircolite compiles each Sigma rule
to SQL and executes it against events loaded into SQLite (confirmed working
pattern from `/home/kali/director/projects/detection-rule-lab`), so it can
measure true-positive and false-positive hits directly, which is a different
kind of evidence than STP's structural reasoning about evadability.

## What was measured

Sigma-equivalent rules were written for all 6 SPL detections
(`sigma_rules/splunk_detection_lab/*.yml`), each translating the original SPL
field for field (see each rule's own `description:` for the exact SPL it
mirrors). They were run with Zircolite against:

- **Attack data (true positive check):** the 5 real converted attack capture
  files in `splunk-detection-lab/data/converted/attack/` (50,859 events total,
  OTRF/Mordor captures of Empire and Metasploit techniques).
- **Benign data (false positive check):** the 94 real converted benign files in
  `splunk-detection-lab/data/converted/benign/` (242,133 events total, a single
  Windows Server 2022 baseline host, NextronSystems evtx-baseline).

Full command output is in `reports/phase2_zircolite_stp_crosscheck.json`.

## Result

| Rule | STP score | Attack hits | Benign hits |
|---|---|---|---|
| D2 Schtasks hidden PowerShell | 1 | 1 | 0 |
| D3 Net localgroup admins | 1 | 2 | 0 |
| D4 Net user enumeration | 1 | 2 | 0 |
| D5 Process access AUDIODG | 2 | 74 | 0 |
| D6 PowerShell spawns recon tool | 2 | 3 | 0 |
| D1 Registry Run key SetValue | 4 | 2 | 0 |

**6 of 6 rules fired on the real attack data.** That is a genuine, if modest,
confirmation: every one of these hand-written detections has at least one real
event in this corpus that triggers it, independent of the STP score.

**0 of 6 rules fired on the real benign data, at every STP score level.**

## Are the two measures directly comparable? No, and here is why

The STP score and the Zircolite benign-hit count did **not** disagree in the
sense of pointing opposite directions. They simply could not be compared on
this corpus, because the benign corpus contains **zero occurrences of the
specific processes and registry paths these rules key on**, confirmed directly
(`scripts/phase2_benign_eligibility_check.py`,
`reports/phase2_benign_eligibility.json`):

- 2,030 EventID 1 (process creation) events exist in the benign corpus. Zero of
  them run `net.exe`, `net1.exe`, or `schtasks.exe`, the exact binaries D2, D3,
  D4, and D6 filter on.
- 6,194 EventID 10 (process access) events exist. Zero of them touch
  `AUDIODG.EXE`, what D5 filters on.
- 66,675 EventID 13 (registry SetValue) events exist. Zero of them write under
  a `\Run\` key, what D1 filters on.

This is a real property of the corpus (one Windows Server 2022 host, one
capture window), not a bug in the rules, the field mapping, or Zircolite. The
eligibility check confirms the right event TYPES are present in real numbers;
the specific process names and paths these 6 rules were written around simply
never occurred on this host during this capture.

**The honest conclusion: this Zircolite run cannot confirm or contradict the
STP scores, because it never gave the STP-weak rules (D2/D3/D4, literal
command-line text with no technique-inherent link) a chance to produce a false
positive.** A rule scoring 1 on STP is exactly the kind of rule expected to
fire on ordinary admin activity elsewhere (someone running `net localgroup
administrators` by hand, a legitimate scheduled task that happens to mention
PowerShell), but this specific benign host never ran that kind of activity in
this window. Reporting "0 false positives" as if it validated the STP scoring
would be the false equivalence the task explicitly warned against forcing.

What Zircolite DID independently confirm, on its own terms: every rule has a
real, working match against the exact attack behavior it claims to detect.
That is evidence pySigma-level conversion and field logic are correct end to
end (SPL logic to Sigma to compiled SQL to a real match), which is a smaller
but still real claim, separate from anything about robustness or false-positive
rate.

## What would actually test the STP hypothesis

A benign corpus that contains ordinary, non-attacker use of `net.exe`,
`schtasks.exe`, and PowerShell (a fleet of real admin workstations, not one
server host) would be the corpus that could actually confirm or refute
whether the STP-weak rules are noisier than the STP-strong one. That data does
not exist locally in this portfolio; building or sourcing it is out of scope
for this project (see README "What this cannot claim").
