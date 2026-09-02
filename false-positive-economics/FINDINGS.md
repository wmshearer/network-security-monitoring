# Findings

Every number below traces to a named evidence file. Where a number is
computed rather than read directly, the computation is shown so it can be
checked by hand.

## CAVEAT (applies to every section below without exception)

Verbatim from `detection-rule-lab/reports/findings.md`, "## Limitations",
items 1 and 4:

> "These are counts on one corpus, not rates. The benign baseline is a
> single Windows Server 2022 host. A rule that is quiet here may be noisy
> on a workstation fleet, a developer machine, or a domain controller.
> Nothing here supports a claim about any rule's false-positive rate in
> general."

> "Event counts are not alert counts. A rule matching 4,000 events would
> not produce 4,000 alerts in a real SIEM, which would aggregate them.
> Counts here measure match volume, not analyst workload."

Source file: `/home/kali/director/projects/detection-rule-lab/reports/findings.md`
(read-only reference; not modified). SHA-256 of the underlying data file
this project actually reads, `scoring-run.json`, is recorded in
`evidence/source_file_hashes.txt`.

## 1. The corpus, and the anchor case

Source: `detection-rule-lab/reports/scoring-run.json`, key `results`
(135 entries), each with `rule_id`, `title`, `level`, `author`,
`malicious_hits`, `benign_hits`, `precision`. Independently re-read and
recomputed for this project; not transcribed from any prior table.

Recomputation (see `scripts/01_rank_by_noise.py`, function
`build_ranking`, and the raw pass in `evidence/01_ranking.json`):

| Quantity | Value | How it was computed |
|---|---|---|
| Rules loaded | 2,691 | `summary.rules_loaded` |
| Rules fired (any hit) | 135 | `summary.rules_fired`, and `len(results) == 135` |
| Rules touching the benign baseline | 4 | `len([r for r in results if r.benign_hits > 0])` |
| Total benign hits across those 4 rules | 62 | `sum(r.benign_hits for r in those 4)` |
| Benign hits from the top rule alone | 56 | `max(r.benign_hits for r in those 4)` |
| Top rule's share of total benign hits | 90.3% | `56 / 62 * 100 = 90.32258...` |

The four rules touching the benign baseline, exactly as read from the
source JSON (no rows added, none omitted, none re-labeled):

| Rule | Attack hits | Benign hits | Precision |
|---|---|---|---|
| Modification of IE Registry Settings | 0 | 56 | 0.00 |
| Suspicious High IntegrityLevel Conhost Legacy Option | 10 | 2 | 0.83 (2/12 rounds to 0.83) |
| Disable Windows Defender Functionalities Via Registry Keys | 2 | 2 | 0.50 |
| RunMRU Registry Key Deletion - Registry | 2 | 2 | 0.50 |

**The anchor finding:** "Modification of IE Registry Settings" matched 0
attack events across the entire 834,226-event malicious corpus and 56
events on the 110,095-event benign baseline. Its precision is exactly
0.00 (0 divided by 56). This requires no cost model: a rule that has
caught nothing has a cost-per-true-positive of infinity at every possible
per-alert cost greater than zero, because the value captured
(`malicious_hits * value_per_true_positive`) is exactly zero regardless of
what `value_per_true_positive` is assumed to be. This is proven formally
in `scripts/02_breakeven.py`, function `breakeven_triage_minutes`, which
returns `None` whenever `malicious_hits == 0` for exactly this reason, and
confirmed by `tests/test_breakeven.py::test_zero_true_positive_rule_has_no_finite_breakeven`.

Evidence: `evidence/01_ranking.json`, `charts/01_anchor_case.png`,
`evidence/gui/01_ranking.png` (real terminal capture of the script that
produced this table).

## 2. Ranking by noise-to-value (no assumption required)

Method: `noise_to_value_ratio = benign_hits / max(malicious_hits, 1)`,
computed only from measured counts, in `scripts/01_rank_by_noise.py`. When
`malicious_hits == 0` the ratio is flagged `ratio_is_undefined_infinite:
true` rather than reported as a finite number, because dividing by the
`max(mal, 1)` floor would otherwise disguise an undefined value as a
merely-large one.

| Rank | Rule | Attack | Benign | Noise/Value |
|---|---|---|---|---|
| 1 | Modification of IE Registry Settings | 0 | 56 | undefined (infinite) |
| 2 | Disable Windows Defender Functionalities Via Registry Keys | 2 | 2 | 1.00 |
| 3 | RunMRU Registry Key Deletion - Registry | 2 | 2 | 1.00 |
| 4 | Suspicious High IntegrityLevel Conhost Legacy Option | 10 | 2 | 0.20 |

Evidence: `evidence/01_ranking.json`, `evidence/gui/01_ranking.png`.

## 3. Break-even analysis (every input either measured or labeled ASSUMED)

Measured inputs: `malicious_hits`, `benign_hits` per rule, from the same
JSON as section 1.

Assumed inputs, swept, never fixed to one value:

- `triage_minutes_per_alert`: [5, 15, 30, 60] minutes.
- `analyst_hourly_cost`: [$40, $75, $120] per hour (fully loaded cost,
  spanning a junior-tier to senior-tier SOC analyst cost band; this
  range is a labeled assumption, not drawn from any wage survey).
- `value_per_true_positive`: [$50, $200, $1,000] (the value assigned to
  catching one true attack event; not measurable from either corpus and
  not asserted as a real number, only swept to show how sensitive the
  result is to this input).

Formula (see `scripts/02_breakeven.py`):

```
cumulative_triage_cost = (malicious_hits + benign_hits) * (triage_minutes / 60) * hourly_cost
value_captured          = malicious_hits * value_per_true_positive
breakeven_triage_minutes = value_captured * 60 / ((malicious_hits + benign_hits) * hourly_cost)
```

`breakeven_triage_minutes` is undefined (returns `None`) whenever
`malicious_hits == 0`, because `value_captured` is then always exactly
zero and cumulative cost is always strictly positive for nonzero benign
hits: there is no minutes value, however large, at which the two become
equal. This is not a numerical edge case handled awkwardly; it is the
formal statement of "cost-negative at any nonzero assumption."

### 3a. The anchor rule (Modification of IE Registry Settings)

`malicious_hits = 0`. No `breakeven_triage_minutes` exists at any of the 9
combinations of `(hourly_cost, value_per_true_positive)` swept. Confirmed
in `evidence/02_breakeven.json`, entry for this rule:
`cost_negative_at_any_nonzero_assumption: true`, and every one of its 36
sweep entries (4 triage-minute points x 9 hourly/value pairs) has
`cost_justified: false`.

### 3b. The three rules with nonzero precision

Break-even triage minutes, computed exactly (not read off a chart), across
the full 3x3 grid of (`analyst_hourly_cost`, `value_per_true_positive`):

**Suspicious High IntegrityLevel Conhost Legacy Option** (10 attack hits, 2 benign hits):

| hourly \\ value_per_TP | $50 | $200 | $1,000 |
|---|---|---|---|
| $40/hr | 62.5 min | 250.0 min | 1,250.0 min |
| $75/hr | 33.3 min | 133.3 min | 666.7 min |
| $120/hr | 20.8 min | 83.3 min | 416.7 min |

**Disable Windows Defender Functionalities Via Registry Keys** and
**RunMRU Registry Key Deletion - Registry** (both 2 attack hits, 2 benign
hits, so numerically identical break-even table):

| hourly \\ value_per_TP | $50 | $200 | $1,000 |
|---|---|---|---|
| $40/hr | 37.5 min | 150.0 min | 750.0 min |
| $75/hr | 20.0 min | 80.0 min | 400.0 min |
| $120/hr | 12.5 min | 50.0 min | 250.0 min |

**Where the curves actually cross, stated plainly:** at the low end of the
value assumption ($50 per true positive), all three of these rules cross
from cost-justified to cost-negative within a range a real SOC would
recognize as plausible tier-1 triage time: roughly 12.5 to 62.5 minutes
per alert, depending on the assumed hourly cost. At the middle value
assumption ($200), the crossing point rises to 50 to 250 minutes, which is
implausible for routine triage. At the high end ($1,000), it rises further
to 250 to 1,250 minutes, which no SOC would assume for a single alert.

**Is this an interesting finding or a non-finding?** Genuinely mixed, and
reported as such rather than reframed to look sharper in one direction:

- It is **not** a non-finding in the sense the brief describes (curves
  that only cross at implausible extremes like 400 minutes), because at
  the low end of the value sweep the crossing point IS inside a plausible
  range.
- It **is** highly sensitive to an input this project cannot measure
  (the value of catching one true attack event), and at the two higher
  value assumptions the crossing point moves well past anything a real
  SOC would assume. The honest statement is: whether these three rules
  are cost-justified on this corpus depends almost entirely on how much
  the organization believes catching one of these specific attacks is
  worth, a number no corpus can supply.

Evidence: `evidence/02_breakeven.json` (full 4x3x3 sweep per rule, 144
scenario points across the 4 benign-touching rules), `evidence/gui/02_breakeven.png`
(real terminal capture), `charts/02_breakeven_curves_low_value.png`
(crossing visible within plausible range), `charts/03_breakeven_curves_high_value.png`
(no crossing within the charted 90-minute range), `charts/04_breakeven_minutes_grid.png`
(the full 3x3 grid per rule as a bar chart).

## 4. Literature sourcing (the methodology-transparency exhibit)

Full detail: `evidence/literature_sources.json`. Both URLs below were
checked live before being cited:

| Source | URL | HTTP status checked | Usable as a numeric input here? |
|---|---|---|---|
| Alahmadi, Axon, Martinovic, "99% False Positives: A Qualitative Study of SOC Analysts' Perspectives on Security Alarms," USENIX Security 2022 | https://www.usenix.org/system/files/sec22-alahmadi.pdf | 200 | No. The "99%" is one analyst's verbal estimate; the paper itself calls it likely unreliable because analysts use "false positive" inconsistently. Cited here only as an example of how unreliable this kind of self-reported figure is, never as a rate. |
| Sundaramurthy et al., "A Human Capital Model for Mitigating Security Analyst Burnout," USENIX SOUPS 2015 | https://www.usenix.org/system/files/conference/soups2015/soups15-paper-sundaramurthy.pdf | 200 | No numeric input at all; contains no minutes-per-alert or dollar figure. Usable only for the burnout-mechanism narrative. |
| Ponemon Institute / Devo, "2019 State of SOC Report" (n=554) | (checked full text, not cited as a link) | n/a | Rejected. Methodology is disclosed but the report contains no minutes-per-alert figure anywhere; any secondary source citing one from it is fabricating a number the source does not contain. |
| Various AI-SOC vendor blog posts citing "25 minutes per alert" / "30-70 minutes per alert" | (not cited; no single traceable source) | n/a | Rejected. No disclosed methodology or sample in any post checked. Mostly published by vendors selling a replacement for the manual baseline they quote. |
| "Sandia National Laboratories alert-fatigue research" | none found | n/a | **Unverifiable.** Searched four separate ways in prior research; no traceable Sandia publication was found matching this claim. Not cited as a source anywhere in this project. Recorded here only as a claim that could not be confirmed. |

No dollar figure, minutes-per-alert figure, or false-positive rate used
anywhere in this project's `scripts/` or `charts/` is drawn from any
source in this table. All assumed inputs (triage minutes, hourly cost,
value per true positive) are labeled ASSUMPTIONS chosen to span a
plausible range, not values taken from the literature.

## 5. Second corpus: eBPF runtime probes

Source: `ebpf-container-detection/evidence/analysis.json`, key
`false_positive_measurement`. Read-only; not modified.

| Probe | Benign-baseline false positives (measured) |
|---|---|
| `cap_capable` (capability check) | 12,841 |
| ...of which from cpptools/gdb (known dev-tool source) | 1,393 |
| ...of which from other processes | 11,448 |
| namespace | 0 |
| mount | 0 |
| ptrace | 0 |
| sensitive_write | 0 |

Check: `1,393 + 11,448 = 12,841`, confirmed in
`tests/test_ebpf_corpus.py::test_cpptools_gdb_plus_other_equals_total`.

This project's ranking framing (order by measured false-positive count,
no rate claim) applies to these 5 probes exactly the way it applies to
the 135 Sigma rules: `cap_capable` ranks worst by a wide margin, the other
four rank tied for best (zero measured false positives on this window).
No break-even dollar figure is computed for this probe, because the
source project provides no equivalent to "attack hits caught" for the
capability probe in this evidence file; extending the break-even
arithmetic here would require inventing a true-positive count that does
not exist in the source data, which this project will not do.

The source project's own conclusion, quoted from
`ebpf-container-detection/FINDINGS.md`: a detector that "alerts on every
`cap_capable()` call... is not usable as-is; it needs to also correlate
the calling process's cgroup or namespace identity against a known set of
container workloads before the signal is worth acting on."

Evidence: `charts/05_ebpf_probe_comparison.png`, `evidence/source_file_hashes.txt`.

## 6. What would have made this uninteresting, and whether that happened

The project brief states the falsifiable non-finding condition explicitly:
if break-even curves only cross at implausible extremes (400+ minutes per
alert), that is a genuine non-finding and must be reported as such.

That is **not** what happened for the three nonzero-precision rules at
the low end of the value-per-true-positive sweep ($50): those cross at
12.5 to 62.5 minutes, which is inside a plausible tier-1 triage window.
It **is** close to what happens at the high end of the sweep ($1,000):
250 to 1,250 minutes, well past anything plausible. The honest summary is
that the interestingness of this specific result depends on an input this
project cannot supply, and that dependence is itself reported rather than
resolved in either direction.

The one part of this project that is interesting under every possible
assumption, with no sensitivity to anything swept, is the anchor case in
section 1: a rule with 0 measured value and 56 measured false positives.
That is the project's only claim that survives every assumption
simultaneously.
