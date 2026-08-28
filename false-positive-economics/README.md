# False-positive economics

A detection rule that catches an attack is not automatically a good rule.
It also has to be survivable for the people watching it. This project asks
a manager's question, not an engineer's question: **what does a noisy rule
cost the team that has to look at every alert it produces, and can that
team survive it?**

It answers the question using two things that already exist: a labeled
scoring run of 2,691 Sigma detection rules against real Windows telemetry
(`detection-rule-lab`), and a set of eBPF runtime-probe measurements
against ordinary desktop use (`ebpf-container-detection`). Nothing here was
re-measured. Both source files are read once, read-only, and every number
below traces back to one of them by file path.

## CAVEAT (read this before any number below)

This entire project inherits a caveat stated verbatim in
`detection-rule-lab/reports/findings.md`, and it applies to every figure,
chart, and table in this project without exception:

> "These are counts on one corpus, not rates. The benign baseline is a
> single Windows Server 2022 host. A rule that is quiet here may be noisy
> on a workstation fleet, a developer machine, or a domain controller.
> Nothing here supports a claim about any rule's false-positive rate in
> general."

And:

> "Event counts are not alert counts... would not produce 4,000 alerts in
> a real SIEM, which would aggregate them."

**Definitions, since this project assumes no prior detection-engineering
background:**

- **False positive (FP):** an alert that fires on something harmless. The
  analyst has to look at it, decide it is nothing, and move on.
- **True positive (TP):** an alert that correctly caught something real.
- **Precision:** true positives divided by (true positives + false
  positives). A precision of 0.00 means every single hit was a false
  positive; the rule never once caught the thing it exists to catch, on
  this corpus.
- **Triage:** the manual work of looking at one alert and deciding what it
  is. Every alert costs triage time, whether it turns out to be real or
  not.
- **SOC (Security Operations Center):** the team of analysts who watch
  alerts for a living and decide what to escalate.
- **Analyst tier:** SOCs commonly split staff by experience level (tier 1,
  2, 3). Tier-1 analysts usually do the first pass of triage on the
  highest volume of alerts, which is the role this project's break-even
  minutes assumption is meant to represent.

## The anchor case: a rule that caught nothing, 56 times

Of 2,691 Sigma rules run against this corpus, 135 fired at all. Of those
135, only 4 ever touched the benign baseline (produced a false positive).
Together those 4 rules produced 62 false positives. **56 of those 62 (90.3
percent) came from a single rule: "Modification of IE Registry Settings."
That rule matched zero attack events and 56 benign events. Its precision
is 0.00.**

This is the strongest finding in the project and it needs no cost model,
no triage-time assumption, and no hourly-wage assumption to state. A rule
with zero true positives has infinite cost per true positive at any
nonzero per-alert cost whatsoever, because the numerator (value captured)
is exactly zero no matter what happens to the denominator. See
`FINDINGS.md`, section 1, for the full arithmetic and `charts/01_anchor_case.png`
for the chart.

The other three benign-touching rules are not free of cost either, but
they at least caught something: 10, 2, and 2 attack events respectively,
against 2, 2, and 2 false positives each. Their break-even behavior is
the subject of section 2.

## What this project refuses to do

The scoring run's own limitations page says the benign baseline is one
host, and that event counts are not alert counts. Given that, there is
exactly one operation this project will not perform under any
circumstance: **multiplying a per-alert cost by a fleet size, host count,
or analyst headcount to produce a single absolute dollar figure.** That
number would look precise and would be fabricated, because nothing in
either source file measures a fleet, and nothing here licenses projecting
one host's counts onto many. `tests/test_no_fleet_multiplication.py`
enforces this by scanning the codebase for the tokens that operation would
require and failing the build if any appear.

Instead, every dollar figure in this project is either:

1. A **ranking** by measured counts alone (no assumption needed), or
2. A **break-even curve**, swept across a labeled, disclosed assumption
   for triage minutes and analyst hourly cost, never collapsed to one
   point estimate, or
3. A **break-even solve**: at what assumed per-alert cost does a specific
   rule's cumulative triage cost equal the value assigned to what it
   caught.

## Findings, briefly (full detail in FINDINGS.md)

- Anchor case: 1 rule, 0 attack hits, 56 benign hits, 0.00 precision,
  no assumption under which it is anything but cost-negative.
- The other 3 benign-touching rules break even (cumulative triage cost
  equals assumed value captured) somewhere between about 12.5 minutes and
  1,250 minutes of triage time per alert, depending entirely on which
  point in the swept assumption grid is chosen. At the low end of the
  value assumption ($50 per true positive caught), all three cross from
  cost-justified to cost-negative within a plausible tier-1 triage window
  (roughly 12.5 to 62.5 minutes). At the high end ($1,000 per true
  positive), none of them cross within a 90-minute window. **This is
  reported plainly as sensitivity to an unmeasurable input, not
  resolved into a single verdict**, because resolving it would require
  asserting a number ("catching this attack is worth $X") that this
  project has no basis to assert.
- A structurally different detection paradigm, eBPF runtime probes,
  shows the same shape: one probe (`cap_capable`, which watches Linux
  capability checks) produced 12,841 false-positive events over one idle
  desktop measurement window, while four sibling probes produced zero.
  That source project's own conclusion is that the noisy probe "is not
  usable as-is" without adding logic the current version does not have.
  The ranking and break-even framings apply to it the same way they apply
  to the Sigma rules, without changing a single line of the underlying
  math.

## Literature: what the published research actually supports

Research for this project found exactly one number in the entire
public literature on alert-fatigue cost that comes from a peer-reviewed,
methodologically disclosed study, and that same paper flags its own
number as unreliable. The full sourcing table, including what was
checked and rejected, is `evidence/literature_sources.json` and is
reproduced in `FINDINGS.md` section 4. In short:

- USENIX Security 2022 (Alahmadi et al.) is real, disclosed, and
  peer-reviewed, but its famous "99%" figure is one analyst's verbal
  estimate that the paper itself calls likely unreliable, because
  analysts do not use the term "false positive" consistently.
- USENIX SOUPS 2015 (Sundaramurthy et al.) is real, disclosed field
  research on analyst burnout, but contains no minutes-per-alert or
  dollar figure at all.
- A widely-cited Ponemon/Devo report was checked in full text: it does
  not contain the minutes-per-alert figure blogs attribute to it.
- The "25 minutes per alert" and similar figures circulating in vendor
  blogs have no traceable methodology or sample, mostly published by
  companies selling the automation that replaces the baseline they are
  quoting.
- A claim that Sandia National Laboratories published alert-fatigue
  research could not be verified after being checked four separate ways.
  It is not cited here as a source. It is recorded as an unverified
  claim, not as evidence.

No dollar or minutes-per-alert figure in this project's cost model is
taken from any of the sources above. The literature review is included as
a methodology-transparency exhibit, showing what a search for a real
number in this space actually turns up, which is mostly the absence of
one.

## Layout

```
false-positive-economics/
  README.md                    this file
  FINDINGS.md                  every number, traced to its evidence file
  scripts/                     numbered, idempotent, read-only against sources
  evidence/                    raw JSON output from each script, source hashes,
                                literature sourcing table
  evidence/gui/                real terminal captures via termcap.sh
  charts/                      matplotlib charts generated from real data
  tests/                       pytest; SKIP (not FAIL) if a source project is absent
```

## Reproducing this project's numbers

```
python3 scripts/01_rank_by_noise.py          # ranking table, no assumptions
python3 scripts/02_breakeven.py              # break-even sweep, all assumptions labeled
python3 scripts/03_generate_charts.py        # regenerates every PNG in charts/
python3 -m pytest -v                         # 18 tests, all should pass if both
                                              # source projects are present
```

Every script reads `detection-rule-lab/reports/scoring-run.json` and
`ebpf-container-detection/evidence/analysis.json` by absolute path,
read-only. Neither source project is modified anywhere in this codebase.
