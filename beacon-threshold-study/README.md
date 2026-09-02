# Beacon detection threshold study

How much jitter does a C2 beacon need before a published detection tool stops
flagging it? I set out to find that number. It does not exist, at least not
inside the range any public dataset covers, and what turned up instead is more
useful.

Run against RITA v5.1.2 (Active Countermeasures, GPLv3) using nine labeled
captures that hold the lab environment constant and vary two knobs: callback
delay (10s, 30s, 300s) and jitter (0%, 10%, 25%, 99%).

## Findings

**The tool detects the beacon everywhere in the tested grid.** Every delay,
every jitter level, including 99%. There is no jitter threshold where it goes
blind. That kills the original hypothesis, and it is worth saying plainly rather
than quietly changing the question.

**The perfectly regular beacon is the slowest to alert.** This is the result
worth keeping. At 30 second callbacks with 0% jitter, the beacon's timing is
flawless and RITA's own timestamp subscore says so: a perfect **1.000 in the
first hour**. The composite score is **50.0**, the lowest in the grid. It takes
**5 hours** of observation to cross RITA's "low" alerting band and **6 hours** to
reach "medium."

Every jittered beacon clears 90 inside the first hour.

| delay | jitter | score at hour 1 | timing subscore | hours to reach 70 | hours to reach 90 |
|---|---|---|---|---|---|
| 30s | **0%** | **50.0** | **1.000** | **5** | **6** |
| 30s | 10% | 99.6 | 0.983 | 1 | 1 |
| 30s | 25% | 98.0 | 0.962 | 1 | 1 |
| 30s | 99% | 81.6 | 0.733 | 1 | 9 |
| 10s | 25% | 97.9 | 0.944 | 1 | 1 |
| 300s | 25% | 93.7 | 0.828 | 1 | 1 |

The detector sees the pattern immediately and will not say so for five hours.
The composite score averages four subscores at equal weight, and for the
perfectly regular beacon two of them (duration and histogram) sit at exactly 0
while timing sits at 1.0. That is a scoring artifact, not a perception problem.

**A benign OS service outranks the implant.** `connectivity-check.ubuntu.com`
scores a perfect 1.000 in nearly every capture and renders as **Critical,
100.00%** in RITA's own interface, above the real beacon. Ubuntu's connectivity
checker is a fixed-interval callback to a fixed host, which is what the detector
is built to find. See `evidence/rita-tui.txt` for the tool's own display saying
it.

**Jitter is subtractive, not symmetric.** At a configured 30s delay with 99%
jitter the observed median interval is **15.1 seconds**, not 30. Jitter reduces
the delay rather than varying around it, so "99% jitter" roughly doubles the
callback rate. Anyone reasoning about beacon volume from the configured delay
alone will be off by 2x.

## What is unresolved

**The mechanism behind the 0% jitter result is not identified.** The observation
is verified and reproducible. The cause is not.

RITA recorded only **2 distinct interval values** for the perfectly regular
beacon (30s and 31s, counts 113 and 6) against 4 for the 10% jitter beacon. The
only case with `hist_score = 0` anywhere in the data is the 2-interval case, and
`hist_score` flips from 0 to 1 in the same hour that a third distinct interval
appears.

That correlation is consistent across every dataset here, but it is **not** a
demonstrated cause, and a first attempt to explain it was wrong. I assumed the
distinct-interval list fed the histogram scoring. It does not. Reading the source
(`analysis/beacons.go`), `ts_intervals` is a diagnostic array from
`getTimestampScore`, while the histogram score is built by `createHistogram` from
a 24-bin binning of raw timestamps, computed by different code from different
input. An independent reconstruction of that binning produced 24 populated bins
for both the 0% and 10% datasets, which should score them equally. It does not
match what the tool actually stored.

RITA does not persist the raw timestamp list it feeds into its analyzer, only the
derived intervals, so the reconstruction cannot be replayed exactly against what
the tool really computed. Resolving this needs instrumenting RITA itself rather
than inferring from its stored output.

The relationship is not monotonic either: 4 distinct intervals scores 1.000 while
30 distinct intervals scores 0.529. So "more variety is better" is also wrong.

## Method

Nine capture configurations, each scored at two observation windows.

The captures ship with pre-generated Zeek logs covering both a 1-hour and a
24-hour run, so the whole grid at both windows is about **44 MB**. The packet
captures themselves total roughly 8.2 GB and were not downloaded. They exist to
produce these logs and the publisher already did that. Every archive was verified
against its published SHA256 checksum (`data/SHA256SUMS.published`, all nine
matched).

Zeek would normally generate this connection metadata. It is not installable on
this host: Kali packages 5.1.1, which depends on `libc6 < 2.38` against an
installed 2.42. That is a hard incompatibility, not a workaround, and it is the
same wall the sibling `beacon-analysis` project hit. Using the publisher's own
Zeek logs sidesteps it.

**Ground truth was derived, not assumed.** The publisher never states the lab
addressing. The beacon was identified by finding the one internal host with a
periodic external flow in the 0% jitter capture: median interval **30.0s**, MAD
**0.0s**, across 2,868 connections. That is the configured delay to the tenth of
a second, so the identification is checked against the stated configuration
rather than taken on faith.

RITA stores one row per cumulative hour of observation rather than one row per
dataset, so a single import leaves behind the entire history of what the detector
believed as evidence arrived. `scripts/warmup.py` reads that history out of
ClickHouse. It is what separates "can the detector see this" from "has it seen
enough to say so," which a single final score hides.

## Running it

```
scripts/import_all.sh      # import every log set, export scores as CSV
python3 scripts/analyze.py # the parameter grid
python3 scripts/warmup.py  # the warm-up curves
```

Requires RITA v5.1.2 installed and its containers running. Note that `rita` needs
a full path under sudo, since sudo's PATH excludes `/usr/local/bin`.

## What went wrong along the way

Five explanations, five retractions. The measurements held every time. The
stories about what they meant did not, and none of the errors announced
themselves. Every one produced numbers that looked reasonable.

1. **Matched only the `Destination IP` column.** RITA writes `::` there for any
   row it tied to a hostname and puts the real value in `FQDN`. The matcher
   missed the beacon and silently fell through to unrelated traffic from the same
   host, reporting scores of 0.4 to 0.6 with connection counts of 9 to 282
   against a true 958 to 3,679. Caught by checking counts against the raw logs.
2. **Then matched hostnames.** But the same name does not map to the same address
   across captures. RITA labels the `143.198.3.13` flow `timeserversync.com` in
   one capture with no DNS query in those logs resolving it. Both forms have to be
   checked.
3. **Read the CSV export as the engine's output.** It is a view. Reported "the
   tool fails to detect beacons in short captures" on the strength of a
   low-scoring row, when the database showed the beacon scoring 0.895 to 1.000
   throughout. Nothing was ever missed.
4. **Claimed the CSV merged two rows into a lower-scoring one.** A verifier
   checked and there is no such pair: the row I described as merged already exists
   in the database with that score. The CSV merges nothing.
5. **Blamed a duplicate import.** A clean single import into a fresh database
   reproduced both rows exactly.

The pattern: plausibility is not a check. Each error was caught by querying the
source of truth or by an independent verifier disagreeing, never by the output
looking suspicious.

## Scope and limitations

**This measures one tool against data its own vendor published.** Active
Countermeasures publishes both RITA and these captures. That makes it a fair test
of the tool's stated thresholds and not an independent benchmark.

**Lab traffic, not production traffic.** The background is normal Windows and
broadcast traffic in a clean environment. No corporate NAT, no proxy egress, no
thousands of concurrent users. Any threshold measured here is a best case for the
detector.

**One C2 framework's timing model.** The captures were generated with one
framework's specific jitter implementation. A different implant with a different
random distribution would not necessarily behave the same way.

**The interesting case is not covered by any public data.** A beacon sleeping for
hours with heavy jitter, which is what a patient operator would actually run, is
absent from every public corpus found. The longest delay tested anywhere here is
300 seconds. This study cannot speak to hour-plus intervals, and nothing in it
should be read as if it does.

**No claim about detection in general.** The result is where one open-source
tool's composite scoring lags behind its own timing analysis. A differently
weighted detector would produce a different curve.

**Reuse terms are informal.** The captures carry no formal license. Three checks
found no Terms of Use page exists, nothing restricts reuse, and the posts invite
download. That is weaker than the CC BY 2.0 covering the CTU-13 data used in the
sibling project. Details in `docs/sources.md`.

## Related

- [`../beacon-analysis`](../beacon-analysis) built a median-absolute-deviation
  beacon scorer from scratch and ran it against CTU-13, arriving independently at
  the same MAD-based approach RITA uses. This study measures the published tool
  instead of reimplementing it.

## Reproducing from scratch

The Zeek logs are not committed (a few hundred MB). To rebuild:

```
mkdir -p data/zeek && cd data/zeek
for f in delay_var_d10_j25 delay_var_d30_j25 delay_var_d300_j25 \
         jit_var_d30_j0 jit_var_d30_j10 jit_var_d30_j99 \
         random_d30_j0 random_d30_j25 round_rob_d30_j25; do
  curl -sS -O "https://acm-motd.s3.amazonaws.com/${f}_zeek_logs.zip"
done
sha256sum -c ../SHA256SUMS.published
```

Each archive nests a 1-hour and a 24-hour zip one level down, so extract twice
into `data/logs/<name>_1H/` and `data/logs/<name>_24H/`. Then run
`scripts/import_all.sh`.
