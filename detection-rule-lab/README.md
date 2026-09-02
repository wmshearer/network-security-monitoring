# Detection Rule Lab

Measure what a community detection ruleset actually does against real telemetry.

Deploying a detection ruleset is easy. Knowing which of its rules catch attacks,
which flood the queue with noise, and which do nothing at all is the part that
takes measurement. This runs every Windows Sigma rule against a labeled corpus and
counts, per rule, how many attack events it fires on and how many ordinary events
it fires on.

## Result of the current run

| | |
|---|---|
| Sigma rules evaluated | 2,691 |
| Malicious events | 834,226 |
| Benign events | 110,095 |
| Rules that fired at all | 135 (5.0%) |
| Rules that never fired | 2,556 (95.0%) |
| Rules firing only on attacks | 131 |
| Rules firing on the benign baseline | 4 |

The obvious objection to 95% silence is that the corpus must lack the event types
those rules need. That is controlled for and is not the explanation: **94.6% of the
ruleset targets EventIDs the corpus actually contains.** Those rules saw eligible
events and did not match.

Full tables, per-rule counts, and the limitations section are in
[`reports/findings.md`](reports/findings.md). An ATT&CK Navigator layer covering the
82 techniques with at least one firing rule is in
[`reports/attack-navigator-layer.json`](reports/attack-navigator-layer.json).

## How it works

1. **Export.** The labeled corpus is loaded through the
   [ai-triage-engine](../ai-triage-engine)'s normalization and contamination
   controls, then written as JSON lines. Those controls matter: the malicious and
   benign sources use different collection stacks, and without stripping the
   collection artifacts the two classes are separable by which tool captured them
   rather than by behaviour.
2. **Execute.** Each class is scored in a separate Zircolite run. Zircolite compiles
   each Sigma rule to SQL and runs it against the events in SQLite, which is what
   produces per-rule, per-event match output.
3. **Join.** The two runs are joined by Sigma rule id to get malicious and benign
   counts for every rule.

Classes are scored separately because Zircolite has no notion of a label, so a mixed
input gives no reliable way to attribute a match back to a class.

## Running it

```bash
source ../ai-triage-engine/.venv/bin/activate
pip install -r vendor/Zircolite/requirements.txt
python3 scripts/run_scoring.py
python3 -m pytest tests/ -q
```

Zircolite is vendored rather than pip-installed: it is not on PyPI, and installing
from a clone fails because setuptools rejects its flat layout. It runs as a script.

## What this does not claim

- **These are counts on one corpus, not rates.** The benign baseline is a single
  Windows Server 2022 host. A rule quiet here may be noisy on a workstation fleet.
  Nothing here supports a claim about any rule's general false-positive rate.
- **A silent rule is not a bad rule.** It may target behaviour this corpus never
  performed. Silence measures the corpus and the rule together.
- **Event counts are not alert counts.** A real SIEM would aggregate.

## Licensing

Detection rules are SigmaHQ under **Detection Rule License 1.1**, which requires
per-rule author attribution wherever matches are displayed. Zircolite's output does
not carry the author field, so it is backfilled from the ruleset and every published
table names the rule's author. Zircolite is LGPL. Attack telemetry is OTRF
Security-Datasets (MIT); benign telemetry is NextronSystems evtx-baseline
(Apache-2.0).
