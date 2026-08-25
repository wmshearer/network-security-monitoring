# Detection methodology

Three projects about the same question: does a detection actually work, and how
would you know?

Writing a detection is easy. Deploying a ruleset is easy. Measuring which rules
catch attacks, which flood the queue, and which never fire at all is the part
that gets skipped, and it is the part these three are about.

## The projects

| Project | What it measures |
|---|---|
| [detection-rule-lab](detection-rule-lab/) | What a community detection ruleset actually does against real telemetry, rather than what its rule count implies. |
| [sql-threat-hunting](sql-threat-hunting/) | Four detections written in SQL and scored against 74,040 events from eight public captures, with the failures kept in. |
| [sql-vs-python-detection](sql-vs-python-detection/) | The same seven rules run through two different engines, to separate the rules from the tooling. |

## The results

**detection-rule-lab: 135 of 2,691 rules fired.** Roughly 95 percent of a large
community ruleset produced nothing against the corpus, with the obvious objection
(that the corpus lacked the right attacks) controlled for. Adding one more
capture changed the answer by a factor of four, which is why the project argues
you have to test the corpus before you trust the score.

**sql-vs-python-detection: the engine made no difference at all.** Seven rules,
2,810 prompts, run once in Python and once in SQL. Precision 99.70 percent,
recall 71.81 percent, F1 83.49 percent. Identical to two decimal places in both
engines. The rules were the whole story, and the implementation language was
noise. That is a useful negative result: it means a language debate about
detection tooling is usually the wrong argument.

**sql-threat-hunting** keeps its misses in the write-up rather than reporting
only the detections that worked.

## What none of this claims

- Every corpus here is a public capture set, not production traffic. Rates
  measured against them do not transfer to a real environment without
  re-measuring.
- A rule that does not fire is not automatically a bad rule. It may target
  something absent from the corpus, which is exactly why detection-rule-lab
  controls for that rather than assuming it.
- Precision and recall are computed against labelled data. Where labels are
  weak, each project says so rather than reporting the number alone.
