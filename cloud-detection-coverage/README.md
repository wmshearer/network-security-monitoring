# Cloud detection coverage

How much of the ATT&CK cloud technique set do SigmaHQ's public cloud rules claim
to cover, and where are the holes.

## The result

```
225 rules under rules/cloud/
152 ATT&CK techniques touching a cloud platform (v19.2)
 52 of those have at least one rule claiming them (34.2%)
100 have none
```

By platform:

| Platform | Covered | Total | |
|---|---|---|---|
| Identity Provider | 30 | 48 | 62.5% |
| IaaS | 44 | 104 | 42.3% |
| SaaS | 29 | 70 | 41.4% |
| Office Suite | 31 | 78 | 39.7% |

**The rules cluster hard.** 65 of the 231 technique claims across all 225 rules
point at Valid Accounts (T1078) and its Cloud Accounts sub-technique (T1078.004).
That is 28% of all claimed coverage aimed at one technique family. Meanwhile 18
techniques rest on exactly one rule each.

IaaS has the largest absolute gap: 60 techniques with no rule.

## What this measures, and what it does not

This measures what rules **claim**. Every Sigma rule tags the ATT&CK techniques
it targets, so cross-referencing those tags against the cloud technique set gives
a claimed-coverage map.

It does not measure what **fires**. A sibling project ran 2,691 Sigma rules
against 834K real Windows events and found 135 fired. That is a much stronger
claim, and it needs an event corpus.

**There is no properly licensed public cloud audit-log corpus to use.** The
flaws.cloud CloudTrail dataset is real, freely downloadable, and contains 1.94M
genuine AWS events spanning 2017 to 2020. It carries no stated licence, no terms
of use, and no LICENSE file. Reachable is not the same as licensed, so it is not
used here.

That makes this a weaker measurement than its sibling, and the weakness is
stated rather than hidden behind a percentage.

## The mistake worth recording

38 of the 225 rules carry no technique-level tag, so they cannot be mapped. The
first one I looked at was tagged `attack.stealth`, and I was ready to write that
up as a malformed tag, since "stealth" was not a tactic name I recognised.

Checking the tactic list in the v19.2 bundle before writing it down: `stealth` is
a current ATT&CK tactic. So is `defense-impairment`, where older material would
say `defense-evasion`. The matrix changed. The rules are fine. My expectation was
stale.

All 38 are tagged at tactic level, which is valid Sigma and simply too coarse to
resolve to a technique. A test pins this so the correction does not get lost.

## Running it

```
python3 src/coverage.py
python3 -m pytest tests/ -q
```

Data is fetched, not vendored:

```
curl -sL -o data/enterprise-attack.json \
  "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
git clone --depth 1 https://github.com/SigmaHQ/sigma.git data/sigma
```

## Sources and licences

- **ATT&CK Enterprise STIX bundle**, v19.2, released 2026-08-05. Version read from
  the bundle's own `x-mitre-collection` object rather than from a release page.
- **SigmaHQ rules**, Detection Rule License 1.1, which is MIT-style and permits
  analysis and publication with attribution. Confirmed by reading the repo's
  LICENSE file.

## Scope

Containers is deliberately excluded from the cloud platform set. Kubernetes runs
in plenty of places that are not a cloud provider, and including it would inflate
the denominator with on-prem workloads.

20 techniques are claimed by cloud rules but are not marked cloud-relevant by
ATT&CK. That is not an error. A rule reading cloud audit logs can legitimately
target a technique whose platform list omits cloud.

A technique having no rule does not mean it is undetectable. It means SigmaHQ's
public corpus does not claim it, and commercial detection content is not in scope
here.
