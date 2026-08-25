# Research brief: how SQL is actually used for threat detection

Gathered 2026-08-20 from primary sources before any code was written. This file exists so the
project can be checked against what practitioners really do, not against what sounds right.

## The finding that shaped the whole project

**Pure-SQL detection is rarer than expected.** The dominant production pattern is a split:
SQL does filtering, aggregation and joining at data-lake scale, and a thin procedural layer
does the per-record decision.

- **Panther**: rules are Python or YAML. Scheduled Rules pair a SQL search with a small Python
  function that runs per returned row. Their own docs say to "do as much data processing as
  possible in SQL... to take advantage of database optimizations."
- **Matano**: real-time detections are Python functions over ECS-normalised records. SQL is used
  after detection, to query the alerts table.
- **Sigma / pySigma-backend-sqlite / Zircolite**: this is the one place SQL genuinely IS the
  detection language. Zircolite runs Sigma rules as pure SQLite queries with no other engine.

So a project claiming "SQL replaces Python for detection" would be wrong and would read as
naive. The honest project demonstrates the split, and shows where each side wins.
Sources: docs.panther.com/detections/rules, github.com/matanolabs/matano,
pypi.org/project/pySigma-backend-sqlite, github.com/wagga40/Zircolite

## Constructs that recur in real published queries

| Construct | Where it appears |
|---|---|
| CTEs (`WITH`) | Panther beaconing, baseline-anomaly, DNS tunnel. Near universal. |
| `GROUP BY ... HAVING` | The single most common construct across every real example found. |
| Window functions (`LAG`, running `COUNT() OVER`) | RunReveal impossible travel, Datadog brute-force guide. |
| Array aggregation | Panther baseline anomaly, building per-actor behavioural baselines. |
| JSON / VARIANT field access | Panther's Okta example. Semi-structured columns are the norm. |
| `LEFT JOIN ... IS NULL` | The standard idiom for "this did not happen". |
| Sigma correlation rules | `event_count`, `value_count`, `temporal`, `temporal_ordered`. |

**Self-joins for lateral movement: NOT verified.** No verbatim production query was found from
a named practitioner. Only conceptual descriptions and patents. The research flagged this
explicitly as inference. The project must not present a multi-hop chain query as standard
practice.

## Canonical patterns, with their real shape

- **Password spray**: Panther's actual query groups failures by region and hour and flags
  `COUNT(DISTINCT username) > 5 AND COUNT(*) > 10`. Breadth over depth. That distinction
  (spray vs brute force) is what a naive "too many failures" query misses.
- **Failed then successful auth**: Sigma's `temporal_ordered` correlation is the canonical
  sourced pattern. Order matters and plain aggregation cannot express it.
- **Impossible travel**: `LAG` partitioned by user, ordered by time, then distance over elapsed
  time. RunReveal uses roughly 600 mph as the threshold, above commercial cruise speed.
- **Beaconing**: Panther's production example is a two-stage CTE. Bucket by day and source,
  keep sources with few connections that day, then count how many days showed that pattern.
  Threshold and persistence, not statistical jitter math.
- **Rare process / stack counting**: `GROUP BY ... ORDER BY COUNT(*) ASC`. Splunk's PEAK
  framework names "common is good, uncommon is bad" as an explicit ANTI-pattern, because
  attackers blend in and compromises touch multiple machines. The caveat has to be on the page.

## SQLite limits, verified against sqlite.org

| Feature | Status |
|---|---|
| Window functions | Yes, since 3.25.0 (2018). Cannot use DISTINCT, cannot appear in WHERE. |
| CTEs | Yes, long available. |
| Recursive CTEs | Yes. Enhanced 3.34.0. **Cannot use aggregate or window functions inside the recursive SELECT.** No built-in cycle protection or depth guard. |
| JSON functions | Yes in modern SQLite. |
| `REGEXP` | **NOT built in.** sqlite.org: "No regexp() user function is defined by default and so use of the REGEXP operator will normally result in an error message." Must be registered at runtime. |

The REGEXP gap matters. pySigma-backend-sqlite maps Sigma's `re` modifier straight to REGEXP,
which errors at runtime unless the host registers a Python function first. Showing that
registration explicitly is a checkable sign of having actually run the queries.

Local environment confirmed: SQLite 3.46.1, so every feature above is available.

## What would look naive to a practitioner

Taken directly from the research, and treated as a checklist for this project:

1. A flat `SELECT * WHERE failed_logins > N` with no time bucketing and no spray/brute-force
   distinction.
2. Claiming SQL solves lateral movement with an unbounded recursive CTE and no cycle guard.
3. Using REGEXP in SQLite without showing that it needs runtime registration.
4. Treating "rare equals malicious" uncritically, without the PEAK caveat.
5. Building a fully normalised star schema for log data. Real platforms use wide,
   semi-structured tables. Third normal form here reads academic, not production.

## Decisions this brief drove

- The events table is **wide and flat**, not a star schema, matching Panther and Matano.
- Field names follow **ECS** with dots replaced by underscores, mapped in `docs/SCHEMA.md`.
- The beaconing query uses **CTE chaining**, matching Panther's published shape.
- Lateral movement stops at **one hop**, with the reason written on the page, because the
  multi-hop pattern is unverified and recursive CTEs cannot carry window functions anyway.
- The **REGEXP registration is shown**, not hidden.
- The stack-counting query **carries the PEAK caveat inline**.
- The project ends with an honest section on **where SQL loses to Python**, since the research
  showed that split is the actual production architecture.

## Flagged as uncertain by the research, and how the project handles it

- Multi-hop lateral movement SQL is unsourced. Project stops at one hop and says why.
- OCSF to relational mapping is inferred, not stated by OCSF docs. Project uses ECS naming
  instead and does not claim OCSF conformance.
- "SQL is worse at X" is mostly architectural inference rather than direct practitioner quotes,
  except the regex point which has a named source. Project states this as observed
  architecture, not as a quoted claim.
