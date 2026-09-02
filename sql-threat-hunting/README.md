# SQL threat hunting

Four detections written in SQL, scored against real public captures, with the failures kept in.

The corpus is 74,040 events from eight public packet captures: a Torii botnet infection, a
benign Philips Hue bridge, EternalBlue over SMB, BlueKeep over RDP, and four Active Directory
reconnaissance captures. Nothing is synthetic.

## Run it

```bash
python3 src/ingest.py        # captures -> SQLite, about 2 seconds
python3 scripts/run_all.py   # every query, with its result
python3 -m pytest tests/ -q  # 12 tests
```

## What it found

**The beaconing detector ranks a light bulb above the botnet.** It scores callbacks by how
regular they are. The steadiest thing in the corpus is a Philips Hue bridge checking for
firmware once an hour with 0.07 seconds of deviation. Torii is measurably sloppier, because
malware adds jitter on purpose and a light bulb has no reason to. Precision is 50 percent, and
tightening the threshold drives it to **zero**.

**Grouping by IP address merged three unrelated hosts.** The scanning query reported a scan
window of 98,949,825 seconds, a little over three years. The same RFC 1918 address appears in
three captures recorded in 2017, 2017 and 2020. Fixed by keying every aggregate on
`(capture, ip)`.

**The novelty detector cannot be scored on this corpus.** It flags destinations absent from a
baseline. On these captures it returns only benign results, because Torii's destination set
shrinks from 37 to 32 across the capture. The infection established its channels before
recording began, so the baseline already contains them. It ships labelled unscored rather than
given a flattering number.

**REGEXP availability follows the program, not the SQLite version.** Both the sqlite3 CLI and
Python report version 3.46.1 here. The CLI has REGEXP. Python does not. A Sigma rule using the
`re` modifier will test fine in the shell and then throw at runtime inside a Python pipeline.

Full write-ups in [docs/FINDING.md](docs/FINDING.md).

## What works

Not everything failed.

| Query | Result |
|---|---|
| Scanning | Torii leaves 63.4% of contacted hosts silent, benign leaves 6.3%. Ten to one separation, pointing the right way. |
| Exploit burst | Finds all three attack captures by packets-per-second against one service. No benign false positives. |

## The queries

| File | Pattern | Modelled on |
|---|---|---|
| `01_beaconing.sql` | Callbacks on a schedule | Panther's VPC-flow beaconing search, chained CTEs |
| `02_scanning.sql` | Many targets, mostly silent | Panther's password-spray search, DISTINCT targets |
| `03_exploit_burst.sql` | Dense traffic to one service | Rate-based, the inverse shape of scanning |
| `04_first_contact.sql` | Absent from baseline | Panther's baseline-anomaly search |
| `05_regex_limit.sql` | Where SQL stops | The REGEXP gap, demonstrated |

Constructs used: window functions (`LAG`), chained CTEs, `GROUP BY ... HAVING`,
`LEFT JOIN ... IS NULL` for absence, `NOT EXISTS` for set membership.

## Where SQL loses to Python

Worth stating plainly, because the research found this is what production actually does.

Panther writes rules in Python and uses SQL for scheduled searches over the lake. Matano
detects in Python over ECS-normalised records and queries with SQL afterwards. Only Sigma's
SQLite backend, via Zircolite, treats SQL as the detection language itself.

The split is consistent: **SQL for filtering, grouping and joining at scale. Procedural code
for per-record decisions.** `src/regexp_demo.py` shows the handoff on this corpus. SQL narrows
74,040 events to one candidate SMB conversation in milliseconds. Confirming EternalBlue then
needs the Multiplex ID of a Trans2 response, which is a field inside a packet, and SQL cannot
reach it.

That boundary is the honest answer to "can you do detection in SQL". Some of it, very well.

## Layout

```
src/ingest.py        tshark -> SQLite
src/score.py         beaconing scored against ground truth
src/regexp_demo.py   the REGEXP gap, and the SQL-to-Python handoff
sql/                 the five queries, commented
tests/               12 tests, pinning the findings including the failures
docs/RESEARCH.md     primary-source brief, gathered before any code
docs/FINDING.md      the four findings in full
docs/SCHEMA.md       the table, the ECS mapping, why it is flat
data/captures.json   every capture, its dataset, and why it is included
```

## Data

| Capture | Source | Licence |
|---|---|---|
| Torii botnet, Philips Hue | CTU IoT-23 | Free for research with citation |
| EternalBlue | SANS ISC | Public |
| BlueKeep RDP | BlueKeep PCAPs | Public |
| AD reconnaissance | TinkerSec | Public |

The Philips Hue capture is the control group and the reason three of the four findings exist.
Without benign traffic in the corpus, the beaconing query would have returned five botnet pairs,
scored 100 percent, and shipped as a success.
