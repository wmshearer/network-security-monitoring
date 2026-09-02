# IoT-23 Botnet Traffic Classification

How much of a labelled botnet capture can a few readable rules reproduce, and where do
they break? The IoT-23 dataset labels every connection by behaviour (command and
control, denial of service, scanning, or benign). This project writes three plain rules
from the Mirai traffic, then scores them against the dataset's own labels across three
scenarios: Mirai, Torii, and a benign device.

The result is the useful part. The rules are near-perfect on the family they came from,
find nothing on a second family that uses different ports, and raise real false alarms on
a benign device. A rule that scores 1.000 on one capture can score 0.000 on the next.

## What is measured

| Behaviour | Rule | Mirai precision / recall |
|---|---|---|
| Command and control | TCP to port 6667 (IRC) | 1.000 / 1.000 |
| Denial of service | TCP to port 80 (web flood) | 0.996 / 1.000 |
| Scanning | TCP to port 63798 | 1.000 / 0.992 |

On Torii the command-and-control rule scores 0.000 recall, because Torii's C2 is not on
port 6667. On the benign Philips Hue capture the port-80 rule raises 54 false positives
from ordinary web traffic.

## Data

Source: IoT-23 (Aposemat), Stratosphere Laboratory, CTU University. CC BY 4.0.
Cite: Garcia, Parmisano, Erquiaga (2020), IoT-23, Zenodo, doi 10.5281/zenodo.4743746.
The analysis reads the dataset's Zeek labelled connection logs (conn.log.labeled). The
raw data is gitignored. Download the three scenarios from the source above into
`data/<scenario>/bro/conn.log.labeled`.

One parsing note: the Mirai log is fully tab-separated, while the Torii and benign logs
pack the two label fields into the last column separated by spaces. The reader handles
both, checked by a test.

## Running

```
python3 -m pytest                                    # 9 tests
python3 scripts/run_analysis.py data/*/bro/conn.log.labeled
```

## A note on what this claims

The ports here are what this malware family did in these captures, not a signature for
botnets in general. The value is the method: write a rule you can read, score it against
ground truth, and report where it fails. The tests lock the Torii miss and the benign
false positive so neither can be tuned away to make the numbers look better.
