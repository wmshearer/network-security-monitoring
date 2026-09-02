# Network Beacon Analysis

Find command-and-control beaconing in network traffic by timing, then compare
what that finds against what signature detection finds.

Malware calling home leaves a timing signature even when the traffic is
encrypted and the payload is unreadable. This measures that signature, ranks
candidates, and then does the part that matters: ruling out the benign
explanations one at a time.

## Findings

Run against **CTU-13 scenario 42** (Neris botnet, CC BY 2.0, 323,154 packets
over 4.8 hours).

**The top-ranked candidate is the actual bot.** `147.32.84.165` reaching
`31.192.109.167:80` on a 123.5-second interval with 1.9% jitter across 53
connections. CTU's own README documents `147.32.84.165` as the infected Windows
XP host, so this was checked against ground truth rather than asserted.

**Suricata's default configuration found nothing.** 52,415 ET Open rules loaded
successfully and **zero** threat signatures fired. The infected host sits on a
public university address, outside the default RFC1918 `HOME_NET`, and most ET
rules are written `$HOME_NET -> $EXTERNAL_NET`. Correcting one variable took
detections from **0 to 21 signatures**, including explicit malware
identifications. Nothing errored or warned in between.

**The two methods barely overlap.** Of the destinations each flagged: 3 by both,
13 only by timing analysis, 81 only by signatures. The timing-only finds cluster
on port 443 and non-standard ports, which is where signatures have no payload
pattern to match.

Full analysis in [`reports/differential-diagnosis.md`](reports/differential-diagnosis.md).

## Method

Timing regularity is scored per source/destination/port using **median absolute
deviation**, not standard deviation. Beacon traffic routinely has outliers: the
host sleeps, the laptop closes, the network drops. One six-hour gap would wreck
a standard-deviation score while barely moving the MAD.

Jitter is measured **relative** to the interval. A 5-second wobble on a
60-second beacon is noisy; the same wobble on an hourly beacon is nothing.
Scoring absolute deviation would rank every slow beacon above every fast one
regardless of how regular either actually is.

The unit of analysis is a **flow**, not a packet. Counting packets would make a
chatty file transfer look like a fast beacon.

## What this does not do

It does not decide anything is malicious. Regular timing describes NTP,
telemetry, update checks, keepalives and monitoring agents as readily as it
describes malware. The output is a ranking of what to investigate first.

The differential diagnosis is where the actual conclusions come from, and it
deliberately leaves candidates unresolved when the evidence does not settle
them.

## Running it

```bash
python3 scripts/run_analysis.py data/pcaps/<capture>.pcap
python3 scripts/compare_methods.py
python3 -m pytest tests/ -q
```

Captures are downloaded, not vendored. CTU-13 is at
https://www.stratosphereips.org/datasets-ctu13 under CC BY 2.0.

## Tooling note

Zeek would normally produce the connection metadata this analysis needs. It is
not installable on this host: Kali packages 5.1.1, which depends on
`libc6 < 2.38` against an installed 2.42. That is a hard incompatibility rather
than a permissions problem, so `tshark` is used instead, which emits the same
fields.

## Licensing

- Capture: CTU-13, Stratosphere Lab, CTU Prague, **CC BY 2.0**. Cite Garcia et
  al. 2014.
- Signature ruleset: Emerging Threats Open, **MIT**, confirmed via Suricata's
  own `suricata-update` index. Publishing match results with attribution is
  permitted.
- Suricata engine GPL-2.0. Wireshark/tshark GPL-2.0.
