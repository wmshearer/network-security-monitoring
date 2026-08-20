# The beaconing detector ranks a light bulb above the botnet

## What happened

The beaconing query looks for callbacks on a schedule. It scores each source and destination
pair by jitter: mean absolute deviation of the gaps, divided by the mean gap. A perfect timer
scores 0.

Run against two CTU IoT-23 captures, one Torii botnet infection and one Philips Hue bridge on
a normal network, it flags 10 pairs. Five are the botnet. Five are the light bulb.

Precision at the obvious threshold is 50 percent.

## The part that matters

Tightening the threshold makes it worse, not better.

| max jitter | flagged | true | false | precision |
|---|---|---|---|---|
| 0.15 | 10 | 5 | 5 | 50.0% |
| 0.10 | 10 | 5 | 5 | 50.0% |
| 0.05 | 6 | 2 | 4 | 33.3% |
| 0.03 | 5 | 2 | 3 | 40.0% |
| 0.02 | 3 | 0 | 3 | **0.0%** |
| 0.01 | 2 | 0 | 2 | **0.0%** |

At 0.02 every surviving hit is the Philips Hue. The most metronomic thing in the corpus is a
smart light checking for firmware updates once an hour, with 0.07 seconds of deviation across
20 intervals. Jitter 0.0000.

The Torii botnet is measurably sloppier. Its best pair sits at 0.028, and its command channel
runs at 0.066 to 0.071.

## Why

Malware authors add jitter on purpose, because a fixed interval is exactly what detection
looks for. Embedded devices do not care. A Hue bridge polls on a hardware timer with no reason
to hide, so it produces a cleaner signal than the thing that is actually trying to hide.

"More regular" therefore does not mean "more suspicious". It can mean the opposite. Ranking
purely by regularity ranks well-behaved appliances first.

## What this means for the detection

Jitter alone is not a detector. It is one feature that needs at least one more to be useful:

- **Destination reputation.** The Hue talks to AWS and Philips infrastructure. Torii talks to
  hosts with no business relationship to the device.
- **Port and protocol sense.** NTP on 123 at a steady 65 seconds is a clock doing its job.
- **Volume.** 17,149 intervals on one pair is not a status check.
- **Whether the destination is known at all.** The strongest available filter, and it lives in
  asset inventory, not in the packet capture.

The honest conclusion is that this query is a triage aid, not an alert. It narrows 74,040
events down to 10 pairs worth a human look, and a human resolves five of them in seconds by
recognising the vendor.

## Why it is in the project at all

Because the corpus has a benign control group. Without the Philips Hue capture, the query would
have returned five botnet pairs, scored 100 percent, and shipped as a success.

The control group is what turned a flattering result into a real one. That is the argument for
always carrying benign traffic in a detection corpus, and it generalises well past this query.

## Reference

Splunk's PEAK framework names this failure mode directly. Its guidance on stack counting warns
that "common is good, uncommon is bad" is an anti-pattern, because attackers blend into common
behaviour and defenders mistake unusual-but-benign for hostile. This result is the same error
seen from the other side: a benign device that is unusually regular outranks malware that is
deliberately irregular.

Source: splunk.com/en_us/blog/security/peak-baseline-hunting.html
