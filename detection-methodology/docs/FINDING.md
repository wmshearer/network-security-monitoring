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

---

# A second finding: reused private addresses merged three hosts into one

## What happened

The scanning query grouped by `source_ip` and reported a scan window of 98,949,825 seconds for
192.168.1.46. That is three years and two months, which is not a scan.

The cause: 192.168.1.46 appears in three separate captures, recorded in March 2017, May 2017
and April 2020. RFC 1918 space gets reused on every network on earth, so the same private
address in two captures is almost never the same machine. Grouping on the address alone welded
three unrelated hosts into a single identity and then measured the time between them.

## The fix

Key every aggregate on `(capture, ip)` rather than `ip`. In a production data lake the
equivalent key is `(tenant, sensor, ip, time_window)`, since an address only identifies a host
within a scope and a period.

After the fix the AD host correctly disappears from the results. It never reached three
distinct targets inside any single capture. The earlier appearance was an artefact of the merge.

## Why it is worth writing down

The number was absurd enough to notice. A subtler version of the same bug is not. If two
captures had been a week apart rather than three years, the window would have looked plausible
and the merged host would have shipped as a finding.

Any corpus assembled from more than one capture, or any SIEM ingesting more than one network,
has this problem waiting in it. The fix costs one column in a GROUP BY.

## What survived the fix

The discriminator itself held up. Torii leaves 63.4 percent of the hosts it contacts silent.
The benign Philips Hue leaves 6.3 percent. That is a ten-to-one separation on real traffic,
and unlike jitter it points the right way: the malicious host scores higher.

Silence ratio is a better beaconing companion than regularity, which is the practical lesson
from putting the two queries side by side.

---

# A third finding: the novelty detector fires only on the benign host

## What happened

The first-contact query builds a baseline from the first half of each capture, then flags
destinations that appear only in the second half. It is modelled on Panther's baseline-anomaly
search.

On this corpus it returns three results. All three are the benign Philips Hue bridge. It finds
nothing at all in the Torii botnet capture.

## Why

Counting distinct destinations either side of the midpoint explains it:

| capture | destinations, 1st half | destinations, 2nd half |
|---|---|---|
| Torii (malicious) | 37 | 32 |
| Philips Hue (benign) | 13 | 16 |

Torii's destination set **shrinks**. The infection established its channels before the capture
started and then kept using them. There is no first contact to catch, because first contact
happened before anyone was watching.

The Hue's set grows, because a consumer device on a live network keeps meeting new CDN
endpoints, NTP servers and API hosts over a day.

## The lesson

Novelty detection depends entirely on the baseline containing a genuinely clean period. Here
the "baseline" is just the first half of a capture that was already compromised throughout, so
the malicious channels are inside the baseline and are therefore invisible by construction.

This is not a bug in the query. It is a bug in what the query can be asked on this data. The
detection is sound and the corpus cannot support it.

Stated plainly: **the first-contact query is unscored on this corpus.** Reporting it as a
detection with a precision figure would be dishonest, because the only number available is
"three false positives and no true positives", and that number measures the capture rather than
the query.

## What it would need

A baseline drawn from a period known to be clean, which in practice means either a capture
recorded before infection or an environment with an established asset inventory. Neither exists
in a public IoT-23 capture that starts mid-infection.

Kept in the project because knowing when a detection cannot be evaluated is part of detection
engineering, and quietly dropping it would leave the set looking tidier than the work actually was.
