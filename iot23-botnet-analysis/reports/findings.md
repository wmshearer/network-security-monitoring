# IoT-23 botnet traffic: how far do a few readable rules get you

## Question

The IoT-23 dataset labels every connection in a captured botnet as benign or as a
specific behaviour: command and control, a denial of service flood, or scanning. If a
detection engineer wrote a few plain rules by reading the traffic, how much of that
labelling would the rules reproduce? And where would they fall down? The point is to
end with a real precision and recall number measured against the dataset's own labels,
not a story about one clever packet.

## Data

Source: IoT-23 (Aposemat), Stratosphere Laboratory, CTU University. CC BY 4.0.
Cite as: Garcia, Parmisano, Erquiaga (2020), IoT-23, Zenodo, doi 10.5281/zenodo.4743746.
Three scenarios, using the dataset's own Zeek labelled connection logs:

- Mirai (Capture 34-1): 23,145 connections. 21,222 malicious, 1,923 benign.
- Torii (Capture 20-1): 3,209 connections. 16 malicious, the rest benign.
- Philips Hue honeypot (Capture 4-1): 452 connections, all benign.

One note on reading the files: Mirai writes the two label columns as their own
tab-separated fields, while Torii and the benign capture pack them into the last field
separated by spaces. Reading the label from a fixed column number works on one and
returns the wrong thing on the other. The reader handles both, and a test checks that
the counts match on each format.

## The rules

Three rules, taken from what the Mirai traffic actually does:

- TCP to port 6667 is command and control. This family runs its C2 over IRC.
- TCP to port 80 is the denial of service flood. The bots hammer a victim's web port.
- TCP to port 63798 is scanning.

Everything else is left unlabelled on purpose. A rule that guessed on traffic it has no
signal for would score well by luck.

## What the rules got right, and where they broke

### Mirai: the rules reproduce the labels almost exactly

| Behaviour | Precision | Recall |
|---|---|---|
| Command and control | 1.000 | 1.000 |
| Denial of service | 0.996 | 1.000 |
| Scanning | 1.000 | 0.992 |

Against the family they were read from, the rules are close to perfect. That is the
easy part, and on its own it would be a misleading result to publish.

### Torii: the same rules find nothing

Torii's command and control does not use IRC on port 6667. So the C2 rule that scored a
perfect 1.000 on Mirai scores a recall of 0.000 on Torii. It catches none of the 16
malicious connections. A rule tuned to one family can be blind to the next one. This is
the main finding of the project, and it is why the "test the corpus before you trust the
rule" habit matters.

### The benign device: a real false positive

The Philips Hue capture is all benign, but the device makes ordinary web connections to
port 80. The naive "TCP port 80 is a flood" rule flags 54 of them. In a real environment
that is 54 alerts a analyst has to clear, from one small device over a short capture. The
DDoS rule needs more than a port before it is safe to run.

## Limits

The ports here are what this malware family did in these captures. They are not a
signature for botnets in general. A different sample would need its own reading. The
value is the method: write a rule you can explain, score it against ground truth, and
report where it holds and where it fails, rather than trusting it because it sounds
right. Nine tests lock the counts and, importantly, lock the Torii failure and the benign
false positive so neither can be quietly tuned away.

## Related

Sibling to [beacon-analysis](../beacon-analysis/), which detects one botnet's C2 by the
regularity of its timing. This one works from the dataset's own labels across several
behaviours and several families, and measures how well simple rules reproduce them. The
beacon project asks "is this one host beaconing"; this one asks "how well do readable
rules generalise across families", and finds that they do not, cleanly.
