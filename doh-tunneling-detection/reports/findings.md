# DoH tunneling detection: what actually generalizes

## What DoH tunneling is, and why payload inspection doesn't work

DNS-over-HTTPS (DoH) wraps ordinary DNS queries inside an HTTPS
connection. It was designed for privacy: a network observer normally sees
every domain a device looks up in plaintext, and DoH hides that behind
TLS the same way a web request to any HTTPS site is hidden. That's the
intended use.

The same property makes DoH a convenient tunnel. Tools like dns2tcp,
dnscat2, iodine, dnstt, tcp-over-dns, and tuns can carry arbitrary traffic
(a shell, a file transfer, a whole TCP session) encoded as DNS queries and
responses, and once that's wrapped in DoH, the tunnel looks like normal
encrypted DNS traffic to anything watching the wire. You cannot open the
TLS record and check whether the DNS query inside it is a real hostname
lookup or 200 bytes of tunneled shell output, because that's exactly what
TLS is for. Signature and payload-based detection are out. What's left is
traffic shape: how big the packets are, how often they arrive, how long a
flow lasts, how much data moves each direction. That's the same idea
behind detecting C2 beaconing from connection timing (see
`network-beacon-analysis` in this workspace) applied to a different
signal.

## The dataset

CIRA-CIC-DoHBrw-2020 combined with the DoH-Tunnel-Traffic-HKD extension
(MontazeriShatoori et al. 2020; Mitsuhashi et al. 2022). Full citation and
download instructions are in `data/README.md`. The relevant file is
DoHLyzer-extracted flow statistics: 374,459 flows after dropping a small
number of rows with missing values, 19,746 benign and 354,713 malicious,
split across six tunneling tools (dns2tcp, dnscat2, iodine, dnstt,
tcp-over-dns, tuns). Every flow has the same 34 columns: five identity
columns (source/destination IP and port, timestamp) and 29 behavioral
statistics (packet-size stats, inter-packet-timing stats, DoH
response-time stats, duration, byte counts and rates).

## The leak

This dataset has a structural problem that makes a naive evaluation
worthless, and it's worth being specific about what it is rather than
waving at "IP addresses might leak."

The benign captures and the malicious captures were run as separate
sessions, each with its own fixed client machines. Checked directly
against the CSV (`tests/test_leak_audit.py`, real-data tests): benign
client IPs are `192.168.20.111`, `.112`, `.113`, `.191`. Malicious client
IPs are `192.168.11.12`, `.16`, and `192.168.20.144`, `.204`
through `.212`. Zero overlap. There's a second layer to this too: the six
tunneling tools split into two groups by client subnet. dns2tcp, dnscat2,
and iodine all ran from the `192.168.20.x` range; dnstt, tcp-over-dns, and
tuns all ran from `192.168.11.x`. (Public DoH resolver IPs like
Cloudflare's `1.1.1.1` and Google's `8.8.8.8` do appear on both the
benign and malicious sides, but that's just every DoH client, tunneling
or not, talking to the same handful of public resolvers. It isn't
client-identity leakage and doesn't undermine the disjoint-client-IP
finding above.)

Given that, a model handed `SourceIP`, `DestinationIP`, `SourcePort`,
`DestinationPort`, or the absolute `TimeStamp` doesn't need to learn
anything about what tunneling traffic looks like. It can just memorize
"which address range is this," and under a random train/test split, where
rows from the same capture session land on both sides, that shortcut
alone gets you most of the way to a perfect score. The reported accuracy
would be real in the narrow sense that the math is correct, and meaningless
in the sense that matters: it would tell you nothing about whether the
model can recognize tunneling traffic it hasn't specifically memorized the
source machine for.

This is the same failure mode documented in this workspace's
`ai-triage-engine` project (see `research/phase-1b-shortcut-mitigation.md`
there), where two log sources differing only in collection pipeline
produced a "year of capture" feature that alone hit 100% accuracy. Arp et
al. ("Dos and Don'ts of Machine Learning in Computer Security," USENIX
Security 2022) name this pattern directly: Pitfall #4, Spurious
Correlations, their own worked example being a model that learns IP
ranges instead of attack behavior. Same problem, same fix.

## The honest methodology

**1. Drop every identity/session feature before training.** Not "be
careful with," drop entirely: `SourceIP`, `DestinationIP`, `SourcePort`,
`DestinationPort`, `TimeStamp`. `src/data.py` defines these as
`DROPPED_LEAKY_FEATURES`, and `DoHDataset.feature_matrix()` is the only
method that produces a training matrix; it only ever selects from the 29
`BEHAVIORAL_FEATURES`, so the leaky columns are never reachable from
model-facing code, not just documented as forbidden.

Kept (29 behavioral features): `Duration`, `FlowBytesSent`,
`FlowSentRate`, `FlowBytesReceived`, `FlowReceivedRate`,
`PacketLengthVariance`, `PacketLengthStandardDeviation`,
`PacketLengthMean`, `PacketLengthMedian`, `PacketLengthMode`,
`PacketLengthSkewFromMedian`, `PacketLengthSkewFromMode`,
`PacketLengthCoefficientofVariation`, `PacketTimeVariance`,
`PacketTimeStandardDeviation`, `PacketTimeMean`, `PacketTimeMedian`,
`PacketTimeMode`, `PacketTimeSkewFromMedian`, `PacketTimeSkewFromMode`,
`PacketTimeCoefficientofVariation`, `ResponseTimeTimeVariance`,
`ResponseTimeTimeStandardDeviation`, `ResponseTimeTimeMean`,
`ResponseTimeTimeMedian`, `ResponseTimeTimeMode`,
`ResponseTimeTimeSkewFromMedian`, `ResponseTimeTimeSkewFromMode`,
`ResponseTimeTimeCoefficientofVariation`.

Dropped (5 identity/session features): `SourceIP`, `DestinationIP`,
`SourcePort`, `DestinationPort`, `TimeStamp`.

**2. Validate with leave-one-tool-out, not random k-fold.** Train on
flows from two tunneling tools plus most of the benign traffic, test on
the third tool the model has never seen a single example of, plus a
benign sample held out the same way for every fold. This is implemented
in `src/evaluate.py::leave_one_tool_out_eval`, and it's the real question
a detector has to answer in production: not "can you recognize a tool you
were trained on," but "does whatever you learned about tunneling
generalize to a tool that didn't exist in your training data."

**3. Also report the random-split number, explicitly labeled as
inflated.** Not to bury it, to show the gap. If the honest number and the
leaky number matched, that would be worth reporting too. They don't.

**4. Keep the model simple.** Logistic regression as the headline model
(standardized inputs, so coefficient magnitude is a fair proxy for
feature importance), a random forest run alongside it for a second,
non-linear view of which features carry weight. Neither is tuned for a
better number; both use a fixed random seed (`RANDOM_STATE = 42` in
`src/model.py`) so results are reproducible.

## Results

Full numbers in `reports/results.json`, produced by
`scripts/run_analysis.py`.

| Model | Random split (leaky) | Leave-one-tool-out mean (honest) | Gap |
|---|---|---|---|
| Logistic regression | 95.8% | 72.9% | 22.9 points |
| Random forest | 99.9% | 78.9% | 21.1 points |

The random forest's leaky number, 99.9%, is the kind of result that
should set off alarms on its own: a model getting DoH tunnel detection
almost perfectly right is a sign something's wrong with the evaluation,
not a sign the model is good. It's the number this whole methodology
exists to avoid reporting as the answer.

The leave-one-tool-out breakdown, per tool held out (logistic regression):

| Held-out tool | Accuracy | Precision | Recall | Test rows |
|---|---|---|---|---|
| dns2tcp | 11.9% | 97.5% | 9.0% | 173,211 |
| dnstt | 54.6% | 97.2% | 50.2% | 52,004 |
| iodine | 87.5% | 98.4% | 87.3% | 52,448 |
| dnscat2 | 88.5% | 97.9% | 88.5% | 41,666 |
| tcp-over-dns | 96.7% | 97.6% | 98.4% | 35,964 |
| tuns | 97.9% | 97.6% | 100.0% | 34,964 |

Random forest, same folds:

| Held-out tool | Accuracy |
|---|---|
| dns2tcp | 21.5% |
| dnstt | 55.6% |
| dnscat2 | 96.9% |
| iodine | 99.2% |
| tcp-over-dns | 100.0% |
| tuns | 100.0% |

## The finding that matters more than the mean

Averaging leave-one-tool-out into a single "72.9%" number hides the real
result, which is that generalization is wildly uneven across tools. Four
of six held-out tools (dnscat2, iodine, tcp-over-dns, tuns) score 87-100%
accuracy. Two (dns2tcp, dnstt) collapse: dns2tcp drops to 11.9% accuracy
with the logistic regression, dnstt to 54.6%.

Precision stays high in every fold (97-98%) while recall is what falls
apart for the bad folds (9.0% for dns2tcp, 50.2% for dnstt). That pattern
means the model isn't confusing benign traffic for tunnel traffic; it's
failing to recognize the held-out tool's tunnel traffic as tunnel traffic
at all, calling most of it benign. Whatever "tunneling looks like this"
pattern the model learned from the other five tools doesn't transfer to
dns2tcp's traffic shape.

This lines up with the client-IP grouping from the leak section above.
dns2tcp, dnscat2, and iodine share one client subnet; dnstt, tcp-over-dns,
and tuns share another. dns2tcp is also by far the largest tool in the
dataset (167,486 of 354,713 malicious rows, about 47%), so holding it out
removes nearly half the malicious training data and the tool whose scale
most heavily shaped what "malicious" looks like in the remaining data.
Both of those are plausible explanations for why it's the worst-performing
fold, and this project doesn't have the data to fully separate "dns2tcp's
traffic shape is genuinely different" from "dns2tcp being the largest
class distorts what the other five tools' combined training set looks
like." Both are real limitations of a six-tool, one-dataset study; see
Limitations below.

The headline honest number is **72.9% mean accuracy (logistic
regression) / 78.9% (random forest) across leave-one-tool-out folds**,
against **95.8% / 99.9%** under a random split. Report the mean if a
single number is needed, but the range (11.9% to 97.9%) is the more
important thing to carry forward: this detector generalizes well to some
tunneling tools and poorly to others, and averaging that away would be
the same mistake as reporting the leaky number in different clothing.

## Which behavioral features carry the signal

Both models converge on the same family of features, not flow-level
totals (bytes sent, bytes received) but packet-size and timing shape:

Logistic regression, by standardized coefficient magnitude:

1. `PacketLengthStandardDeviation`
2. `ResponseTimeTimeMean`
3. `PacketLengthVariance`
4. `PacketLengthCoefficientofVariation`
5. `PacketLengthMean`

Random forest, by impurity-based importance:

1. `PacketLengthMode`
2. `FlowBytesReceived`
3. `Duration`
4. `PacketLengthMean`
5. `PacketTimeStandardDeviation`

Packet-size statistics dominate both rankings. That has a straightforward
explanation: a DoH tunnel is carrying a different kind of payload than a
real DNS lookup. An ordinary DNS query and response are small and close to
a fixed size; a tunneling tool moving shell commands or file data through
DNS-shaped messages produces packets with a different size distribution,
and that difference survives TLS encryption because TLS hides the
content of a record, not its length. This is the same reason encrypted
traffic in general keeps leaking metadata through packet size and timing
even when payload inspection is impossible; it's why tools like this can
work at all against a fully encrypted channel. `ResponseTimeTimeMean`
mattering too fits the same story: how long a DoH server takes to answer
a query that's actually carrying tunneled data can differ from how long a
real DNS lookup takes.

## What this does not establish

- **Only six tunneling tools, all from one lab-generated dataset.**
  Leave-one-tool-out here means "generalize to a tool that exists in this
  dataset but wasn't in training," not "generalize to any tunneling tool
  that could exist." A seventh tool built differently (different
  chunking, different padding, deliberately mimicking normal DNS
  response-size distributions) could behave nothing like any of the six
  here.
- **Generated, not captured in the wild.** This traffic was produced by
  running specific tools in a lab, not observed on a live network among
  real DNS traffic, other encrypted protocols, and whatever noise a
  production network actually has. Real-world false-positive behavior
  against ordinary DoH traffic from browsers and OS resolvers is untested.
- **The dns2tcp/dnstt collapse could be a dataset artifact, not a model
  limitation.** As discussed above, dns2tcp is nearly half the malicious
  data and shares a client subnet with two of the tools that generalize
  well to it; there isn't enough here to cleanly separate "this tool's
  behavior is genuinely different" from "removing this tool distorts the
  training distribution." A dataset with more tools, more balanced tool
  sizes, or tools deliberately varied in evasion strategy would be needed
  to settle that.
- **No adversarial evasion tested.** Nothing here checks whether a
  tunneling tool tuned to mimic benign packet-size and timing
  distributions (padding to typical DNS response sizes, adding jitter)
  would defeat this detector. Given that packet-size statistics are the
  dominant signal, that's a plausible and untested evasion path.
- **The benign class is a single, fairly small sample (19,746 rows from
  four client machines).** Leave-one-tool-out gives the malicious side a
  real generalization test; the benign side never gets an equivalent
  test, because there's only one benign class and no second, differently
  generated benign source to hold out against.

## Provenance

Data: CIRA-CIC-DoHBrw-2020 (MontazeriShatoori, Davidson, Kaur, Lashkari,
IEEE CCECE 2020) combined with DoH-Tunnel-Traffic-HKD (Mitsuhashi, Jin,
Iida, Shinagawa, Takai, IEEE TNSM 2022). Full citation and license terms
in `data/README.md`.

Methodology grounded in: Arp, D. et al., "Dos and Don'ts of Machine
Learning in Computer Security," USENIX Security 2022 (spurious
correlations / sampling bias, and their prescribed remedy of feature
ablation plus disclosure). Same failure mode independently found and
documented in this workspace's `ai-triage-engine` project
(`research/phase-1b-shortcut-mitigation.md`), on a different pair of
datasets.

Environment: scikit-learn 1.9.0, pandas 3.0.5, numpy 2.5.2 in a
project-local virtualenv (`.venv/`, not committed; the system Python on
this host doesn't have scikit-learn installed). Fixed random seed 42
throughout for reproducibility. Run `scripts/run_analysis.py` to
regenerate `reports/results.json` and these numbers from scratch.
