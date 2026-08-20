# Findings

## Finding 1: the median account in an influence operation does almost nothing

The first summary of the feature table used medians, and every operation showed an automation
share of 0.00. That contradicted a corpus-level count showing 96 percent of Armenian tweets
posted through `twitterfeed` and `dlvr.it`.

Both numbers were right. The median was the wrong statistic.

| operation | accounts | tweets | median tweets/account | max | top 3 accounts' share of volume |
|---|---|---|---|---|---|
| GRU | 51 | 26,684 | 42 | 9,977 | 63% |
| IRA | 24 | 68,914 | 1,168 | 23,527 | 61% |
| Armenia | 31 | 72,960 | 36 | 22,351 | 79% |
| Iran | 209 | 560,571 | 298 | 302,648 | 60% |

In every operation, three accounts carry 60 to 79 percent of the traffic. The rest post a
handful of times and stop.

So a per-account median describes the dormant majority and says nothing about the accounts that
did the work. Weighting by volume tells the real story:

| operation | accounts over 50% automated | share of TWEETS from automation clients |
|---|---|---|
| Armenia | 19% | **96%** |
| Iran | 0% | 15% |
| IRA | 4% | 8% |
| GRU | 0% | 0% |

Six of Armenia's 31 accounts produced almost all of its output, through scheduling tools.

### Why this matters beyond a statistics note

An operation is not a uniform population of similar accounts. It is a small number of workhorses
plus a long tail of registered-but-idle assets. Any per-account average, median included,
mixes two populations that are doing different jobs.

It also affects what a detector can claim. A model scoring accounts one at a time will see mostly
low-signal dormant accounts and learn very little. The signal lives in the relationship between
accounts, and in the handful that actually post.

## Finding 2: automation is not a shared trait across operations

The four operations do not look alike.

Armenia runs on syndication tooling: 96 percent of its volume through `twitterfeed` and
`dlvr.it`. GRU shows zero automation-client usage at all. Its accounts post through ordinary
Twitter web and phone clients.

So "posted via automation" separates Armenia from GRU cleanly, and separates neither from an
ordinary newsroom account that also syndicates headlines through `dlvr.it`. The feature is
informative about how an operation was run, not about whether something is an operation.

This is the same trap as ranking by regularity in the SQL threat hunting project, where a
Philips Hue bridge scored as a more perfect beacon than a botnet. A mechanically distinctive
behaviour is not automatically a malicious one, and the benign population usually contains
plenty of it.

## What this means for the detector

Two design consequences, both taken before any model was built:

1. **Score coordination between accounts, not properties of one account.** Shared tooling,
   overlapping activity hours, common retweet targets and identical hashtag sets are relational.
   A single account's automation share is not.

2. **Weight by volume, or say which population is being described.** Reporting a median across
   an operation describes its dormant tail. That may be worth reporting, but it must be labelled
   as such rather than presented as the operation's behaviour.

## Data note

Every account here comes from Twitter's own Election Integrity releases, which the platform
published after identifying and removing these accounts as state-linked. The labels are the
platform's, not mine.

The four operations used: Armenia (December 2020 release), GRU, IRA, and Iran (all December 2020
release). 315 accounts, 729,129 tweets.

A parsing note that cost real time: an early account count using `cut -d,` reported 244,447
accounts for Iran against an actual 209. Tweet text contains commas and newlines, so a naive
field split inflates the count by three orders of magnitude. Everything here uses a real CSV
parser with an enlarged field-size limit.

---

## Finding 3: four coordination signals, and only two of them work

Scoring all 34,191 pairs of accounts that posted at least 20 times, and asking whether each
signal separates same-operation pairs from cross-operation pairs:

| signal | median, same operation | median, cross operation | AUC |
|---|---|---|---|
| shared hashtags | 0.014 | 0.000 | **0.797** |
| shared tooling | 0.873 | 0.028 | 0.644 |
| co-timing | 0.537 | 0.454 | 0.592 |
| shared retweet targets | 0.000 | 0.000 | 0.513 |

AUC of 0.5 is a coin flip.

### Shared hashtags is the strongest signal, and the medians say why

The medians are both near zero. Most pairs share no hashtags at all, in the same operation or
across operations. But when a pair does share tags, it is far more likely to be inside one
operation. The separation lives in the tail, not the middle, which is exactly what a campaign
looks like: a small number of accounts pushing the same specific tags at the same time, against
a background of accounts sharing nothing.

That is also why the median is a poor summary here and the AUC is the honest number.

### Shared tooling has the widest median gap and a mediocre AUC

0.873 within an operation against 0.028 across operations is a very wide gap, yet the AUC is
only 0.644.

The explanation is Finding 2. Armenia runs almost entirely on `twitterfeed` and `dlvr.it`, so
its accounts match each other almost perfectly. GRU uses no automation clients at all, so its
accounts also match each other, on ordinary phone and web clients. Both are high within-operation
scores, and both are trivially explained by "everyone in one operation was set up by the same
person on the same day".

The signal is real but it is measuring provisioning, not coordination. It would fire just as
hard on any group of accounts configured together for a legitimate reason.

### Shared retweet targets does not work at all, and it is a data problem

AUC 0.513 is a coin flip, and the reason is not the signal. It is that these operations barely
retweet:

| operation | retweets with a resolvable target | share of all tweets |
|---|---|---|
| Iran | 17,981 | 3.2% |
| IRA | 1,217 | 1.8% |
| GRU | 398 | 1.5% |
| Armenia | 207 | 0.3% |

Amplification networks are the classic CIB shape, where a cluster of accounts boosts the same
handful of sources. These four operations are not that. They are content producers. They post
original material rather than amplifying each other, so a retweet-overlap signal has almost
nothing to work with.

Reporting AUC 0.513 as "this signal is weak" would be wrong. The correct statement is that
this corpus cannot evaluate it, in the same way the threat-intel data mart could not evaluate
cross-campaign indicator overlap. The signal is unproven here, not disproven.

### Co-timing is weakly positive and honestly so

AUC 0.592. Better than chance and not by much. Accounts in one operation do post in overlapping
hours, which is what a shared working day looks like, but ordinary accounts in one time zone
also share posting hours. Without a benign control group there is no way to know how much of
that 0.592 is coordination and how much is simply geography.
