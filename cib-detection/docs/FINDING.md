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

---

## Finding 4: with a benign control, one signal survives and one collapses

Findings 1 to 3 were all measured inside the influence-operation corpus, comparing
same-operation pairs against cross-operation pairs. That is the weaker test, because every
account in it was removed by Twitter as state-linked. Nothing there is benign.

Adding a control group changes two of the answers.

Control: the Caverlee 2011 social honeypot dataset, 19,276 accounts the authors verified as
legitimate human users, 3,259,693 tweets. 300 accounts sampled with a fixed seed, giving 44,850
benign pairs against 17,556 same-operation pairs.

| signal | operation median | control median | operation p95 | control p95 | AUC |
|---|---|---|---|---|---|
| shared hashtags | 0.014 | 0.000 | 0.100 | **0.000** | **0.888** |
| co-timing | 0.537 | 0.515 | 0.847 | 0.802 | **0.534** |

### Co-timing was never a coordination signal

Against other operations it scored AUC 0.592. Against benign accounts it scores **0.534**, which
is close enough to chance to call it nothing.

The medians explain it: 0.537 for operation pairs, 0.515 for benign pairs. Ordinary accounts
overlap in posting hours almost exactly as much as coordinated ones do. That is what a shared
time zone looks like, and it has nothing to do with whether anyone is running the accounts
together.

The earlier 0.592 was measuring the difference between operations, not the presence of
coordination. Four operations in four different regions post in four different sets of hours,
so accounts inside one match each other better than accounts across two. Real, and useless for
detection.

**Without a benign control this would have shipped as a working signal.** It is the same failure
as the beaconing detector ranking a smart bulb above a botnet, caught the same way.

### Shared hashtags got stronger, and the control shows why

AUC rises from 0.797 against other operations to **0.888** against benign accounts.

The control p95 is 0.000. Ninety-five percent of benign pairs share no hashtags at all.

That is not because ordinary people avoid hashtags. 214 of the 300 control accounts, 71 percent,
use them. But only 3.54 percent of benign pairs share any, and the highest benign overlap
anywhere in 44,850 pairs is 0.600.

Ordinary accounts use hashtags about different things. Two people tagging their own interests
produce almost no overlap. A campaign produces a lot, because pushing the same tags is the
point.

That is a genuine discriminator, and it survives the control.

### One signal cannot be evaluated at all

The control's tweet records have four columns: user id, tweet id, text, timestamp. There is no
posting-client field.

So shared tooling, which scored AUC 0.644 inside the CIB corpus, has **no benign baseline**.
It is not weak against ordinary accounts. It is unmeasurable against them with this control, and
any number reported would be invented.

This matters because tooling was the signal with the widest median gap, 0.873 against 0.028, and
would have been the most tempting to headline. Finding 2 already showed it measures provisioning
rather than coordination. The missing control confirms there is no way to check that from here.

### The era gap, stated plainly

The control accounts were created between 2006 and 2009 and their tweets are almost entirely
from 2009. The influence operations run 2014 to 2020.

Twitter changed a great deal in between: the client mix, follower norms, retweet mechanics,
hashtag culture. So some part of any measured difference is a difference between 2009 and 2018
rather than between benign and coordinated.

This weakens both results, and it weakens the hashtag finding more than it looks, since hashtag
usage grew substantially over that period. The honest version of the claim is that shared
hashtags separates these operations from these benign accounts by AUC 0.888, and that a control
from the same era would be needed to rule out the period as the cause.

No such control was found. The search covered Kaggle, Sentiment140, the Cresci datasets, the
Botometer bot repository, Zenodo, Harvard Dataverse, and the Internet Archive Twitter stream
grab. Nothing public carries ordinary accounts from 2014 to 2020 with usable metadata. Twitter's
API stopped being freely available at the scale needed, so most modern corpora are tweet-id-only
and cannot be rehydrated.

### A licence decision worth recording

The Cresci datasets, cresci-2015 and cresci-2017, are the standard academic baseline and both
carry an explicit genuine-human class. Both are mechanically downloadable from a mirror with no
authentication.

They were not used. The originating project at CNR states: "we are not openly posting the
datasets, instead, they are available for researchers who will ask for" and "the datasets cannot
be redistributed."

A file being reachable is not permission to use it. Caverlee 2011 was used instead, and it is
the weaker dataset for this purpose because it lacks the client field.
