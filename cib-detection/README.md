# Coordinated inauthentic behavior detection

Four coordination signals scored against 315 accounts from four state-linked influence
operations, then scored again against a benign control group. One signal survived the control.
One collapsed to chance. One could not be measured at all.

## Run it

```bash
python3 scripts/fetch_data.py     # pulls both corpora from public sources
python3 src/features.py           # per-account features
python3 src/coordination.py       # pairwise scoring within the CIB corpus
python3 src/control.py            # the same signals against benign accounts
python3 -m pytest tests/ -q       # 6 tests
```

## The result

| signal | vs other operations | vs benign accounts |
|---|---|---|
| shared hashtags | 0.797 | **0.888** |
| shared tooling | 0.644 | **not measurable** |
| co-timing | 0.592 | **0.534** |
| shared retweet targets | 0.513 | not run |

AUC 0.5 is a coin flip.

**Co-timing was never a coordination signal.** It scored 0.592 against other operations and
0.534 against benign accounts. Operation pairs have a median co-timing of 0.537; benign pairs
0.515. Ordinary accounts overlap in posting hours almost exactly as much as coordinated ones,
because that is what a shared time zone looks like. The earlier number was measuring the
difference between four operations in four regions.

Without a benign control this would have shipped as a working detector.

**Shared hashtags survived and got stronger.** 95 percent of benign pairs share no hashtags at
all, though 71 percent of benign accounts use them. Ordinary people tag different things. A
campaign tags the same thing, because that is the point.

**Shared tooling cannot be evaluated.** The control corpus has no posting-client field. This was
the signal with the widest median gap and the most tempting to headline. It ships marked
unmeasurable rather than given an invented number.

Full write-ups in [docs/FINDING.md](docs/FINDING.md).

## Two other findings

**The median account in an operation does almost nothing.** Three accounts carry 60 to 79
percent of the volume in every one of the four operations. A per-account median describes the
dormant tail, not the operation. The first summary of this corpus reported automation share
0.00 everywhere, which contradicted a corpus-level count of 96 percent. Both were right and the
median was the wrong statistic.

**Retweet overlap could not be evaluated either.** These operations retweet in 0.3 to 3.2
percent of their tweets. They are content producers, not an amplification network, so the
classic CIB signal has almost nothing to work with here. Unproven on this corpus rather than
disproven.

## Data

| corpus | source | what it is | licence |
|---|---|---|---|
| influence operations | Twitter Election Integrity releases, December 2020 | 315 accounts, 729,129 tweets, Armenia + GRU + IRA + Iran | released by Twitter for research; no formal licence stated |
| benign control | Caverlee 2011 social honeypot | 19,276 verified legitimate accounts, 3,259,693 tweets | academic use, via the OSoMe bot repository |

The influence-operation labels are Twitter's own. These accounts were identified as state-linked
and removed by the platform.

### Two data decisions worth stating

**The Cresci datasets were not used.** cresci-2015 and cresci-2017 are the standard academic
baseline, both carry a genuine-human class, and both are mechanically downloadable from a mirror
with no authentication. The originating project at CNR states the datasets "cannot be
redistributed" and are available on request only. A file being reachable is not permission to
use it. Caverlee was used instead and it is the weaker dataset here, because it has no client
field.

**The era gap is real.** The control is 2009. The operations run 2014 to 2020. Some part of any
measured difference is five years of platform change rather than benign against coordinated,
and that weakens the hashtag result more than it looks, since hashtag use grew over that period.
No public corpus of ordinary accounts from the 2014 to 2020 window with usable metadata was
found. The search covered Kaggle, Sentiment140, the Botometer bot repository, Zenodo, Harvard
Dataverse and the Internet Archive Twitter stream grab. Twitter's API stopped being freely
available at the scale needed, so most modern corpora are tweet-id-only and cannot be rehydrated.

## What this does not claim

- Not a deployable detector. One signal at AUC 0.888 against a decade-old control is a starting
  point, not a system.
- Not generalisable to other platforms, other actors, or AI-generated content. The newest data
  here is from 2020.
- Not a bot detector. The question is whether accounts are being run together, which is a
  different question from whether one account is automated.
