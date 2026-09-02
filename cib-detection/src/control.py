"""
Score the coordination signals against a benign control group.

Why this file exists: every account in the influence-operation corpus was
removed by Twitter as state-linked. Scoring a detector on that alone produces
a number that means nothing. In an earlier project a beaconing detector ranked
a benign smart bulb above a botnet, and that was only visible because the
corpus contained benign traffic.

The control is the Caverlee 2011 social honeypot dataset: 19,276 accounts that
the authors verified as legitimate human users, and 3,259,693 of their tweets.

TWO LIMITS, both real, both stated here rather than discovered by a reader:

1. NO CLIENT FIELD. The control's tweet records carry four columns: user id,
   tweet id, text, timestamp. There is no posting-app field. So the shared
   tooling signal, which scored AUC 0.644 within the CIB corpus, CANNOT be
   evaluated against benign accounts at all. It is not weak here. It is
   unmeasurable, and any number reported for it would be invented.

2. ERA GAP. The control accounts were created 2006 to 2009 and their tweets
   are almost entirely from 2009. The influence operations run 2014 to 2020.
   Twitter changed a great deal in between: client mix, follower norms,
   retweet mechanics, hashtag culture. So a difference between the two groups
   may be a difference between 2009 and 2018 rather than between benign and
   coordinated.

What survives both limits: co-timing and shared hashtags. Both are computed
from a timestamp and text, which both corpora have, and both are about the
relationship between accounts rather than a platform feature that changed.

The honest framing is that this measures whether a pair of BENIGN accounts
looks as coordinated as a pair from one operation. If benign pairs score just
as high, the signal is worthless regardless of how well it separated
operations from each other.
"""

import csv
import random
import sys
from collections import Counter, defaultdict
from datetime import datetime
from itertools import combinations
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from coordination import cosine, jaccard, load_profiles  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CONTROL_TWEETS = ROOT / "data" / "raw" / "legitimate_users_tweets.txt"

# Same floor as the CIB side. Below this every similarity measure is noise:
# two accounts that each posted three times in the same hour score 1.0 on
# co-timing and it means nothing.
MIN_TWEETS = 20


def load_control(path: Path, max_accounts=300, seed=42):
    """Build the same profile shape from the control corpus.

    Sampled rather than using all 19,276 accounts, because the pairwise
    comparison is quadratic and the CIB side has 262 eligible accounts. Using
    a comparable number keeps the two pair populations the same order of
    magnitude, so one is not swamped by the other.

    The seed is fixed so the sample is reproducible.
    """
    by_account = defaultdict(lambda: {"hours": Counter(), "hashtags": Counter(),
                                      "tweets": 0, "operation": "control"})

    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.rstrip("\r\n").split("\t")
            if len(parts) < 4:
                continue
            uid, _tid, text, when = parts[0], parts[1], parts[2], parts[3]
            try:
                dt = datetime.strptime(when.strip(), "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
            a = by_account[uid]
            a["tweets"] += 1
            a["hours"][dt.hour] += 1
            for token in text.split():
                if token.startswith("#") and len(token) > 1:
                    a["hashtags"][token.lower().rstrip(".,!?:;")] += 1

    eligible = {u: p for u, p in by_account.items() if p["tweets"] >= MIN_TWEETS}
    rng = random.Random(seed)
    keys = sorted(eligible)
    if len(keys) > max_accounts:
        keys = rng.sample(keys, max_accounts)
    return {k: eligible[k] for k in keys}


def pair_scores(profiles, signals=("co_timing", "shared_hashtags")):
    """Score every pair on the signals both corpora can support."""
    out = []
    for a, b in combinations(sorted(profiles), 2):
        pa, pb = profiles[a], profiles[b]
        row = {}
        if "co_timing" in signals:
            row["co_timing"] = cosine(pa["hours"], pb["hours"])
        if "shared_hashtags" in signals:
            row["shared_hashtags"] = jaccard(pa["hashtags"], pb["hashtags"])
        out.append(row)
    return out


def auc(positive, negative, cap=500):
    """How often a random positive outscores a random negative. 0.5 is chance."""
    p = sorted(positive)
    n = sorted(negative)
    if not p or not n:
        return 0.5
    ps = p[:: max(1, len(p) // cap)]
    ns = n[:: max(1, len(n) // cap)]
    hits = ties = 0
    for x in ps:
        for y in ns:
            if x > y:
                hits += 1
            elif x == y:
                ties += 1
    total = len(ps) * len(ns)
    return (hits + 0.5 * ties) / total if total else 0.5


def percentile(values, q):
    if not values:
        return 0.0
    s = sorted(values)
    return s[min(len(s) - 1, int(q * len(s)))]


def main():
    if not CONTROL_TWEETS.exists():
        print(f"control corpus missing: {CONTROL_TWEETS}", file=sys.stderr)
        return 1

    print("loading influence operations...")
    cib = load_profiles(ROOT / "data" / "raw")
    cib = {u: p for u, p in cib.items() if p["tweets"] >= MIN_TWEETS}

    print("loading benign control...")
    control = load_control(CONTROL_TWEETS)

    print(f"\n  operation accounts: {len(cib)}")
    print(f"  control accounts:   {len(control)}")

    # Same-operation pairs only. A cross-operation pair is two unrelated
    # adversaries, which is not what a detector is asked to find.
    by_op = defaultdict(dict)
    for uid, p in cib.items():
        by_op[p["operation"]][uid] = p

    cib_pairs = []
    for op, accounts in by_op.items():
        cib_pairs.extend(pair_scores(accounts))

    control_pairs = pair_scores(control)

    print(f"  same-operation pairs: {len(cib_pairs):,}")
    print(f"  benign pairs:         {len(control_pairs):,}\n")

    print(f"{'signal':18} {'op median':>10} {'ctrl median':>12} {'op p95':>9} {'ctrl p95':>10} {'AUC':>7}")
    print("-" * 72)
    for signal in ("co_timing", "shared_hashtags"):
        op_v = [r[signal] for r in cib_pairs]
        ct_v = [r[signal] for r in control_pairs]
        print(f"{signal:18} {percentile(op_v, 0.5):>10.3f} {percentile(ct_v, 0.5):>12.3f} "
              f"{percentile(op_v, 0.95):>9.3f} {percentile(ct_v, 0.95):>10.3f} "
              f"{auc(op_v, ct_v):>7.3f}")

    print("\nshared_tooling: NOT EVALUATED. The control corpus has no posting-client")
    print("field, so there is no benign baseline to compare against. Reporting a")
    print("number for it here would be inventing one.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
