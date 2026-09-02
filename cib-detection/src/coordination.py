"""
Score coordination between accounts rather than properties of one account.

Finding 2 in docs/FINDING.md is the reason this file exists. Per-account
features describe how an operation was run, and they do not separate an
operation from an ordinary account doing something mechanically similar. A
newsroom syndicating headlines through dlvr.it looks like the Armenian
operation on that axis alone.

What does not have a benign twin is a GROUP of accounts that behave like each
other more than chance allows. So every score here is pairwise.

Four independent signals, deliberately measuring different things:

  co-timing        do two accounts post in the same hours of the day
  shared tooling   do they post through the same client apps
  shared targets   do they retweet the same accounts
  shared hashtags  do they use the same tags

They are kept separate rather than blended into one number, because which
signals fire tells you what kind of operation it is. Blending them destroys
that.
"""

import csv
import sys
from collections import Counter, defaultdict
from datetime import datetime
from itertools import combinations
from pathlib import Path

csv.field_size_limit(10 ** 7)


def parse_time(value):
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue
    return None


def load_profiles(raw_dir: Path):
    """One profile per account: the vectors the pairwise scores compare."""
    profiles = defaultdict(lambda: {
        "operation": None,
        "tweets": 0,
        "hours": Counter(),
        "clients": Counter(),
        "retweeted": Counter(),
        "hashtags": Counter(),
    })

    for path in sorted(raw_dir.glob("*_tweets.csv")):
        operation = path.name.replace("_tweets.csv", "")
        with path.open(newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.DictReader(fh):
                uid = row.get("userid")
                if not uid:
                    continue
                p = profiles[uid]
                p["operation"] = operation
                p["tweets"] += 1

                when = parse_time(row.get("tweet_time"))
                if when:
                    p["hours"][when.hour] += 1

                client = (row.get("tweet_client_name") or "").strip()
                if client:
                    p["clients"][client] += 1

                if (row.get("is_retweet") or "").lower() in ("true", "1"):
                    target = (row.get("retweet_userid") or "").strip()
                    if target:
                        p["retweeted"][target] += 1

                for token in (row.get("tweet_text") or "").split():
                    if token.startswith("#") and len(token) > 1:
                        p["hashtags"][token.lower().rstrip(".,!?:;")] += 1

    return profiles


def cosine(a: Counter, b: Counter) -> float:
    """Cosine similarity over two count vectors.

    Chosen over raw overlap because it is insensitive to volume. Two accounts
    posting 20 and 20,000 times can still have the same shape, and in this
    corpus that matters: volume is wildly uneven, so an overlap count would
    just rediscover the busiest accounts.
    """
    if not a or not b:
        return 0.0
    keys = set(a) & set(b)
    if not keys:
        return 0.0
    dot = sum(a[k] * b[k] for k in keys)
    na = sum(v * v for v in a.values()) ** 0.5
    nb = sum(v * v for v in b.values()) ** 0.5
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def jaccard(a: Counter, b: Counter) -> float:
    """Set overlap, for signals where how often matters less than whether.

    Retweet targets and hashtags are set-like. Two accounts amplifying the
    same five accounts is interesting whether each did it twice or two
    hundred times.
    """
    sa, sb = set(a), set(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def score_pairs(profiles, min_tweets=20):
    """Every pair of accounts, scored on four axes.

    Accounts under min_tweets are excluded. With a handful of posts every
    similarity measure becomes noise: two accounts that each tweeted three
    times in the same hour score 1.0 on co-timing and it means nothing. That
    threshold is a judgement call and it is stated rather than buried.
    """
    eligible = {uid: p for uid, p in profiles.items() if p["tweets"] >= min_tweets}
    results = []
    for a, b in combinations(sorted(eligible), 2):
        pa, pb = eligible[a], eligible[b]
        results.append({
            "account_a": a,
            "account_b": b,
            "operation_a": pa["operation"],
            "operation_b": pb["operation"],
            "same_operation": pa["operation"] == pb["operation"],
            "co_timing": cosine(pa["hours"], pb["hours"]),
            "shared_tooling": cosine(pa["clients"], pb["clients"]),
            "shared_targets": jaccard(pa["retweeted"], pb["retweeted"]),
            "shared_hashtags": jaccard(pa["hashtags"], pb["hashtags"]),
        })
    return results, eligible


def evaluate(pairs):
    """Does each signal separate same-operation pairs from cross-operation ones?

    This is the honest test available without a benign control group. If a
    signal cannot tell two accounts inside one operation from two accounts in
    different operations, it is not measuring coordination, it is measuring
    something both operations happen to share.

    It is a weaker test than malicious against benign, and the write-up says so.
    """
    signals = ["co_timing", "shared_tooling", "shared_targets", "shared_hashtags"]
    same = [p for p in pairs if p["same_operation"]]
    diff = [p for p in pairs if not p["same_operation"]]

    out = {}
    for s in signals:
        sv = sorted(p[s] for p in same)
        dv = sorted(p[s] for p in diff)
        med_s = sv[len(sv) // 2] if sv else 0.0
        med_d = dv[len(dv) // 2] if dv else 0.0

        # How often does a random same-operation pair outscore a random
        # cross-operation one. This is the AUC, computed directly. 0.5 is a
        # coin flip.
        hits = ties = 0
        step_d = max(1, len(dv) // 400)
        step_s = max(1, len(sv) // 400)
        sample_d = dv[::step_d]
        sample_s = sv[::step_s]
        for x in sample_s:
            for y in sample_d:
                if x > y:
                    hits += 1
                elif x == y:
                    ties += 1
        total = len(sample_s) * len(sample_d)
        auc = (hits + 0.5 * ties) / total if total else 0.5

        out[s] = {"median_same": med_s, "median_diff": med_d, "auc": auc,
                  "n_same": len(same), "n_diff": len(diff)}
    return out


def main():
    root = Path(__file__).resolve().parent.parent
    profiles = load_profiles(root / "data" / "raw")
    pairs, eligible = score_pairs(profiles)

    print(f"accounts loaded: {len(profiles)}")
    print(f"accounts with 20+ tweets: {len(eligible)}")
    print(f"pairs scored: {len(pairs):,}\n")

    results = evaluate(pairs)
    print(f"{'signal':18} {'med same-op':>12} {'med cross-op':>13} {'AUC':>7}")
    print("-" * 54)
    for name, r in results.items():
        print(f"{name:18} {r['median_same']:>12.3f} {r['median_diff']:>13.3f} {r['auc']:>7.3f}")

    print(f"\nsame-operation pairs: {results['co_timing']['n_same']:,}")
    print(f"cross-operation pairs: {results['co_timing']['n_diff']:,}")

    out = root / "data" / "pairs.csv"
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(pairs[0].keys()))
        w.writeheader()
        w.writerows(pairs)
    print(f"\n-> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
