"""
Turn raw tweet exports into per-account coordination features.

The question this project asks is not "is this account a bot". It is "do these
accounts look like they are being run together". Those are different, and the
second one is what a takedown actually needs to establish.

So every feature here is about an account's relationship to a GROUP, or about
mechanics that are hard to fake at scale, rather than about the content of any
single post. Content is the easiest thing for an operator to vary and the
hardest thing to score reliably. Timing, tooling and account provenance are
harder to vary because they come from how the operation is actually run.

Data: Twitter's own Election Integrity releases. Every account here was
identified by Twitter as state-linked and removed. That is the ground truth,
and it is the platform's own labelling rather than mine.
"""

import csv
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

# Tweet text runs to thousands of characters and contains commas and newlines.
# The default field limit trips on it.
csv.field_size_limit(10 ** 7)

# Clients that post on a schedule with no human at the keyboard. This list is
# not a bot detector. Plenty of legitimate accounts syndicate through these,
# and a newsroom auto-posting headlines is not an influence operation. It is
# one signal among several, and it is only interesting when a whole cluster of
# accounts shares it.
AUTOMATION_CLIENTS = {
    "twitterfeed", "dlvr.it", "IFTTT", "Buffer", "Hootsuite", "TweetDeck",
    "SocialFlow", "roundteam", "twittbot.net", "Zapier", "Later",
}


def parse_time(value):
    """Twitter's export uses a few shapes. Return a datetime or None.

    None rather than a guess: a fabricated timestamp would flow into every
    timing feature and there would be no way to spot it later.
    """
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue
    return None


def load_operation(path: Path, operation: str):
    """Read one operation's tweet export into per-account buckets."""
    accounts = defaultdict(lambda: {
        "operation": operation,
        "tweets": 0,
        "clients": Counter(),
        "hours": Counter(),
        "weekdays": Counter(),
        "languages": Counter(),
        "retweets": 0,
        "replies": 0,
        "times": [],
        "creation": None,
        "followers": None,
        "following": None,
        "hashtags": Counter(),
        "mentions": Counter(),
        "retweeted_users": Counter(),
    })

    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            uid = row.get("userid")
            if not uid:
                continue
            a = accounts[uid]
            a["tweets"] += 1

            client = (row.get("tweet_client_name") or "").strip()
            if client:
                a["clients"][client] += 1

            when = parse_time(row.get("tweet_time"))
            if when:
                a["hours"][when.hour] += 1
                a["weekdays"][when.weekday()] += 1
                a["times"].append(when)

            lang = (row.get("tweet_language") or "").strip()
            if lang:
                a["languages"][lang] += 1

            if (row.get("is_retweet") or "").lower() in ("true", "1"):
                a["retweets"] += 1
                rt_user = (row.get("retweet_userid") or "").strip()
                if rt_user:
                    a["retweeted_users"][rt_user] += 1
            if (row.get("in_reply_to_userid") or "").strip():
                a["replies"] += 1

            if a["creation"] is None:
                a["creation"] = row.get("account_creation_date")
                a["followers"] = row.get("follower_count")
                a["following"] = row.get("following_count")

            text = row.get("tweet_text") or ""
            for token in text.split():
                if token.startswith("#") and len(token) > 1:
                    a["hashtags"][token.lower().rstrip(".,!?:;")] += 1
                elif token.startswith("@") and len(token) > 1:
                    a["mentions"][token.lower().rstrip(".,!?:;")] += 1

    return accounts


def hour_concentration(hours: Counter) -> float:
    """What share of an account's posting falls in its busiest 6 hours.

    A person sleeps, works, and posts in bursts around a life. Roughly a
    quarter of a day covers most of their activity, so the value lands
    somewhere around 0.5 to 0.7 naturally. A scheduler running around the
    clock flattens it toward 0.25. A scheduler running one shift pushes it
    toward 1.0.

    Both extremes are informative and neither is proof.
    """
    total = sum(hours.values())
    if not total:
        return 0.0
    top6 = sum(count for _h, count in hours.most_common(6))
    return top6 / total


def automation_share(clients: Counter) -> float:
    total = sum(clients.values())
    if not total:
        return 0.0
    auto = sum(c for name, c in clients.items() if name in AUTOMATION_CLIENTS)
    return auto / total


def burstiness(times: list) -> float:
    """Coefficient of variation of the gaps between consecutive posts.

    A scheduler produces near-identical gaps, so this trends toward 0. Human
    posting is bursty: a flurry, then silence, so it trends well above 1.

    This is the same measure that ranked a light bulb above a botnet in the
    SQL threat hunting project. It is included with that caveat attached, not
    as a settled signal.
    """
    if len(times) < 3:
        return 0.0
    ordered = sorted(times)
    gaps = [(ordered[i + 1] - ordered[i]).total_seconds()
            for i in range(len(ordered) - 1)]
    gaps = [g for g in gaps if g > 0]
    if len(gaps) < 2:
        return 0.0
    mean = sum(gaps) / len(gaps)
    if mean == 0:
        return 0.0
    var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    return (var ** 0.5) / mean


def to_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def build_features(accounts: dict) -> list:
    rows = []
    for uid, a in accounts.items():
        times = a["times"]
        span_days = 0.0
        if len(times) >= 2:
            span_days = (max(times) - min(times)).total_seconds() / 86400

        clients_total = sum(a["clients"].values())
        top_client, top_client_n = (a["clients"].most_common(1) or [("", 0)])[0]

        rows.append({
            "userid": uid,
            "operation": a["operation"],
            "tweets": a["tweets"],
            "distinct_clients": len(a["clients"]),
            "top_client": top_client,
            "top_client_share": (top_client_n / clients_total) if clients_total else 0.0,
            "automation_share": automation_share(a["clients"]),
            "hour_concentration": hour_concentration(a["hours"]),
            "burstiness": burstiness(times),
            "retweet_share": a["retweets"] / a["tweets"] if a["tweets"] else 0.0,
            "reply_share": a["replies"] / a["tweets"] if a["tweets"] else 0.0,
            "distinct_languages": len(a["languages"]),
            "span_days": round(span_days, 1),
            "tweets_per_day": round(a["tweets"] / span_days, 2) if span_days > 0 else 0.0,
            "account_creation_date": a["creation"],
            "follower_count": to_int(a["followers"]),
            "following_count": to_int(a["following"]),
            "distinct_hashtags": len(a["hashtags"]),
            "distinct_mentions": len(a["mentions"]),
            "distinct_retweeted": len(a["retweeted_users"]),
        })
    return rows


def main():
    root = Path(__file__).resolve().parent.parent
    raw = root / "data" / "raw"
    out = root / "data" / "accounts.csv"

    all_rows = []
    for path in sorted(raw.glob("*_tweets.csv")):
        operation = path.name.replace("_tweets.csv", "")
        accounts = load_operation(path, operation)
        rows = build_features(accounts)
        all_rows.extend(rows)
        print(f"  {operation:18} {len(rows):>4} accounts")

    if not all_rows:
        print("no input found", file=sys.stderr)
        return 1

    fields = list(all_rows[0].keys())
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"\n{len(all_rows)} accounts -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
