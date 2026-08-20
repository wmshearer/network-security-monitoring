"""Tests pinning the CIB findings, including the signal that collapsed."""
import csv, sys, subprocess
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
csv.field_size_limit(10**7)

ACCOUNTS = ROOT / "data" / "accounts.csv"
PAIRS = ROOT / "data" / "pairs.csv"


@pytest.fixture(scope="module")
def accounts():
    if not ACCOUNTS.exists():
        subprocess.run([sys.executable, str(ROOT/"src"/"features.py")], check=True)
    return list(csv.DictReader(open(ACCOUNTS)))


@pytest.fixture(scope="module")
def pairs():
    if not PAIRS.exists():
        subprocess.run([sys.executable, str(ROOT/"src"/"coordination.py")], check=True)
    return list(csv.DictReader(open(PAIRS)))


def test_corpus_size(accounts):
    """315 accounts across four operations. Pinned so a re-download that
    silently changes the corpus is visible."""
    assert len(accounts) == 315
    ops = {a["operation"] for a in accounts}
    assert ops == {"GRU_202012", "IRA_202012", "armenia_202012", "iran_202012"}


def test_volume_is_concentrated_in_a_few_accounts(accounts):
    """Finding 1. The median account does almost nothing, so a per-account
    median describes the dormant tail rather than the operation."""
    from collections import defaultdict
    by_op = defaultdict(list)
    for a in accounts:
        by_op[a["operation"]].append(int(a["tweets"]))
    for op, vols in by_op.items():
        vols.sort()
        top3 = sum(vols[-3:]) / sum(vols)
        assert top3 > 0.55, f"{op}: top 3 accounts now carry only {top3:.0%} of volume"


def test_automation_is_not_shared_across_operations(accounts):
    """Finding 2. Armenia runs on scheduling tools, GRU uses none. The feature
    describes provisioning, not whether something is an operation."""
    def share(op):
        rs = [a for a in accounts if a["operation"] == op]
        tot = sum(int(a["tweets"]) for a in rs)
        auto = sum(int(a["tweets"]) * float(a["automation_share"]) for a in rs)
        return auto / tot
    assert share("armenia_202012") > 0.9
    assert share("GRU_202012") < 0.05


def test_retweet_signal_has_almost_no_data(pairs):
    """Finding 3. shared_targets scores a coin flip because these operations
    barely retweet. That is a data limit, not a weak signal."""
    vals = [float(p["shared_targets"]) for p in pairs]
    nonzero = [v for v in vals if v > 0]
    assert len(nonzero) / len(vals) < 0.05, (
        "retweet overlap is now common; the 'unproven on this corpus' claim "
        "in docs/FINDING.md needs revisiting"
    )


def test_hashtag_signal_separates_same_operation_pairs(pairs):
    """The strongest within-corpus signal, and the separation is in the tail."""
    same = [float(p["shared_hashtags"]) for p in pairs if p["same_operation"] == "True"]
    diff = [float(p["shared_hashtags"]) for p in pairs if p["same_operation"] == "False"]
    same.sort(); diff.sort()
    p95_same = same[int(0.95 * len(same))]
    p95_diff = diff[int(0.95 * len(diff))]
    assert p95_same > p95_diff * 2, "hashtag separation has disappeared"


def test_control_collapses_cotiming_and_confirms_hashtags():
    """Finding 4, the load-bearing one. Co-timing is chance against benign
    accounts; hashtags survive. If this ever flips, the whole write-up is
    wrong and should fail loudly."""
    control_file = ROOT / "data" / "raw" / "legitimate_users_tweets.txt"
    if not control_file.exists():
        pytest.skip("control corpus not downloaded")

    from control import load_control, pair_scores, auc, CONTROL_TWEETS
    from coordination import load_profiles
    from collections import defaultdict

    cib = {u: p for u, p in load_profiles(ROOT/"data"/"raw").items() if p["tweets"] >= 20}
    by_op = defaultdict(dict)
    for uid, p in cib.items():
        by_op[p["operation"]][uid] = p
    cib_pairs = []
    for accounts_ in by_op.values():
        cib_pairs.extend(pair_scores(accounts_))

    ctrl = load_control(CONTROL_TWEETS)
    ctrl_pairs = pair_scores(ctrl)

    cot = auc([r["co_timing"] for r in cib_pairs], [r["co_timing"] for r in ctrl_pairs])
    tag = auc([r["shared_hashtags"] for r in cib_pairs],
              [r["shared_hashtags"] for r in ctrl_pairs])

    assert cot < 0.60, f"co-timing now scores {cot:.3f} against benign; it collapsed to chance before"
    assert tag > 0.80, f"hashtag signal now scores {tag:.3f} against benign; it held at 0.888 before"
    assert tag > cot, "the ordering of the two signals has reversed"
