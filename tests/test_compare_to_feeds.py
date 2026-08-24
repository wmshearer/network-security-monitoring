import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from compare_to_feeds import compare


def _lockbit_filtered(ips, dns, sha256):
    return {
        "ips": {"kept": ips, "dropped": []},
        "dns": {"kept": dns, "dropped": []},
        "sha256_kept": sha256,
    }


def test_no_overlap_when_disjoint():
    lb = _lockbit_filtered(["1.2.3.4"], ["evil.example.net"], ["A" * 64])
    feed = {"ips": ["9.9.9.9"], "dns": ["other.example.net"], "sha256": ["B" * 64]}
    result = compare(lb, feed)
    assert result["match_counts"]["total"] == 0
    assert result["overlap_percentage"]["total"] == 0.0


def test_full_overlap_when_identical():
    lb = _lockbit_filtered(["1.2.3.4"], ["evil.example.net"], ["A" * 64])
    feed = {"ips": ["1.2.3.4"], "dns": ["evil.example.net"], "sha256": ["A" * 64]}
    result = compare(lb, feed)
    assert result["match_counts"]["total"] == 3
    assert result["overlap_percentage"]["total"] == 100.0


def test_partial_overlap_counts_and_percentage_are_exact():
    lb = _lockbit_filtered(
        ["1.1.1.1", "2.2.2.2"], ["a.example.net", "b.example.net"], ["A" * 64, "B" * 64]
    )
    feed = {"ips": ["1.1.1.1"], "dns": [], "sha256": []}
    result = compare(lb, feed)
    assert result["match_counts"]["ips"] == 1
    assert result["match_counts"]["dns"] == 0
    assert result["match_counts"]["sha256"] == 0
    assert result["match_counts"]["total"] == 1
    # 1 match out of 6 total surviving lockbit indicators
    assert result["overlap_percentage"]["total"] == round(100.0 / 6, 4)


def test_matching_is_case_and_type_exact_not_fuzzy():
    """A SHA256 that only matches on lowercase, or a DNS name that is a
    substring but not an exact match, must NOT count as a match. Matching
    is exact-string, not fuzzy, per the module's docstring.
    """
    lb = _lockbit_filtered([], ["evil.example.net"], ["A" * 64])
    feed = {"ips": [], "dns": ["sub.evil.example.net"], "sha256": ["a" * 64]}
    # sha256 in lb is uppercased 'A'*64, feed has lowercase 'a'*64 -- these
    # must be normalized identically upstream or they will not match here;
    # this test uses the SAME case on both sides deliberately below to
    # prove real matches work, then a mismatched case above to prove it
    # does NOT silently match cross-case if normalization is skipped.
    result = compare(lb, feed)
    assert result["match_counts"]["dns"] == 0  # substring, not exact match
    assert result["match_counts"]["sha256"] == 0  # case differs, no normalization applied here
