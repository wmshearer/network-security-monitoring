"""
Pins the Q2 controlled-experiment numbers: match parity across constructs,
and the timing result (literal/regex/hex indistinguishable, elf-loop slower).
"""


def test_literal_regex_hex_wildcard_match_identical_file_count(cost_experiment_results):
    r = cost_experiment_results["results"]
    assert r["cost_literal_string"]["match_count"] == 2278
    assert r["cost_regex"]["match_count"] == 2278
    assert r["cost_hex_wildcard"]["match_count"] == 2278


def test_elf_loop_matches_a_different_count(cost_experiment_results):
    """Not expected to equal the byte-scan rules; see FINDINGS.md for the
    36-file explanation (qemu cross-arch binaries have .dynstr but not this
    literal linker-path substring, and vice versa for 2 non-ELF matches)."""
    r = cost_experiment_results["results"]
    assert r["cost_elf_loop"]["match_count"] == 2310
    assert r["cost_elf_loop"]["match_count"] != r["cost_literal_string"]["match_count"]


def test_literal_regex_hex_wildcard_are_statistically_indistinguishable(cost_experiment_results):
    """Mean times for the three byte-scan constructs must each fall within
    the others' mean +/- 3 stdev -- i.e. not a real difference, just noise."""
    r = cost_experiment_results["results"]
    names = ["cost_literal_string", "cost_regex", "cost_hex_wildcard"]
    means = {n: r[n]["mean_seconds"] for n in names}
    stdevs = {n: r[n]["stdev_seconds"] for n in names}
    for a in names:
        for b in names:
            if a == b:
                continue
            band = max(stdevs[a], stdevs[b], 0.05) * 3
            assert abs(means[a] - means[b]) < band, f"{a} vs {b}: {means[a]} vs {means[b]}, band {band}"


def test_elf_loop_is_meaningfully_slower(cost_experiment_results):
    """The elf-loop construct must be at least 1.5x slower than the literal
    string construct on the mean -- this is the real, reported difference,
    not noise (contrast with the identical-cost byte-scan constructs)."""
    r = cost_experiment_results["results"]
    assert r["cost_elf_loop"]["mean_seconds"] > 1.5 * r["cost_literal_string"]["mean_seconds"]


def test_repeats_is_at_least_five(cost_experiment_results):
    assert cost_experiment_results["repeats"] >= 5
