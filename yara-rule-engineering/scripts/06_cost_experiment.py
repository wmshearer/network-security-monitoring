#!/usr/bin/env python3
"""
Q2: controlled cost experiment. rules/cost_experiment.yar defines four rules
that all target the SAME 28 bytes of content ("/lib64/ld-linux-x86-64.so.2")
via four different pattern-matching constructs: literal string, regex, hex
with wildcard nibbles, and a `for` loop over elf.sections. Verified
separately (evidence/06_cost_experiment_match_parity.json) that the first
three produce byte-identical match sets on the usr_bin corpus (2278/2278
files each); the elf-loop variant differs by 36 files, explained in
FINDINGS.md, and is reported as a distinct, not equivalent, measurement.

Each rule is compiled and scanned ALONE (not merged with the others) against
the SAME corpus (usr_bin, full 3239 files), repeated N times, to get a wall-
clock distribution per construct rather than a single point estimate. Runs
are repeated because a single run cannot distinguish real cost difference
from noise (disk cache state, OS scheduling, etc).
"""
import json
import statistics
import sys
import time
from pathlib import Path

import yara

PROJECT_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = PROJECT_DIR / "evidence"
RULES_FILE = PROJECT_DIR / "rules" / "cost_experiment.yar"

REPEATS = 7


def load_corpus_files():
    with open(EVIDENCE_DIR / "corpus_manifest.json") as fh:
        manifest = json.load(fh)
    return manifest["corpora"]["usr_bin"]["files"]


def extract_single_rule_source(rule_name: str) -> str:
    """Pull out exactly one rule's source block (plus its `import` line if
    the rule needs one) from cost_experiment.yar, so each construct can be
    compiled and timed in total isolation from the other three."""
    text = RULES_FILE.read_text()
    needs_elf_import = rule_name == "cost_elf_loop"
    start = text.index(f"rule {rule_name} ")
    # Find the matching closing brace by counting braces from the rule's own opening one.
    open_idx = text.index("{", start)
    depth = 0
    i = open_idx
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    rule_src = text[start : i + 1]
    if needs_elf_import:
        rule_src = 'import "elf"\n' + rule_src
    return rule_src


def time_rule(rule_name: str, corpus_files):
    src = extract_single_rule_source(rule_name)
    rules = yara.compile(source=src)

    match_count = 0
    for entry in corpus_files:
        try:
            m = rules.match(entry["path"], timeout=5)
        except yara.Error:
            continue
        if m:
            match_count += 1

    run_times = []
    for _ in range(REPEATS):
        t0 = time.perf_counter()
        for entry in corpus_files:
            try:
                rules.match(entry["path"], timeout=5)
            except yara.Error:
                continue
        run_times.append(time.perf_counter() - t0)
    return {
        "rule": rule_name,
        "match_count": match_count,
        "repeats": REPEATS,
        "run_times_seconds": [round(t, 4) for t in run_times],
        "mean_seconds": round(statistics.mean(run_times), 4),
        "stdev_seconds": round(statistics.stdev(run_times), 4) if len(run_times) > 1 else 0.0,
        "min_seconds": round(min(run_times), 4),
        "max_seconds": round(max(run_times), 4),
    }


def main():
    corpus_files = load_corpus_files()
    print(f"Corpus: usr_bin, {len(corpus_files)} files", file=sys.stderr)

    results = {}
    for rule_name in ["cost_literal_string", "cost_regex", "cost_hex_wildcard", "cost_elf_loop"]:
        print(f"Timing {rule_name} ({REPEATS} repeats over {len(corpus_files)} files)...", file=sys.stderr)
        t0 = time.time()
        result = time_rule(rule_name, corpus_files)
        print(
            f"  matches={result['match_count']} mean={result['mean_seconds']}s "
            f"stdev={result['stdev_seconds']}s min={result['min_seconds']}s max={result['max_seconds']}s "
            f"(probe took {time.time()-t0:.1f}s wall)",
            file=sys.stderr,
        )
        results[rule_name] = result

    match_parity = {
        "cost_literal_string_vs_cost_regex_match_count_equal": results["cost_literal_string"]["match_count"]
        == results["cost_regex"]["match_count"],
        "cost_literal_string_vs_cost_hex_wildcard_match_count_equal": results["cost_literal_string"]["match_count"]
        == results["cost_hex_wildcard"]["match_count"],
        "cost_literal_string_match_count": results["cost_literal_string"]["match_count"],
        "cost_elf_loop_match_count": results["cost_elf_loop"]["match_count"],
        "note": "cost_elf_loop is NOT expected to equal the byte-scan rules; see FINDINGS.md for the 36-file explanation.",
    }

    out = {"corpus_file_count": len(corpus_files), "repeats": REPEATS, "results": results, "match_parity": match_parity}
    out_path = EVIDENCE_DIR / "06_cost_experiment_timing.json"
    with open(out_path, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"Wrote {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
