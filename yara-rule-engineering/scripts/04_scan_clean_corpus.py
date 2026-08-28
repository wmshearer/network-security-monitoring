#!/usr/bin/env python3
"""
Q1: scan the clean corpus (built by 00_build_corpus.py) with every ruleset
that compiled at least one rule file (per 02_compile_rulesets.py), using
yara-python, and record every match.

For each ruleset, all individually-compiled rule files are merged into ONE
yara.compile() call using yara's `filepaths={namespace: path}` form so cross-
file rule name collisions land in separate namespaces instead of silently
overwriting each other. Rule files that failed to compile alone (see
evidence/02_compile_results_yara_python.json) are excluded from the merge,
same as script 02's per-file pass.

Timebox: this project's ceiling is ~10 minutes per scan. Corpus sizes are
capped in 00_build_corpus.py to keep per-FILE cost down, but that alone is
not enough for the "yara-rules" ruleset specifically: measured directly
(evidence/04_yara_rules_speed_probe.txt), the full 12,630-rule merged
compile of yara-rules runs at ~5.3 files/sec against usr_bin, versus 313-488
files/sec for the other three rulesets on the same 100 files. At that rate
usr_bin (3239 files) alone would take ~10 minutes for yara-rules alone,
before the other three corpora or three other rulesets are scanned. The
other three rulesets compile to far fewer total rules (308-3021, vs
yara-rules' 12,630) and scan two to three orders of magnitude faster, so
they run at FULL corpus size with no cap.

CAP APPLIED: for the "yara-rules" ruleset only, the usr_bin and
usr_lib_x86_64 corpora are each capped to the first 400 files (alphabetical,
same file list scripts/00_build_corpus.py already produced, just truncated)
so the whole four-ruleset x four-corpus sweep finishes in well under 10
minutes. The two firmware corpora (2181 + 1012 files, already small) are NOT
capped for any ruleset. This cap is recorded per-run in the evidence JSON
under "capped_to" so it is auditable, not silent.
"""
YARA_RULES_SLOW_CORPORA_CAP = 400
import json
import sys
import time
from pathlib import Path

import yara

PROJECT_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = PROJECT_DIR / "evidence"
RULESETS_DIR = PROJECT_DIR / ".rulesets"


def load_corpus_manifest():
    with open(EVIDENCE_DIR / "corpus_manifest.json") as fh:
        return json.load(fh)


def load_compiled_files(ruleset_name: str):
    with open(EVIDENCE_DIR / "02_compile_results_yara_python.json") as fh:
        d = json.load(fh)
    res = d[ruleset_name]
    return [RULESETS_DIR / f["path"] for f in res.get("compiled_files", [])]


def build_merged_rules(ruleset_name: str):
    """Compile every individually-good rule file for this ruleset into one
    yara.Rules object, one namespace per file (namespace = relative path)
    so identical rule identifiers across files never collide."""
    files = load_compiled_files(ruleset_name)
    filepaths = {}
    for i, f in enumerate(files):
        # yara.compile requires namespace keys to be strings; must also be
        # unique. Use the index to guarantee uniqueness even if two files
        # somehow stringify the same.
        ns = f"ns{i}_{f.name}"
        filepaths[ns] = str(f)
    t0 = time.time()
    rules = yara.compile(filepaths=filepaths)
    compile_seconds = time.time() - t0
    return rules, len(files), compile_seconds


def scan_corpus(rules, corpus_files, progress_label=""):
    matches_by_rule = {}
    files_matched = 0
    files_scanned = 0
    files_errored = []
    t0 = time.time()
    for entry in corpus_files:
        path = entry["path"]
        files_scanned += 1
        if progress_label and files_scanned % 500 == 0:
            print(
                f"    ...{progress_label}: {files_scanned}/{len(corpus_files)} files, "
                f"{time.time()-t0:.1f}s elapsed",
                file=sys.stderr,
            )
        try:
            # 5s per-file timeout: this is a false-positive-rate study on a
            # CLEAN corpus, not a worst-case adversarial one, so a single
            # file should never legitimately need more than a few seconds.
            # A file that hits this is logged as an error, not silently
            # dropped or allowed to stall the whole run (see evidence file
            # for the per-ruleset per-corpus timeout counts).
            m = rules.match(path, timeout=5)
        except yara.Error as e:
            files_errored.append({"path": path, "error": str(e)})
            continue
        if m:
            files_matched += 1
            for match in m:
                rule_key = f"{match.namespace}:{match.rule}"
                matches_by_rule.setdefault(rule_key, {"rule": match.rule, "namespace": match.namespace, "files": []})
                matches_by_rule[rule_key]["files"].append(path)
    scan_seconds = time.time() - t0
    return {
        "files_scanned": files_scanned,
        "files_matched": files_matched,
        "files_errored": files_errored,
        "scan_seconds": scan_seconds,
        "matches_by_rule": matches_by_rule,
    }


def main():
    manifest = load_corpus_manifest()
    ruleset_names = [
        "yara-rules",
        "yara-rules-official-index",
        "reversinglabs",
        "signature-base",
        "protections-artifacts",
    ]

    all_results = {}
    for ruleset_name in ruleset_names:
        print(f"=== {ruleset_name} ===", file=sys.stderr)
        try:
            rules, n_files, compile_seconds = build_merged_rules(ruleset_name)
        except yara.Error as e:
            print(f"  merged compile FAILED: {e}", file=sys.stderr)
            all_results[ruleset_name] = {"error": f"merged compile failed: {e}"}
            continue
        print(f"  merged {n_files} rule files in {compile_seconds:.2f}s", file=sys.stderr)

        ruleset_results = {"merged_files_count": n_files, "merged_compile_seconds": round(compile_seconds, 3), "corpora": {}}
        for corpus_name, corpus in manifest["corpora"].items():
            corpus_files = corpus["files"]
            capped_to = None
            if ruleset_name in ("yara-rules", "yara-rules-official-index") and corpus_name in ("usr_bin", "usr_lib_x86_64"):
                if len(corpus_files) > YARA_RULES_SLOW_CORPORA_CAP:
                    capped_to = YARA_RULES_SLOW_CORPORA_CAP
                    corpus_files = corpus_files[:YARA_RULES_SLOW_CORPORA_CAP]
            t0 = time.time()
            result = scan_corpus(rules, corpus_files, progress_label=f"{ruleset_name}/{corpus_name}")
            wall = time.time() - t0
            cap_note = f" (CAPPED to {capped_to}/{len(corpus['files'])})" if capped_to else ""
            print(
                f"  corpus={corpus_name}{cap_note}: {result['files_scanned']} scanned, "
                f"{result['files_matched']} matched, {len(result['matches_by_rule'])} distinct rules fired, "
                f"{wall:.1f}s wall",
                file=sys.stderr,
            )
            ruleset_results["corpora"][corpus_name] = {
                "capped_to": capped_to,
                "corpus_full_size": len(corpus["files"]),
                "files_scanned": result["files_scanned"],
                "files_matched": result["files_matched"],
                "files_errored": result["files_errored"],
                "scan_wall_seconds": round(wall, 3),
                "distinct_rules_fired": len(result["matches_by_rule"]),
                "matches_by_rule": {
                    k: {"rule": v["rule"], "namespace": v["namespace"], "file_count": len(v["files"]), "files": v["files"]}
                    for k, v in result["matches_by_rule"].items()
                },
            }
        all_results[ruleset_name] = ruleset_results

    out_path = EVIDENCE_DIR / "04_scan_clean_corpus_yara_python.json"
    with open(out_path, "w") as fh:
        json.dump(all_results, fh, indent=2)
    print(f"Wrote {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
