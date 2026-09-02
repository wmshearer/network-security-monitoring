#!/usr/bin/env python3
"""
Q3: does YARA-X agree with YARA 4.x? For each ruleset, take the files that
compiled successfully under BOTH yara-python (evidence/02) and yara-x
(evidence/03) -- that is the only fair basis for a scan-behaviour diff, since
a file that fails to compile in one engine cannot be scanned with it at all.
Build one merged ruleset per engine from exactly that common file list, scan
the SAME corpus with each, and diff the match results per file.

This only tells you whether the engines agree on rules BOTH can compile.
Compile-time portability (rules that work in one engine but not the other)
is a separate, already-quantified finding in evidence/02 and evidence/03;
this script does not re-litigate it, it isolates the orthogonal question of
runtime agreement.
"""
import json
import sys
import time
from pathlib import Path

import yara
import yara_x

PROJECT_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = PROJECT_DIR / "evidence"
RULESETS_DIR = PROJECT_DIR / ".rulesets"

RULESET_NAMES = ["yara-rules-official-index", "reversinglabs", "signature-base", "protections-artifacts"]

# Scanning through BOTH engines' Python bindings, file by file, is the
# expensive part; cap usr_bin/usr_lib_x86_64 sample sizes so the full
# four-ruleset sweep finishes well inside the ~10 minute timebox. Measured
# directly (evidence/05_diff_speed_note.txt): yara-rules-official-index
# scans 100 usr_bin files in 18.0s under yara-python vs 1.0s under yara-x on
# the SAME 416-file common ruleset -- an ~17x difference that is itself a Q3
# finding, but it means the yara-python side of this specific ruleset sets
# the pace for how large a sample is affordable.
USR_BIN_SAMPLE_SIZE = 300
SLOW_RULESETS = {"yara-rules-official-index"}
SLOW_RULESET_SAMPLE_SIZE = 150


def load_common_files(ruleset_name: str):
    with open(EVIDENCE_DIR / "02_compile_results_yara_python.json") as fh:
        d2 = json.load(fh)
    with open(EVIDENCE_DIR / "03_compile_results_yara_x.json") as fh:
        d3 = json.load(fh)
    ok2 = {f["path"] for f in d2[ruleset_name]["compiled_files"]}
    ok3 = {f["path"] for f in d3[ruleset_name]["compiled_files"]}
    common = sorted(ok2 & ok3)
    return common, len(ok2), len(ok3)


def build_yara_python_rules(common_files):
    filepaths = {f"ns{i}": str(RULESETS_DIR / p) for i, p in enumerate(common_files)}
    return yara.compile(filepaths=filepaths)


def build_yara_x_rules(common_files):
    compiler = yara_x.Compiler()
    for i, p in enumerate(common_files):
        compiler.new_namespace(f"ns{i}")
        src = (RULESETS_DIR / p).read_text(errors="replace")
        compiler.add_source(src, origin=str(RULESETS_DIR / p))
    return compiler.build()


def scan_with_yara_python(rules, files):
    out = {}
    for entry in files:
        try:
            m = rules.match(entry["path"], timeout=5)
        except yara.Error as e:
            out[entry["path"]] = {"error": str(e)}
            continue
        out[entry["path"]] = sorted({f"{match.namespace}:{match.rule}" for match in m})
    return out


def scan_with_yara_x(rules, files):
    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(5)
    out = {}
    for entry in files:
        try:
            res = scanner.scan_file(entry["path"])
        except Exception as e:  # noqa: BLE001
            out[entry["path"]] = {"error": str(e)}
            continue
        out[entry["path"]] = sorted({f"{r.namespace}:{r.identifier}" for r in res.matching_rules})
    return out


def load_corpus_manifest():
    with open(EVIDENCE_DIR / "corpus_manifest.json") as fh:
        return json.load(fh)


def get_sample_files(manifest, corpus_name, ruleset_name):
    files = manifest["corpora"][corpus_name]["files"]
    if corpus_name in ("usr_bin", "usr_lib_x86_64"):
        cap = SLOW_RULESET_SAMPLE_SIZE if ruleset_name in SLOW_RULESETS else USR_BIN_SAMPLE_SIZE
        if len(files) > cap:
            return files[:cap]
    return files


def diff_results(py_results, x_results):
    agree = 0
    disagree = 0
    disagreements = []
    for path in py_results:
        py_val = py_results[path]
        x_val = x_results.get(path)
        if isinstance(py_val, dict) or isinstance(x_val, dict):
            # one side errored; record but don't count as agree/disagree
            disagreements.append({"path": path, "yara_python": py_val, "yara_x": x_val, "reason": "scan_error"})
            continue
        if py_val == x_val:
            agree += 1
        else:
            disagree += 1
            disagreements.append(
                {
                    "path": path,
                    "yara_python_only": sorted(set(py_val) - set(x_val)),
                    "yara_x_only": sorted(set(x_val) - set(py_val)),
                }
            )
    return agree, disagree, disagreements


def main():
    manifest = load_corpus_manifest()
    all_results = {}

    for ruleset_name in RULESET_NAMES:
        print(f"=== {ruleset_name} ===", file=sys.stderr)
        common_files, n_ok_py, n_ok_x = load_common_files(ruleset_name)
        print(
            f"  yara-python compiled {n_ok_py} files, yara-x compiled {n_ok_x} files, "
            f"{len(common_files)} in common",
            file=sys.stderr,
        )
        if not common_files:
            all_results[ruleset_name] = {"error": "no common compiled files between engines"}
            continue

        t0 = time.time()
        py_rules = build_yara_python_rules(common_files)
        py_compile_s = time.time() - t0
        t0 = time.time()
        x_rules = build_yara_x_rules(common_files)
        x_compile_s = time.time() - t0
        print(f"  merged-common compile: yara-python {py_compile_s:.2f}s, yara-x {x_compile_s:.2f}s", file=sys.stderr)

        ruleset_result = {
            "common_files_count": len(common_files),
            "yara_python_compiled_count": n_ok_py,
            "yara_x_compiled_count": n_ok_x,
            "merged_compile_seconds": {"yara_python": round(py_compile_s, 3), "yara_x": round(x_compile_s, 3)},
            "corpora": {},
        }

        for corpus_name in manifest["corpora"]:
            sample = get_sample_files(manifest, corpus_name, ruleset_name)
            t0 = time.time()
            py_res = scan_with_yara_python(py_rules, sample)
            py_scan_s = time.time() - t0
            t0 = time.time()
            x_res = scan_with_yara_x(x_rules, sample)
            x_scan_s = time.time() - t0
            agree, disagree, disagreements = diff_results(py_res, x_res)
            print(
                f"  corpus={corpus_name} (n={len(sample)}): agree={agree} disagree={disagree} "
                f"yara-python={py_scan_s:.1f}s yara-x={x_scan_s:.1f}s",
                file=sys.stderr,
            )
            ruleset_result["corpora"][corpus_name] = {
                "sample_size": len(sample),
                "full_corpus_size": len(manifest["corpora"][corpus_name]["files"]),
                "agree": agree,
                "disagree": disagree,
                "scan_seconds": {"yara_python": round(py_scan_s, 3), "yara_x": round(x_scan_s, 3)},
                "disagreements": disagreements,
            }
        all_results[ruleset_name] = ruleset_result

    out_path = EVIDENCE_DIR / "05_diff_yara_vs_yarax.json"
    with open(out_path, "w") as fh:
        json.dump(all_results, fh, indent=2)
    print(f"Wrote {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
