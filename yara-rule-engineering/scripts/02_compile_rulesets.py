#!/usr/bin/env python3
"""
Compile every individual rule FILE (not rule, file) in each cloned ruleset,
one file at a time, with yara-python. Compiling a whole ruleset as a single
unit fails immediately on the first bad file (verified: compiling
.rulesets/yara-rules/index.yar fails at malware/RAT_CrossRAT.yar with
"invalid field name md5" and never reaches the rest), so per-file compilation
is the only way to get an honest count of how many rules actually work.

For each ruleset this produces one evidence file: which files compiled, which
did not (with the exact yara-python error string), and how many total rule
identifiers came out of the files that DID compile.

Rules requiring the "hash", "cuckoo", "androguard", or "magic" modules are
expected to fail under yara-python because those modules are not built into
the yara-python wheel; androguard/magic also fail under yara-x, but
hash/cuckoo compile fine under yara-x (see evidence/03_yara_x_module_support.txt).
This is recorded, not filtered out, so the compiled/failed counts are real.
"""
import json
import sys
import time
from pathlib import Path

import yara

PROJECT_DIR = Path(__file__).resolve().parent.parent
RULESETS_DIR = PROJECT_DIR / ".rulesets"
EVIDENCE_DIR = PROJECT_DIR / "evidence"

RULESET_SPECS = {
    "yara-rules": {
        "root": RULESETS_DIR / "yara-rules",
        "extensions": [".yar"],
        # index_gen.sh output and top-level *_index.yar files are include-only
        # wrappers around the category dirs; compiling both the index AND the
        # category files would double count. Skip *_index.yar and index*.yar.
        "skip_name_suffixes": ["_index.yar"],
        "skip_name_prefixes": ["index"],
        # "deprecated" dir is explicitly retired by the upstream project.
        "skip_dir_names": ["deprecated"],
    },
    # Same ruleset, but scoped to EXACTLY what the project's own index.yar
    # includes (verified by grepping index.yar for "include" lines: it
    # references antidebug_antivm, capabilities, crypto, cve_rules, email,
    # exploit_kits, maldocs, malware, packers, webshells -- NOT utils,
    # mobile_malware, or deprecated). See evidence/ruleset_index_scope.txt.
    # This exists because utils/ contains generic helper patterns
    # (domain/url/ip/base64 "does this look like a domain" regexes) never
    # meant to be deployed as standalone detection rules, and scanning with
    # them included produces a wildly different, misleading false-positive
    # rate. Reported side by side in FINDINGS.md, not silently substituted.
    "yara-rules-official-index": {
        "root": RULESETS_DIR / "yara-rules",
        "extensions": [".yar"],
        "skip_name_suffixes": ["_index.yar"],
        "skip_name_prefixes": ["index"],
        "skip_dir_names": ["deprecated", "utils", "mobile_malware"],
    },
    "reversinglabs": {
        "root": RULESETS_DIR / "reversinglabs" / "yara",
        "extensions": [".yara"],
        "skip_name_suffixes": [],
        "skip_name_prefixes": [],
        "skip_dir_names": [],
    },
    "signature-base": {
        "root": RULESETS_DIR / "signature-base" / "yara",
        "extensions": [".yar"],
        "skip_name_suffixes": [],
        "skip_name_prefixes": [],
        "skip_dir_names": [],
    },
    "protections-artifacts": {
        "root": RULESETS_DIR / "protections-artifacts" / "yara",
        "extensions": [".yar"],
        "skip_name_suffixes": [],
        "skip_name_prefixes": [],
        "skip_dir_names": [],
    },
}


def should_skip(path: Path, spec: dict) -> bool:
    if any(part in spec["skip_dir_names"] for part in path.parts):
        return True
    name = path.name
    if any(name.endswith(suf) for suf in spec["skip_name_suffixes"]):
        return True
    if any(name.startswith(pre) for pre in spec["skip_name_prefixes"]):
        return True
    return False


def count_rules_in_source(compiled: "yara.Rules") -> int:
    return len(list(compiled))


def compile_ruleset(name: str, spec: dict) -> dict:
    root = spec["root"]
    if not root.exists():
        return {"name": name, "root": str(root), "error": "not cloned (run scripts/01_fetch_rulesets.sh)"}

    files = []
    for ext in spec["extensions"]:
        files.extend(sorted(root.rglob(f"*{ext}")))
    files = [f for f in files if not should_skip(f, spec)]

    compiled_files = []
    failed_files = []
    total_rules = 0

    for f in files:
        try:
            rules = yara.compile(filepath=str(f))
            n = count_rules_in_source(rules)
            compiled_files.append({"path": str(f.relative_to(RULESETS_DIR)), "rule_count": n})
            total_rules += n
        except yara.Error as e:
            failed_files.append({"path": str(f.relative_to(RULESETS_DIR)), "error": str(e)})
        except Exception as e:  # noqa: BLE001 - record any unexpected error type too
            failed_files.append({"path": str(f.relative_to(RULESETS_DIR)), "error": f"{type(e).__name__}: {e}"})

    return {
        "name": name,
        "root": str(root),
        "files_total": len(files),
        "files_compiled": len(compiled_files),
        "files_failed": len(failed_files),
        "rules_compiled_total": total_rules,
        "compiled_files": compiled_files,
        "failed_files": failed_files,
    }


def main():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    all_results = {}
    for name, spec in RULESET_SPECS.items():
        print(f"Compiling ruleset: {name}", file=sys.stderr)
        t0 = time.time()
        result = compile_ruleset(name, spec)
        result["compile_wall_seconds"] = round(time.time() - t0, 2)
        all_results[name] = result
        if "error" in result:
            print(f"  SKIPPED: {result['error']}", file=sys.stderr)
            continue
        print(
            f"  {result['files_total']} files, {result['files_compiled']} compiled "
            f"({result['rules_compiled_total']} rules), {result['files_failed']} failed, "
            f"{result['compile_wall_seconds']}s",
            file=sys.stderr,
        )

    out_path = EVIDENCE_DIR / "02_compile_results_yara_python.json"
    with open(out_path, "w") as fh:
        json.dump(all_results, fh, indent=2)
    print(f"Wrote {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
