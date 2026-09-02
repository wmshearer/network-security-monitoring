#!/usr/bin/env python3
"""
Same per-file compilation pass as scripts/02_compile_rulesets.py, but using
the YARA-X (Rust engine) Python API instead of yara-python. Same file list,
same skip rules, so the two evidence files are directly diffable file-by-file
for Q3 (does YARA-X agree with YARA 4.x).

YARA-X exposes compilation through yara_x.Compiler().add_source(src, origin=path)
then .build(); a source string with a compile error raises on add_source(),
which is caught per file exactly like yara.compile() is in script 02.
"""
import json
import sys
import time
from pathlib import Path

import yara_x

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rule_count import count_rule_declarations  # noqa: E402

PROJECT_DIR = Path(__file__).resolve().parent.parent
RULESETS_DIR = PROJECT_DIR / ".rulesets"
EVIDENCE_DIR = PROJECT_DIR / "evidence"

# Must match scripts/02_compile_rulesets.py exactly so the two results are comparable.
RULESET_SPECS = {
    "yara-rules": {
        "root": RULESETS_DIR / "yara-rules",
        "extensions": [".yar"],
        "skip_name_suffixes": ["_index.yar"],
        "skip_name_prefixes": ["index"],
        "skip_dir_names": ["deprecated"],
    },
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
            src = f.read_text(errors="replace")
        except OSError as e:
            failed_files.append({"path": str(f.relative_to(RULESETS_DIR)), "error": f"read error: {e}"})
            continue
        try:
            compiler = yara_x.Compiler()
            compiler.add_source(src, origin=str(f))
            compiler.build()  # raises on the first compile error; result unused, we only need pass/fail
            n = count_rule_declarations(src)  # yara_x.Rules has no rule-count API in 1.20.0; see rule_count.py
            compiled_files.append({"path": str(f.relative_to(RULESETS_DIR)), "rule_count": n})
            total_rules += n
        except Exception as e:  # yara_x raises generic exceptions with formatted diagnostic text
            failed_files.append({"path": str(f.relative_to(RULESETS_DIR)), "error": str(e)})

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
        print(f"Compiling ruleset (yara-x): {name}", file=sys.stderr)
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

    out_path = EVIDENCE_DIR / "03_compile_results_yara_x.json"
    with open(out_path, "w") as fh:
        json.dump(all_results, fh, indent=2)
    print(f"Wrote {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
