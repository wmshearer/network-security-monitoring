#!/usr/bin/env python3
"""
Q3: check which YARA modules each engine's Python binding supports, by
attempting to compile a trivial one-line rule that imports each module.
This surfaced a real finding while investigating why some public rules
failed to compile under yara-python but not yara-x: "hash" and "cuckoo" are
built into yara-x 1.20.0's bundled modules but NOT into this yara-python
4.5.4 build (yara-python links against libyara, whose module set depends on
how it was compiled with --enable-hash/--enable-cuckoo, and this system's
libyara10 4.5.8-1 package was not built with them). "androguard" and "magic"
are unsupported by BOTH bindings.
"""
import json
from pathlib import Path

import yara
import yara_x

PROJECT_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = PROJECT_DIR / "evidence"

MODULES_TO_CHECK = ["pe", "elf", "math", "hash", "cuckoo", "androguard", "magic"]


def check_module(mod: str) -> dict:
    src = f'import "{mod}"\nrule t {{ condition: true }}'

    py_ok, py_err = True, None
    try:
        yara.compile(source=src)
    except Exception as e:  # noqa: BLE001
        py_ok, py_err = False, str(e)

    x_ok, x_err = True, None
    try:
        yara_x.compile(src)
    except Exception as e:  # noqa: BLE001
        x_ok, x_err = False, str(e)

    return {
        "yara_python_compiles": py_ok,
        "yara_python_error": py_err,
        "yara_x_compiles": x_ok,
        "yara_x_error": x_err,
    }


def main():
    results = {mod: check_module(mod) for mod in MODULES_TO_CHECK}
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    out_path = EVIDENCE_DIR / "03b_module_support.json"
    with open(out_path, "w") as fh:
        json.dump(results, fh, indent=2)
    for mod, r in results.items():
        print(f"{mod}: yara-python={r['yara_python_compiles']} yara-x={r['yara_x_compiles']}")
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
