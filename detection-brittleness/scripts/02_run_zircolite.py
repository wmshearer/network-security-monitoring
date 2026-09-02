#!/usr/bin/env python3
"""Stage 2: run Zircolite, unmodified, against every staged sample group.

For each technique/group directory under evidence/samples/, runs Zircolite
once with the vendored windows_merged Sigma ruleset (the documented default
for EVTX in Zircolite's own README) and saves the raw JSON detection output
to evidence/zircolite_raw/<technique>/<group>.json before anything is
summarized. Nothing here computes a "survives / misses" verdict; that is
done in 03_build_matrix.py by reading these raw files back.

Zircolite is vendored at detection-as-code/vendor/Zircolite (sibling project,
referenced read-only, never modified). Its already-provisioned .venv is used
to avoid re-solving the orjson/lxml dependency set.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLES_DIR = ROOT / "evidence" / "samples"
RAW_DIR = ROOT / "evidence" / "zircolite_raw"

VENV_PY = Path("/home/kali/director/projects/detection-as-code/.venv/bin/python3")
ZIRCOLITE_PY = Path("/home/kali/director/projects/detection-as-code/vendor/Zircolite/zircolite.py")
RULESET = Path("/home/kali/director/projects/detection-as-code/vendor/Zircolite/rules/rules_windows_merged.json")

TIMEOUT_S = 300  # 5 min per group; largest group here is ~22k events, well under this


def run_group(technique: str, group_dir: Path) -> dict:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RAW_DIR / technique / f"{group_dir.name}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    log_path = out_path.with_suffix(".log.txt")

    xml_files = list(group_dir.glob("*.xml"))
    extra_flag = ["-x"] if xml_files else []

    cmd = [
        str(VENV_PY), str(ZIRCOLITE_PY),
        "-e", str(group_dir),
        *extra_flag,
        "-r", str(RULESET),
        "-o", str(out_path),
    ]
    t0 = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_S)
    dt = time.time() - t0
    log_path.write_text(
        f"cmd: {' '.join(cmd)}\nreturncode: {proc.returncode}\nduration_s: {dt:.2f}\n\n"
        f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}\n"
    )
    if not out_path.exists():
        out_path.write_text("[]")  # Zircolite writes nothing when zero rules match; record that as an empty match list

    matches = json.loads(out_path.read_text() or "[]")
    return {
        "technique": technique,
        "group": group_dir.name,
        "returncode": proc.returncode,
        "duration_s": round(dt, 2),
        "rules_matched": len(matches),
        "total_matched_events": sum(m.get("count", 0) for m in matches),
        "out_path": str(out_path),
        "log_path": str(log_path),
    }


def main() -> None:
    summary = []
    for technique_dir in sorted(SAMPLES_DIR.iterdir()):
        if not technique_dir.is_dir():
            continue
        for group_dir in sorted(technique_dir.iterdir()):
            if not group_dir.is_dir():
                continue
            print(f"[{technique_dir.name}] running Zircolite on {group_dir.name} ...")
            result = run_group(technique_dir.name, group_dir)
            print(f"  -> {result['rules_matched']} rules matched, "
                  f"{result['total_matched_events']} events, {result['duration_s']}s")
            summary.append(result)

    summary_path = ROOT / "evidence" / "02_zircolite_run_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    print(f"\nwrote {summary_path}")


if __name__ == "__main__":
    main()
