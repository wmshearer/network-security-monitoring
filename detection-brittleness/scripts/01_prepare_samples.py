#!/usr/bin/env python3
"""Stage 1: build per-sample-group input directories for Zircolite.

Reads manifest/technique_manifest.json, copies (or symlinks) the referenced
raw files under _corpora/ into evidence/samples/<technique>/<group>/, and for
attack_data's raw XML .log files (one <Event> per line, no root element)
writes a wrapped copy with a single <Events> root so lxml.etree.iterparse
(which Zircolite's -x mode uses) can parse the whole file instead of stopping
after the first top-level element.

This does not touch the source corpora (read-only, referenced by absolute
path). It writes only into this project's evidence/samples/ directory, which
is derived data, not a copy of the corpus, and is excluded from git via
.gitignore except for a manifest of what was staged.

Idempotent: re-running clears and rebuilds evidence/samples/.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPORA = Path("/home/kali/director/projects/_corpora")
MANIFEST = ROOT / "manifest" / "technique_manifest.json"
SAMPLES_DIR = ROOT / "evidence" / "samples"


def wrap_xml_lines(src: Path, dst: Path) -> int:
    """Wrap a file of one-<Event>-per-line XML fragments in a single <Events> root.

    Returns the number of <Event elements written (a crude count by substring,
    used only for the staging log, not for the final scoring numbers).
    """
    lines = [l for l in src.read_text(errors="replace").split("\n") if l.strip()]
    dst.parent.mkdir(parents=True, exist_ok=True)
    with dst.open("w") as f:
        f.write("<Events>\n")
        for line in lines:
            f.write(line + "\n")
        f.write("</Events>\n")
    return sum(1 for l in lines if "<Event " in l)


def stage_attack_data_log(rel_path: str, dest_dir: Path, log: list[str]) -> None:
    """One or more attack_data .log paths, space-separated tokens after globbing hints stripped."""
    # rel_path in the manifest may embed a parenthetical list of extra files;
    # only the first path token before a space is a real relative path, so we
    # resolve explicit file names when given, else treat rel_path as literal.
    candidates = [rel_path.split(" (")[0].split(" ")[0]]
    for c in candidates:
        src = CORPORA / "attack_data" / c.lstrip("/")
        if not src.exists():
            log.append(f"MISSING: {src}")
            continue
        dst = dest_dir / (Path(c).stem + ".xml")
        n = wrap_xml_lines(src, dst)
        log.append(f"wrapped {src} -> {dst} ({n} <Event> tags)")


def stage_evtx_files(files: list[dict], src_dir: Path, dest_dir: Path, log: list[str]) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    for entry in files:
        name = entry["name"]
        src = src_dir / name
        if not src.exists():
            log.append(f"MISSING: {src}")
            continue
        dst = dest_dir / name
        shutil.copyfile(src, dst)
        log.append(f"copied {src} -> {dst}")


def main() -> None:
    manifest = json.loads(MANIFEST.read_text())
    if SAMPLES_DIR.exists():
        shutil.rmtree(SAMPLES_DIR)
    SAMPLES_DIR.mkdir(parents=True)

    log: list[str] = []

    for tech in manifest["techniques"]:
        tid = tech["technique_id"]
        for sample in tech["samples"]:
            corpus = sample["corpus"]

            if corpus == "attack_data":
                tool = sample["tool_or_source"]
                group_slug = "snapattack" if "SnapAttack" in tool else "atomic_red_team"
                dest_dir = SAMPLES_DIR / tid / f"attack_data_{group_slug}"
                dest_dir.mkdir(parents=True, exist_ok=True)

                if "event_count_by_file" in sample:
                    # atomic_red_team T1003.001: multiple named files
                    base = Path(sample["path"].split(" (")[0]).parent
                    for fname in sample["event_count_by_file"]:
                        rel = str(base / fname)
                        stage_attack_data_log(rel, dest_dir, log)
                elif tid == "T1059.001" and group_slug == "atomic_red_team":
                    base = Path(sample["path"].split(" (")[0]).parent
                    names = ["windows-sysmon.log", "4104-psremoting-windows-powershell.log",
                             "get_ciminstance_windows-powershell.log",
                             "start_stop_service_windows-powershell.log"]
                    for fname in names:
                        stage_attack_data_log(str(base / fname), dest_dir, log)
                else:
                    stage_attack_data_log(sample["path"], dest_dir, log)

            elif corpus == "EVTX-ATTACK-SAMPLES":
                dest_dir = SAMPLES_DIR / tid / "evtx_attack_samples"
                src_dir = CORPORA / "EVTX-ATTACK-SAMPLES" / "Credential Access"
                stage_evtx_files(sample["files"], src_dir, dest_dir, log)

            elif corpus == "EVTX-to-MITRE-Attack":
                dest_dir = SAMPLES_DIR / tid / "evtx_to_mitre_attack"
                if tid == "T1003.001":
                    src_dir = CORPORA / "EVTX-to-MITRE-Attack" / "TA0006-Credential Access" / "T1003-Credential dumping"
                else:
                    src_dir = CORPORA / "EVTX-to-MITRE-Attack" / "TA0002-Execution" / "T1059.001-PowerShell"
                stage_evtx_files(sample["files"], src_dir, dest_dir, log)

    log_path = ROOT / "evidence" / "01_staging_log.txt"
    log_path.write_text("\n".join(log) + "\n")
    print(f"staged samples under {SAMPLES_DIR}")
    print(f"staging log: {log_path} ({len(log)} lines)")
    missing = [l for l in log if l.startswith("MISSING")]
    if missing:
        print(f"WARNING: {len(missing)} missing source files, see log")


if __name__ == "__main__":
    main()
