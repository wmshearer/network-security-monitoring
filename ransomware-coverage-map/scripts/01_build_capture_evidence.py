#!/usr/bin/env python3
"""Stage 1: for every family x technique cell, determine whether the
behaviour is PRESENT in that family's raw captured log files.

This answers only "did this behaviour happen in this capture", which is the
GREY-vs-not-GREY question. It says nothing about whether a detection fires;
that is stage 2 (scripts/02_score_detection_coverage.py).

Method: case-insensitive grep of manifest/technique_manifest.json's
grep_patterns against every raw .log file under
attack_data/datasets/malware/<family>/**. Raw grep output (one file per
family x technique, listing every matching line with its source file and
line number) is saved to evidence/01_capture_grep/ BEFORE any counting, so
every number in FINDINGS.md can be traced back to the actual matched lines,
never just a count computed once and reused.

Idempotent: re-running overwrites the same evidence files with the same
content, given the same corpus on disk (grep's file order is stabilized by
sorting the file list first).
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "manifest" / "technique_manifest.json"
CORPUS_ROOT = Path("/home/kali/director/projects/_corpora/attack_data/datasets/malware")
EVIDENCE_DIR = ROOT / "evidence" / "01_capture_grep"

# Verified false-positive source, found while building this project: some
# captures (lockbit_ransomware, prestige_ransomware, chaos_ransomware) have a
# security agent ("Aurora-Agent") on the monitored host whose own vendored
# Sigma-rule archive gets written to disk as inert *.yml.tmp files with
# technique-suggestive names (e.g. "...defender_disabled.yml.tmp",
# "...netsh_firewall_disable.yml.tmp"). These are the security tool's OWN
# reference content, not attacker activity, and would silently inflate
# T1562/T1562.001 presence if not excluded. Any grep hit whose matched line
# ALSO contains one of these strings is dropped before counting.
NOISE_EXCLUDE_PATTERN = "Aurora-Agent|sigma-rules|\\.yml\\.tmp"


def family_log_files(corpus_dir: str) -> list[Path]:
    d = CORPUS_ROOT / corpus_dir
    if not d.is_dir():
        return []
    return sorted(d.rglob("*.log"))


GREP_TIMEOUT_S = 30  # a single alternative against ~115k lines takes well under a second normally


def _run_one_grep(pattern: str, files: list[Path]) -> list[str]:
    """Runs ONE pattern (no top-level '|') with grep -inP. Kept to a single
    alternative per call rather than joining every technique's patterns with
    '|' into one regex: combining several '.{0,300}'-prefixed alternatives
    into one alternation was tried first and caused catastrophic
    backtracking (observed hang, killed after 2+ minutes on the conti
    corpus). Running each alternative as its own grep call and unioning the
    matched lines in Python is slightly more subprocess overhead but cannot
    blow up this way, and a hard timeout still guards it.

    Uses -P (PCRE), not -E (POSIX ERE): -E's bounded-repetition engine (used
    here for patterns containing '.{0,300}') was independently confirmed to
    hang (still running after a 5s hard timeout) on these same files' long
    single-line XML events even for a SINGLE alternative with no '|' at all,
    while -P with the byte-identical pattern returned in well under a
    second. PCRE syntax is a superset of ERE for everything used in this
    project's patterns (literals, {0,300}, character classes, backreference-
    free groups), so no pattern text needed to change, only the flag."""
    cmd = ["grep", "-inP", pattern, *[str(f) for f in files]]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=GREP_TIMEOUT_S)
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(
            f"grep pattern {pattern!r} did not finish within {GREP_TIMEOUT_S}s "
            f"(likely regex backtracking blowup) against files {[str(f) for f in files]}"
        ) from e
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"grep failed (rc={proc.returncode}) for pattern {pattern!r}: {proc.stderr}")
    if proc.returncode == 1:
        return []  # grep's documented "no matches" exit code, not an error
    return proc.stdout.splitlines()


def grep_patterns_in_files(patterns: list[str], files: list[Path]) -> tuple[list[str], int]:
    """Runs each of a technique's grep_patterns as its OWN grep call (see
    _run_one_grep for why), unions and de-duplicates the matched
    'file:lineno:line' rows (stable-sorted so output is deterministic), then
    drops any line matching NOISE_EXCLUDE_PATTERN. Returns ([], 0) if
    nothing matches or files is empty; never fabricates a match. Second
    return value is the count of lines dropped by the noise filter, so that
    suppression is itself auditable."""
    if not files:
        return [], 0
    seen: dict[str, None] = {}
    for pattern in patterns:
        for line in _run_one_grep(pattern, files):
            seen.setdefault(line, None)  # de-dup while preserving first-seen order
    raw_lines = list(seen.keys())
    noise_re = re.compile(NOISE_EXCLUDE_PATTERN, re.IGNORECASE)
    kept = [l for l in raw_lines if not noise_re.search(l)]
    dropped = len(raw_lines) - len(kept)
    return kept, dropped


def main() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text())
    techniques = {k: v for k, v in manifest["techniques"].items() if not k.startswith("_")}
    families = {k: v for k, v in manifest["families"].items() if not k.startswith("_")}

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    summary = {}  # family -> technique -> {present, files_matched, lines_matched, matched_files}

    for fam_name, fam_info in families.items():
        files = family_log_files(fam_info["corpus_dir"])
        summary[fam_name] = {"corpus_dir": fam_info["corpus_dir"], "log_files_found": [str(f) for f in files], "techniques": {}}
        if not files:
            print(f"WARNING: no .log files found for family {fam_name} under {fam_info['corpus_dir']}")
        for tech_id, tech_info in techniques.items():
            patterns = tech_info["grep_patterns"]
            raw_lines, dropped = grep_patterns_in_files(patterns, files)

            out_path = EVIDENCE_DIR / f"{fam_name}__{tech_id}.txt"
            out_path.write_text(
                f"# family={fam_name} technique={tech_id} ({tech_info['name']})\n"
                f"# patterns (each run as its own 'grep -inE', matches unioned): {patterns}\n"
                f"# files searched: {[str(f) for f in files]}\n"
                f"# matched lines (after noise exclusion): {len(raw_lines)}\n"
                f"# lines dropped by NOISE_EXCLUDE_PATTERN ({NOISE_EXCLUDE_PATTERN}): {dropped}\n"
                f"#\n" + "\n".join(raw_lines) + ("\n" if raw_lines else "")
            )

            matched_files = sorted({line.split(":", 1)[0] for line in raw_lines})
            summary[fam_name]["techniques"][tech_id] = {
                "present": len(raw_lines) > 0,
                "lines_matched": len(raw_lines),
                "files_matched": len(matched_files),
                "files_searched": len(files),
                "evidence_file": str(out_path.relative_to(ROOT)),
            }
            print(f"{fam_name:22s} {tech_id:11s} present={summary[fam_name]['techniques'][tech_id]['present']!s:5s} "
                  f"lines={len(raw_lines):4d} files_matched={len(matched_files)}/{len(files)}")

    out_summary = ROOT / "evidence" / "01_capture_evidence_summary.json"
    out_summary.write_text(json.dumps(summary, indent=2))
    print(f"\nwrote {out_summary}")
    print(f"wrote {len(list(EVIDENCE_DIR.glob('*.txt')))} raw grep files to {EVIDENCE_DIR}")


if __name__ == "__main__":
    main()
