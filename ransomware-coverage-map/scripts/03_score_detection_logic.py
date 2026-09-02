#!/usr/bin/env python3
r"""Stage 3: for every family x technique cell, decide whether a Splunk
security_content detection's OWN literal match conditions would plausibly
fire against that family's raw capture, using the detection's SPL search
text (not just its metadata tags).

Why this stage exists and is not just "detection tagged to this
technique+story => GREEN": a detection can be tagged to a technique and a
family's story yet target a process/command-line string that never
occurs at all in that family's capture (a real detection gap, or a capture that
never exercised that exact variant). Checking the detection's actual SPL
literals against the same raw .log files stage 1 already grepped is how
this project tells GREEN from RED-LOGIC instead of assuming every tagged
detection would fire.

Method for each candidate detection (tagged to the row's technique_id AND to
the column's analytic_story, from evidence/02_detection_index.json):
  1. Extract literal command/process terms from the detection's `search`
     field (the quoted strings after process_name=, Processes.process IN
     (...), etc). This stays narrow on purpose: only literal strings actually
     written into the SPL are extracted, nothing is inferred.
  2. grep those literals (case-insensitive) against the family's raw .log
     files (same files stage 1 used).
  3. If no candidate detection exists at all for this technique+story pair:
     UNDETERMINED-NO-DETECTION (there is nothing to test; this is not the
     same as a miss and is reported separately, never silently folded into
     RED).
  4. If a candidate detection's literals are extractable and found in the
     capture: the detection's logic-relevant strings are present, scored
     LOGIC_MATCH.
  5. If a candidate detection exists and its literals are extractable but
     NONE occur in the capture: LOGIC_NO_MATCH (candidate exists, its exact
     variant not evidenced here).
  6. If a candidate detection's literals could not be extracted from its SPL
     (e.g. the search is structured in a way this narrow extractor does not
     parse): UNDETERMINED-UNPARSEABLE-SEARCH. Never defaults to a verdict.

This stage answers "would AT LEAST ONE candidate detection's literal terms
match this capture", which script 04 combines with stage 1's presence
verdict to assign the final GREEN / RED-LOGIC / RED-TELEMETRY / GREY cell
state.

RESOLVED INTERPRETIVE LIMITATION (was open, now closed by a live test): two
cells (lockbit_ransomware|T1486, chaos_ransomware|T1486) trace to
ransomware_notes_bulk_creation.yml's SPL
`file_name IN ("*\.txt","*\.html","*\.hta")`. The backslash before the dot
is NOT one of SPL's two defined string escapes (\" and \\). A strict reading
of SPL's own string-literal grammar would preserve it literally, meaning the
detection's own wildcard would only match a filename containing a literal
backslash immediately before "txt"/"html"/"hta", which no real filename has.
This project could not previously determine, without a live Splunk instance,
whether Splunk's search-time wildcard matcher actually enforces that literal
backslash or silently treats the unrecognized escape as a bare ".". It has
since been tested directly against a live Splunk Enterprise 10.4.2 instance
(see evidence/07_spl_backslash_resolved.txt): the backslash is treated
permissively, `"*\.txt"` matches a plain ".txt" filename exactly like
`"*.txt"` does, confirmed against a negative control. `unescape_spl_string`
below now reflects that live-tested behavior (drop the backslash for ANY
escape, not only the two SPL formally defines), so both cells score GREEN.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "manifest" / "technique_manifest.json"
DETECTION_INDEX_PATH = ROOT / "evidence" / "02_detection_index.json"
CAPTURE_SUMMARY_PATH = ROOT / "evidence" / "01_capture_evidence_summary.json"
CORPUS_ROOT = Path("/home/kali/director/projects/_corpora/attack_data/datasets/malware")
OUT_PATH = ROOT / "evidence" / "03_detection_logic_scores.json"

# Same reasoned exclusion as stage 1 (see scripts/01_build_capture_evidence.py).
NOISE_EXCLUDE_PATTERN = "Aurora-Agent|sigma-rules|\\.yml\\.tmp"

# Literal-string extraction patterns applied to a detection's SPL `search`
# field. Stays narrow on purpose: only pulls strings that are explicit
# equality/IN/wildcard comparisons against a small set of CIM Endpoint
# fields ransomware detections actually use, never free text from
# descriptions or comments (the search field itself contains no comments).
#
# security_content's SPL writes these comparisons three ways, all observed
# directly in this project's target detections (deleting_shadow_copies.yml,
# bcdedit_failure_recovery_modification.yml, wbadmin_delete_system_backups.yml):
#   Processes.process_name=vssadmin.exe          (bareword, no quotes)
#   Processes.process="*delete*"                 (quoted, wildcarded)
#   Processes.process_name IN ("a.exe", "b.exe")  (quoted IN-list)
# A first version of this extractor only handled the quoted form and silently
# produced zero literals for the other two, which would have mis-scored every
# such detection as UNDETERMINED-UNPARSEABLE-SEARCH instead of testing its
# real logic. All three forms are handled below.
FIELD_PREFIXES = r"(?:Processes|Registry|Filesystem)\."
FIELD_NAMES = r"(?:process_name|process|parent_process_name|parent_process|original_file_name|registry_path|registry_value_name|registry_key_name|registry_value_data|service_name|file_path|file_name)"
# Bare fields (no Processes./Registry./Filesystem. datamodel prefix) used by
# detections built on raw `sysmon`/`wineventlog` macros instead of tstats
# over a data model, e.g. ransomware_notes_bulk_creation.yml's
# `file_name IN (...)` and modification_of_wallpaper.yml's raw Sysmon
# `TargetObject IN (...)` (the un-normalized registry-key field name Sysmon
# itself uses, distinct from the CIM-normalized Registry.registry_path).
BARE_FIELD_NAMES = r"(?:file_name|TargetFilename|TargetObject|ScriptBlockText)"

# Finds the whole comparison expression first (up to the closing paren for
# IN-lists, or the single quoted/bareword token for a plain '='), then a
# second pass pulls every quoted string out of THAT matched span. This
# handles multi-item IN-lists (e.g. file_name IN ("*.txt","*.html","*.hta")),
# which a single capture group cannot, since re.findall only returns the
# last group repetition for a quantified group, not all of them.
#
# The field name itself may ALSO be quoted (e.g. "Processes.process_name"=,
# "Filesystem.file_path"=, seen in ryuk_test_files_detected.yml and
# windows_security_account_manager_stopped.yml), so an optional pair of
# double-quotes is allowed around the whole {prefix}{field} token.
#
# The quoted VALUE alternative below (after '"?...= or IN\s*') must treat a
# backslash-escaped quote (\") as part of the string, not a terminator: a
# real detection's SPL literally contains "*stop \"samss\"*" (a Splunk
# command-line value that itself contains double quotes around "samss",
# escaped). An earlier version used "[^"]*" here, which stopped at the FIRST
# quote and silently truncated that detection's literal to 'stop \', which
# then correctly failed to match ryuk's raw capture even though the true
# literal ('stop "samss"') DOES occur there verified by direct grep. That
# would have reported a real detection as a gap (RED-LOGIC) when it is
# actually a GREEN, which is exactly the class of silent-wrong-answer this
# project exists to avoid.
QUOTED_VALUE = r'"(?:\\.|[^"\\])*"'
FIELD_EXPR_RE = re.compile(
    rf'"?(?:{FIELD_PREFIXES}{FIELD_NAMES}|{BARE_FIELD_NAMES})"?\s*(?:=|IN)\s*(\([^)]*\)|{QUOTED_VALUE}|[A-Za-z0-9_.:\\*-]+)',
    re.IGNORECASE,
)
QUOTED_ITEM_RE = re.compile(r'"((?:\\.|[^"\\])+)"')


def unescape_spl_string(s: str) -> str:
    """Undoes SPL's own backslash-escaping of a quoted string literal so the
    result is the literal bytes that string would match at search time,
    matching what would actually appear in raw captured text.

    Splunk SPL string literals formally define two escapes, \\" (literal
    quote) and \\\\ (literal backslash). But this project's own live test
    against a running Splunk instance (Splunk Enterprise 10.4.2, see
    evidence/07_spl_backslash_resolved.txt) established that Splunk's
    search-time wildcard matcher does NOT enforce a literal backslash for an
    unrecognized escape such as \\. : `file_name IN ("*\\.txt")` matched a
    plainly-named "cHpfiXA9s.README.txt" exactly like the unescaped
    `("*.txt")` form did, with a negative control (a non-.txt filename)
    confirming the matcher was doing real filtering, not matching every
    event indiscriminately. So every
    backslash-prefixed character, recognized escape or not, is passed
    through with the backslash dropped, which is what Splunk itself does at
    search time, not the stricter SPL string-literal grammar.

    Three real detections in this project's scope motivated getting this
    exactly right rather than guessing:
      - windows_security_account_manager_stopped.yml's SPL contains the
        4-character sequence \\" (escaped quote) inside *stop \\"samss\\"*;
        naively stopping at the first raw '"' truncated the literal to
        'stop \\', which does not occur in ryuk's capture, when the real
        unescaped literal 'stop "samss"' DOES (confirmed by direct grep).
      - ryuk_test_files_detected.yml's SPL contains \\\\ (escaped backslash)
        in C:\\\\*Ryuk*; passing the literal backslashes through unescaped
        left two literal backslash characters in the extracted string, which
        does not occur in the raw Sysmon paths (which use ONE backslash per
        path separator, e.g. '...\\RyukReadMe...', confirmed by direct grep).
      - ransomware_notes_bulk_creation.yml's SPL contains
        `file_name IN ("*\\.txt","*\\.html","*\\.hta")`; a strict reading
        (backslash preserved because \\. is not a defined SPL escape) would
        require a literal backslash before "txt", which no real filename
        has. Live-tested against Splunk and found permissive (see above):
        the backslash is dropped and the dot matches a plain ".txt".
    Every case above would have silently reported a real GREEN as RED-LOGIC
    if left unfixed.
    """
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            out.append(s[i + 1])
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def extract_literals(search_text: str) -> list[str]:
    """Best-effort, narrow extraction of literal comparison strings from an
    SPL search, covering quoted, wildcarded, multi-item IN-list, and
    bareword field comparisons (see the forms documented above). Wildcard
    markers are stripped since they are not literal characters; the OR/AND
    keywords Splunk allows in parens are never matched by these patterns
    because they are not preceded by a recognized field name. Returns []
    (not a fabricated guess) if nothing is extracted."""
    if not search_text:
        return []
    raw: list[str] = []
    for expr in FIELD_EXPR_RE.findall(search_text):
        quoted_items = QUOTED_ITEM_RE.findall(expr)
        if quoted_items:
            raw.extend(quoted_items)
        elif expr.strip("()").strip():
            raw.append(expr.strip("()").strip())
    cleaned = []
    for lit in raw:
        stripped = unescape_spl_string(lit).strip("*").strip()
        if len(stripped) >= 3 and stripped.upper() not in ("AND", "OR", "NOT"):
            cleaned.append(stripped)
    return sorted(set(cleaned))


def family_log_files(corpus_dir: str) -> list[Path]:
    d = CORPUS_ROOT / corpus_dir
    if not d.is_dir():
        return []
    return sorted(d.rglob("*.log"))


def grep_literal(literal: str, files: list[Path]) -> list[str]:
    """Searches for a detection's extracted literal against the family's raw
    .log files. An INTERIOR '*' in the literal (leading/trailing '*' are
    already stripped by extract_literals) is a genuine SPL wildcard meaning
    "any characters", not a literal asterisk, e.g. the extracted literal
    'C:\\*Ryuk' from ryuk_test_files_detected.yml means "a path starting
    with C: and containing Ryuk somewhere later", matching real paths like
    'C:\\ProgramData\\...\\RyukReadMe.html'. Using grep -F (fixed string)
    on this, as an earlier version of this script did, searches for a
    literal asterisk character, which never occurs in a real file path and
    silently turned a real match into a false LOGIC_NO_MATCH. Every other
    character in the literal is escaped so it is matched literally; only
    '*' is translated to a real regex wildcard, via grep -P."""
    if not files:
        return []
    if "*" in literal:
        pattern = ".*".join(re.escape(part) for part in literal.split("*"))
        cmd = ["grep", "-inP", pattern, *[str(f) for f in files]]
    else:
        cmd = ["grep", "-inF", literal, *[str(f) for f in files]]  # -F: fixed string, no regex risk at all
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"grep failed (rc={proc.returncode}) for literal {literal!r} (cmd={cmd[:3]}): {proc.stderr}")
    if proc.returncode == 1:
        return []
    noise_re = re.compile(NOISE_EXCLUDE_PATTERN, re.IGNORECASE)
    return [l for l in proc.stdout.splitlines() if not noise_re.search(l)]


def main() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text())
    techniques = {k: v for k, v in manifest["techniques"].items() if not k.startswith("_")}
    families = {k: v for k, v in manifest["families"].items() if not k.startswith("_")}
    detections = json.loads(DETECTION_INDEX_PATH.read_text())["detections"]

    results = {}  # family -> technique -> {...}

    for fam_name, fam_info in families.items():
        story = fam_info["security_content_story"]
        files = family_log_files(fam_info["corpus_dir"])
        results[fam_name] = {}

        for tech_id in techniques:
            candidates = []
            if story is not None:
                candidates = [
                    d for d in detections
                    if tech_id in d["mitre_attack_id"] and story in d["analytic_story"]
                ]

            if not candidates:
                results[fam_name][tech_id] = {
                    "verdict": "UNDETERMINED-NO-DETECTION",
                    "story_used": story,
                    "candidate_detections": [],
                }
                print(f"{fam_name:22s} {tech_id:11s} NO_DETECTION (story={story})")
                continue

            cell_candidates = []
            any_logic_match = False
            for d in candidates:
                literals = extract_literals(d.get("search") or "")
                if not literals:
                    cell_candidates.append({
                        "detection_name": d["detection_name"],
                        "source_file": d["source_file"],
                        "status": d["status"],
                        "verdict": "UNDETERMINED-UNPARSEABLE-SEARCH",
                        "literals": [],
                        "matched_lines": 0,
                    })
                    continue
                matched_lines = []
                for lit in literals:
                    matched_lines.extend(grep_literal(lit, files))
                verdict = "LOGIC_MATCH" if matched_lines else "LOGIC_NO_MATCH"
                if verdict == "LOGIC_MATCH":
                    any_logic_match = True
                cell_candidates.append({
                    "detection_name": d["detection_name"],
                    "source_file": d["source_file"],
                    "status": d["status"],
                    "verdict": verdict,
                    "literals": literals,
                    "matched_lines": len(matched_lines),
                })

            overall = "LOGIC_MATCH" if any_logic_match else (
                "LOGIC_NO_MATCH" if any(c["verdict"] == "LOGIC_NO_MATCH" for c in cell_candidates)
                else "UNDETERMINED-UNPARSEABLE-SEARCH"
            )
            results[fam_name][tech_id] = {
                "verdict": overall,
                "story_used": story,
                "candidate_detections": cell_candidates,
            }
            print(f"{fam_name:22s} {tech_id:11s} {overall:28s} candidates={len(candidates)}")

    OUT_PATH.write_text(json.dumps(results, indent=2))
    print(f"\nwrote {OUT_PATH}")


if __name__ == "__main__":
    main()
