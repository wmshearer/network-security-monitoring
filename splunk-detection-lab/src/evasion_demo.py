#!/usr/bin/env python3
"""Demonstrate a brittle detection (D2) failing on a semantically identical
but reworded event, while a durable detection (D6) keeps firing on the same
edited event.

Method: OFFLINE, not re-ingested into Splunk. The real captured EventID 1
event that D2 and D6 both fire on
(data/converted/attack/empire_schtasks_creation_standard_user.json, the
schtasks.exe process-creation event with a PowerShell parent) is loaded and
copied in memory. Each tested transformation is applied to the CommandLine
field ONLY, on the copy. D2's and D6's real SPL filter logic (the exact text
in evidence/detection_dev/d2_schtasks_encoded_powershell.spl and
d6_powershell_spawns_recon_tool.spl) is then re-implemented as a plain
Python predicate over the event's fields and evaluated against the edited
copy.

Why offline instead of re-ingesting into a robustness_lab index: the two
SPL filters here are simple field/substring predicates
(Image/CommandLine/ParentImage wildcard and substring matches), not
statistics or time-window logic, so a faithful Python re-implementation is
exact, not an approximation. Re-ingesting a handful of edited JSON lines
into a separate index and re-running the real SPL against Splunk would be
strictly more evidence of "Splunk itself, wired up, gives this result," but
it also risks the exact class of silent ingest failure this project's own
README documents at length (timestamp parsing, MAX_DAYS_AGO, field-name
collisions) for a demonstration whose actual claim is about the MATCH
LOGIC, not about Splunk's ingest pipeline. The match logic is copied
verbatim from the deployed .spl files below (see PREDICATE constants), so
this is not a fresh reimplementation invented for this script -- it is the
same filter text used by score_detections.py to build the live SPL queries.

The original captured file is NEVER modified. Every event object used here
is loaded fresh and copied before editing.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

REAL_EVENT_FILE = "data/converted/attack/empire_schtasks_creation_standard_user.json"


def load_real_event() -> dict:
    """Load the real, unmodified EventID 1 schtasks.exe event that both D2
    and D6 fire on. Read-only: this file is never written to by this
    script."""
    path = Path(REAL_EVENT_FILE)
    with path.open() as fh:
        for line in fh:
            event = json.loads(line)
            if (
                event.get("EventID") == 1
                and event.get("Image", "").endswith("schtasks.exe")
                and "powershell" in event.get("CommandLine", "").lower()
            ):
                return event
    raise RuntimeError(f"expected schtasks.exe/EventID=1 event not found in {path}")


# --- D2 and D6 match logic, copied verbatim from the deployed SPL fragments
# in evidence/detection_dev/*.spl. These are the same predicates
# score_detections.py sends to Splunk as SPL text; here they are
# reimplemented as Python so they can be evaluated against an in-memory,
# never-ingested edited copy of the event.
#
# D2 SPL: index=detection_lab EventID=1 Image="*schtasks.exe"
#         CommandLine="*powershell*" CommandLine="*hidden*"
# D6 SPL: index=detection_lab EventID=1 ParentImage="*powershell.exe"
#         (Image="*\net.exe" OR Image="*\net1.exe" OR Image="*\schtasks.exe")


def d2_fires(event: dict) -> bool:
    if event.get("EventID") != 1:
        return False
    if not event.get("Image", "").endswith("schtasks.exe"):
        return False
    cmdline = event.get("CommandLine", "")
    return "powershell" in cmdline.lower() and "hidden" in cmdline.lower()


def d6_fires(event: dict) -> bool:
    if event.get("EventID") != 1:
        return False
    if not event.get("ParentImage", "").endswith("powershell.exe"):
        return False
    image = event.get("Image", "")
    return image.endswith("net.exe") or image.endswith("net1.exe") or image.endswith("schtasks.exe")


# --- Transformations, applied to a COPY of the real event's CommandLine
# field only. Each one is a tested fact from FINDINGS.md's 2026-08-24
# correction, not a new invented edit.

def transform_original(event: dict) -> dict:
    return copy.deepcopy(event)


def transform_windowstyle_hidden(event: dict) -> dict:
    """FINDINGS.md-documented NEGATIVE case: does NOT evade D2. Kept in this
    table specifically to prove the earlier wrong claim stays wrong when
    re-tested, not just to show a working evasion."""
    e = copy.deepcopy(event)
    e["CommandLine"] = e["CommandLine"].replace("-W hidden", "-windowstyle hidden")
    return e


def transform_renamed_interpreter_same_dir(event: dict) -> dict:
    """FINDINGS.md-documented NEGATIVE case: does NOT evade D2, because the
    literal substring "powershell" still appears in the directory path
    C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\ even after the
    executable name changes."""
    e = copy.deepcopy(event)
    e["CommandLine"] = e["CommandLine"].replace(
        "WindowsPowerShell\\v1.0\\powershell.exe", "WindowsPowerShell\\v1.0\\ps.exe"
    )
    return e


def transform_windowstyle_numeric(event: dict) -> dict:
    """FINDINGS.md-documented POSITIVE case: evades D2. -W hidden and
    -WindowStyle 1 are the same PowerShell option in its numeric form (same
    behavior), and the word "hidden" is absent from the numeric form."""
    e = copy.deepcopy(event)
    e["CommandLine"] = e["CommandLine"].replace("-W hidden", "-WindowStyle 1")
    return e


def transform_interpreter_neutral_path(event: dict) -> dict:
    """FINDINGS.md-documented POSITIVE case: evades D2. Copying the
    interpreter to a neutral path removes BOTH occurrences of the literal
    substring "powershell" from CommandLine (the executable name and the
    WindowsPowerShell directory segment)."""
    e = copy.deepcopy(event)
    e["CommandLine"] = e["CommandLine"].replace(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Users\\Public\\svc.exe",
    )
    return e


TRANSFORMS = [
    ("original (unedited)", transform_original),
    ("-W hidden -> -windowstyle hidden (tested: does NOT evade D2)", transform_windowstyle_hidden),
    ("interpreter renamed, same directory (tested: does NOT evade D2, path still contains 'powershell')", transform_renamed_interpreter_same_dir),
    ("-W hidden -> -WindowStyle 1 (tested: evades D2)", transform_windowstyle_numeric),
    ("interpreter copied to C:\\Users\\Public\\svc.exe (tested: evades D2)", transform_interpreter_neutral_path),
]


def run_demo() -> list[dict]:
    real_event = load_real_event()
    results = []
    for label, transform_fn in TRANSFORMS:
        edited = transform_fn(real_event)
        results.append(
            {
                "transformation": label,
                "commandline": edited.get("CommandLine"),
                "d2_fires": d2_fires(edited),
                "d6_fires": d6_fires(edited),
            }
        )
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="evidence/robustness/evasion_results.json")
    args = ap.parse_args()

    results = run_demo()

    print(f"{'transformation':<75} {'D2 fires':<10} {'D6 fires':<10}")
    print("-" * 97)
    for r in results:
        print(f"{r['transformation']:<75} {str(r['d2_fires']):<10} {str(r['d6_fires']):<10}")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\nwrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
