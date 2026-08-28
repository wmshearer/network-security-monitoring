#!/usr/bin/env python3
"""
Find every detection in security_content tagged with an ATT&CK Supply Chain
Compromise sub-technique (T1195, T1195.001, T1195.002, T1195.003), plus the
Sunburst detection (verified separately to carry T1203 instead, a data-quality
finding this project reports).

Read-only against the security_content corpus. Writes a JSON list of
{path, name, status, mitre_attack_id} to evidence/.

Idempotent: re-running overwrites the same output deterministically.
"""
import json
import re
import sys
from pathlib import Path

CORPUS = Path("/home/kali/director/projects/_corpora/security_content")
OUT = Path(__file__).resolve().parent.parent / "evidence" / "01_t1195_detections.json"

SUNBURST_PATH = "detections/endpoint/sunburst_correlation_dll_and_network_event.yml"


def parse_minimal_yaml_fields(text):
    """
    Pull a handful of top-level scalar/list fields out of a detection YAML
    without a YAML library dependency, since these files are hand-authored
    with a consistent, simple structure. This is intentionally narrow: it
    only extracts 'status:' and the 'mitre_attack_id:' block, both of which
    this project needs and neither of which appears inside the multi-line
    'search:' or 'description:' blocks under a different indentation level.
    """
    status = None
    m = re.search(r"^status:\s*(\S+)\s*$", text, re.MULTILINE)
    if m:
        status = m.group(1)

    ids = []
    m = re.search(r"^mitre_attack_id:\n((?:\s+-\s+\S+\n?)+)", text, re.MULTILINE)
    if m:
        ids = re.findall(r"-\s+(\S+)", m.group(1))

    name = None
    m = re.search(r"^name:\s*(.+)$", text, re.MULTILINE)
    if m:
        name = m.group(1).strip()

    return status, ids, name


def main():
    if not CORPUS.exists():
        print(f"SKIP: corpus not found at {CORPUS}", file=sys.stderr)
        sys.exit(0)

    detections_dir = CORPUS / "detections"
    results = []
    for path in sorted(detections_dir.rglob("*.yml")):
        text = path.read_text(errors="replace")
        if not re.search(r"^\s*-\s+T1195(\.\d+)?\s*$", text, re.MULTILINE):
            continue
        status, ids, name = parse_minimal_yaml_fields(text)
        rel = str(path.relative_to(CORPUS))
        results.append({
            "path": rel,
            "name": name,
            "status": status,
            "mitre_attack_id": ids,
        })

    # Sunburst is verified (by direct read, see rubric/calls.csv) to carry
    # T1203 only, not any T1195 sub-technique, so the regex above correctly
    # excludes it. Add it explicitly with a flag so the count is auditable.
    sunburst_full = CORPUS / SUNBURST_PATH
    if sunburst_full.exists():
        text = sunburst_full.read_text(errors="replace")
        status, ids, name = parse_minimal_yaml_fields(text)
        results.append({
            "path": SUNBURST_PATH,
            "name": name,
            "status": status,
            "mitre_attack_id": ids,
            "note": "included manually: canonical SUNBURST detection, tagged T1203 not T1195, verified by direct read",
        })

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(results, indent=2) + "\n")

    t1195_count = sum(1 for r in results if any(i.startswith("T1195") for i in r["mitre_attack_id"]))
    print(f"Wrote {len(results)} detections to {OUT}")
    print(f"  {t1195_count} tagged with a T1195 sub-technique")
    print(f"  {len(results) - t1195_count} added manually (Sunburst, mistagged T1203)")
    statuses = {}
    for r in results:
        statuses[r["status"]] = statuses.get(r["status"], 0) + 1
    print(f"  status breakdown: {statuses}")


if __name__ == "__main__":
    main()
