#!/usr/bin/env python3
"""Stage 2: index every Splunk security_content endpoint detection by the
MITRE technique IDs and analytic_story names it declares in its own YAML
metadata.

This answers "does Splunk SHIP a detection that claims to cover this
technique for this family's story", which is the metadata half of the
GREEN/RED-LOGIC/RED-TELEMETRY decision. It does NOT run any SPL, and does
NOT decide whether the detection would actually fire; that requires the
detection's own literal match conditions to be checked against the raw
capture, which is stage 3 (scripts/03_score_detection_logic.py).

Reads every detections/endpoint/*.yml (the corpus this project scopes to;
application/cloud/network/web detections are out of scope, see README) and
writes one row per (detection, technique_id) pair to
evidence/02_detection_index.json, plus the exact source file for each row so
every claim traces back to a real file on disk.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DETECTIONS_DIR = Path("/home/kali/director/projects/_corpora/security_content/detections/endpoint")
OUT_PATH = ROOT / "evidence" / "02_detection_index.json"


def main() -> None:
    yml_files = sorted(DETECTIONS_DIR.glob("*.yml"))
    if not yml_files:
        raise RuntimeError(f"no detection YAML files found under {DETECTIONS_DIR}; corpus path may have moved")

    rows = []
    parse_errors = []
    for f in yml_files:
        try:
            data = yaml.safe_load(f.read_text())
        except yaml.YAMLError as e:
            parse_errors.append({"file": str(f), "error": str(e)})
            continue
        if not isinstance(data, dict):
            parse_errors.append({"file": str(f), "error": "top-level YAML is not a mapping"})
            continue

        mitre_ids = data.get("mitre_attack_id") or []
        stories = data.get("analytic_story") or []
        if not isinstance(mitre_ids, list):
            mitre_ids = [mitre_ids]
        if not isinstance(stories, list):
            stories = [stories]

        rows.append({
            "detection_name": data.get("name"),
            "detection_id": data.get("id"),
            "status": data.get("status"),
            "mitre_attack_id": mitre_ids,
            "analytic_story": stories,
            "search": data.get("search"),
            "source_file": str(f.relative_to(DETECTIONS_DIR.parents[2])),
        })

    OUT_PATH.write_text(json.dumps({"detections": rows, "parse_errors": parse_errors}, indent=2))

    n_with_mitre = sum(1 for r in rows if r["mitre_attack_id"])
    n_production = sum(1 for r in rows if r["status"] == "production")
    print(f"parsed {len(yml_files)} YAML files, {len(parse_errors)} parse errors")
    print(f"{len(rows)} detections indexed, {n_with_mitre} carry at least one mitre_attack_id, {n_production} status=production")
    if parse_errors:
        for e in parse_errors:
            print(f"  PARSE ERROR: {e['file']}: {e['error']}")
    print(f"wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
