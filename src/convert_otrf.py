#!/usr/bin/env python3
"""Convert OTRF Security-Datasets attack captures into labeled JSON-lines for Splunk.

Each atomic capture zip (data/raw/otrf/captures/*.zip) contains one JSON-lines
file already -- OTRF ships events pre-flattened, one JSON object per line
(confirmed by direct inspection: unzip -l shows a single .json member per
capture; each line independently json.loads's as one Windows Event Log
record). No format conversion is needed here, unlike the .evtx baseline --
only labeling.

Ground truth: each capture has a sidecar metadata YAML
(data/raw/otrf/metadata/<capture-id>.yaml) with an `attack_mappings` list
naming an ATT&CK technique + tactic. Because these are ATOMIC captures (one
technique executed end-to-end, not a multi-stage campaign), it is honest to
apply that one technique uniformly to every event in the capture -- this
mirrors the same reasoning documented in
../ai-triage-engine/src/ingest/normalize.py (read for reference, not
imported/modified).

APT29 compound captures (data/raw/otrf/compound_captures/*.zip) are
DELIBERATELY OUT OF SCOPE for per-technique labeling: OTRF publishes no
per-event or single-primary technique mapping for these (they are 15+
technique, multi-day campaigns) and there is no metadata YAML for them in
this dataset. Inventing a technique mapping for them would fabricate ground
truth. See README.md for the decision to exclude them from Phase 1/2 scoring.
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path
from typing import Any

import yaml


def load_metadata(yaml_path: Path) -> dict[str, Any]:
    data = yaml.safe_load(yaml_path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"expected YAML mapping: {yaml_path}")
    return data


def technique_from_metadata(meta: dict[str, Any]) -> tuple[str, str, list[str]]:
    mappings = meta.get("attack_mappings") or []
    if not mappings:
        raise ValueError(f"no attack_mappings in metadata for {meta.get('id')}")
    primary = mappings[0]
    technique = primary.get("technique")
    sub = primary.get("sub-technique") or ""
    sub = str(sub).strip()
    technique_id = f"{technique}.{sub}" if sub else technique
    tactics = primary.get("tactics") or []
    return technique_id, technique, tactics


def convert_capture(zip_path: Path, yaml_path: Path, capture_id: str) -> list[dict[str, Any]]:
    meta = load_metadata(yaml_path)
    technique_id, technique_base, tactics = technique_from_metadata(meta)

    records: list[dict[str, Any]] = []
    errors = 0
    with zipfile.ZipFile(zip_path) as zf:
        json_members = [n for n in zf.namelist() if n.endswith(".json")]
        for member in json_members:
            with zf.open(member) as fh:
                for line_no, raw_line in enumerate(fh, start=1):
                    line = raw_line.decode("utf-8").strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        errors += 1
                        continue
                    event["label"] = "attack"
                    event["source_capture"] = capture_id
                    event["technique_id"] = technique_id
                    event["technique_base"] = technique_base
                    event["attack_tactics"] = ",".join(tactics)
                    event["capture_title"] = meta.get("title", "")
                    records.append(event)
    if errors:
        print(f"  WARNING: {zip_path.name}: {errors} malformed JSON lines skipped", file=sys.stderr)
    return records


# Maps capture zip filename stem -> metadata YAML filename (by capture id).
# Built by matching each capture's `files[].link` basename in the metadata
# YAML against the zip filename actually on disk (verified by hand for all 5
# captures -- see README.md ingest section for the mapping table).
CAPTURE_TO_METADATA = {
    "empire_persistence_registry_modification_run_keys_standard_user": "SDWIN-190319023812.yaml",
    "empire_schtasks_creation_standard_user": "SDWIN-190319024742.yaml",
    "empire_shell_net_localgroup_administrators": "SDWIN-190319020147.yaml",
    "empire_shell_net_local_users": "SDWIN-190319020729.yaml",
    "msf_record_mic": "SDWIN-200609225055.yaml",
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--captures-dir", required=True, type=Path)
    ap.add_argument("--metadata-dir", required=True, type=Path)
    ap.add_argument("--out-dir", required=True, type=Path)
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    total_events = 0
    summary: dict[str, Any] = {}
    for capture_id, meta_filename in CAPTURE_TO_METADATA.items():
        zip_path = args.captures_dir / f"{capture_id}.zip"
        yaml_path = args.metadata_dir / meta_filename
        if not zip_path.exists():
            print(f"MISSING zip: {zip_path}", file=sys.stderr)
            return 1
        if not yaml_path.exists():
            print(f"MISSING metadata: {yaml_path}", file=sys.stderr)
            return 1

        records = convert_capture(zip_path, yaml_path, capture_id)
        out_path = args.out_dir / f"{capture_id}.json"
        with out_path.open("w") as fh:
            for rec in records:
                fh.write(json.dumps(rec, default=str) + "\n")

        technique_id = records[0]["technique_id"] if records else "?"
        summary[capture_id] = {"events": len(records), "technique_id": technique_id}
        total_events += len(records)
        print(f"  {capture_id}: {len(records)} events, technique={technique_id} -> {out_path}")

    print(f"\nTotal attack events: {total_events}")
    # See convert_evtx.py's matching comment: manifest lives in a sibling
    # _manifests/ dir so it can never be swept up by a bulk event-file ingest
    # loop over data/converted/attack/*.json.
    manifest_dir = args.out_dir.parent / "_manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / f"{args.out_dir.name}_manifest.json"
    manifest_path.write_text(json.dumps({"per_capture": summary, "total_events": total_events}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
