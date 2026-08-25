#!/usr/bin/env python3
"""Convert benign-baseline .evtx files into flat JSON-lines for Splunk ingest.

WHY this approach (documented per the task's "document what you chose and why"
requirement):

Splunk Enterprise on Linux has no native EVTX (binary Windows Event Log) parser
-- EVTX is a proprietary binary chunked-record format, and Splunk's own docs
only describe reading it via a Windows universal forwarder's WinEventLog input,
which requires a live Windows host or the forwarder's native Win32 API calls.
Neither is available here (this data is offline captured .evtx files on Linux,
no Windows host in the loop).

What was tried and rejected:
  - `file:// ` monitor input pointed straight at a .evtx file: Splunk indexes
    it as opaque binary/garbled text (confirmed: the props.conf pipeline can
    only line-break and regex against bytes it can read as text; EVTX's binary
    chunk/record framing does not line up with any text delimiter). Rejected
    -- this is exactly the "sourcetype detection on a blob" failure mode the
    task called out to avoid.
  - Shipping to a Windows forwarder: no Windows host is available in this
    environment, and the task says analyze EXISTING captured data only, not
    stand up new infrastructure.

What was chosen: convert to JSON first, on the Linux host, using the `evtx`
PyPI package (github.com/omerbenamram/evtx, aka pyevtx-rs) -- Rust-backed,
dual MIT/Apache-2.0, versions 0.12.x confirmed installed here. This is the
same library already used and documented in
../ai-triage-engine/src/ingest/parse_evtx.py (read for reference only, not
imported/modified -- that project's dependency choice and field-mapping
rationale is reused here because it has already been verified against real
OTRF + evtx-baseline data by that project's own tests).

Output shape: one JSON object per line, per source .evtx file, written to
data/converted/benign/<channel-file-stem>.json. Each record carries:
  - every flattened Windows Event Log field (Channel, EventID, Hostname,
    EventTime, plus whatever EventData the event type carries -- CommandLine,
    TargetObject, etc.)
  - label = "benign" (indexed field the whole scoring pipeline depends on)
  - source_capture = "evtx_baseline_win2022"
  - technique_id = "" (benign events have no ATT&CK ground truth by
    definition; left empty rather than null so Splunk's default CSV-ish
    field handling doesn't need to special-case JSON null)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from evtx import PyEvtxParser


def _unwrap_attributed(node: Any) -> Any:
    """Collapse evtx's `{"#attributes": ..., "#text": ...}` wrapper to the bare value."""
    if isinstance(node, dict) and "#text" in node:
        return node["#text"]
    return node


def flatten_event(raw: dict[str, Any]) -> dict[str, Any]:
    """Reshape one evtx-library nested JSON record into a flat dict.

    Field-mapping approach and the specific System.* -> flat-name choices below
    are the same ones verified in ai-triage-engine/src/ingest/parse_evtx.py
    (read, not imported) against real OTRF + evtx-baseline data -- see that
    file's module docstring for the direct-inspection evidence that these
    field names already match real Windows Event Log / OTRF conventions.
    """
    event = raw.get("Event", {})
    system = event.get("System", {})
    event_data = event.get("EventData") or {}

    flat: dict[str, Any] = {}

    if isinstance(event_data, dict):
        for key, value in event_data.items():
            flat[key] = value

    provider = system.get("Provider") or {}
    provider_attrs = provider.get("#attributes") or {}
    execution = system.get("Execution") or {}
    execution_attrs = execution.get("#attributes") or {}
    time_created = system.get("TimeCreated") or {}
    time_created_attrs = time_created.get("#attributes") or {}
    system_time = time_created_attrs.get("SystemTime")

    flat["Channel"] = system.get("Channel")
    flat["EventID"] = _unwrap_attributed(system.get("EventID"))
    flat["Hostname"] = system.get("Computer")
    if system_time:
        flat["EventTime"] = system_time
        flat["@timestamp"] = system_time
    flat["RecordNumber"] = system.get("EventRecordID")
    for name in ("Keywords", "Task", "Opcode", "Version", "Level"):
        if name in system:
            flat[name] = system[name]
    if provider_attrs.get("Guid"):
        flat["ProviderGuid"] = provider_attrs["Guid"]
    if execution_attrs.get("ProcessID") is not None:
        flat["ExecutionProcessID"] = execution_attrs["ProcessID"]
    if execution_attrs.get("ThreadID") is not None:
        flat["ThreadID"] = execution_attrs["ThreadID"]

    return flat


def convert_file(evtx_path: Path, label: str, source_capture: str) -> list[dict[str, Any]]:
    parser = PyEvtxParser(str(evtx_path))
    records: list[dict[str, Any]] = []
    errors = 0
    for record in parser.records_json():
        try:
            raw = json.loads(record["data"])
        except (json.JSONDecodeError, KeyError, TypeError):
            errors += 1
            continue
        flat = flatten_event(raw)
        flat["label"] = label
        flat["source_capture"] = source_capture
        flat["technique_id"] = ""
        records.append(flat)
    if errors:
        print(f"  WARNING: {evtx_path.name}: {errors} malformed records skipped", file=sys.stderr)
    return records


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--src-dir", required=True, type=Path, help="directory of .evtx files")
    ap.add_argument("--out-dir", required=True, type=Path, help="output directory for JSON-lines files")
    ap.add_argument("--source-capture", default="evtx_baseline_win2022")
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    evtx_files = sorted(args.src_dir.glob("*.evtx"))
    if not evtx_files:
        print(f"no .evtx files found under {args.src_dir}", file=sys.stderr)
        return 1

    total_events = 0
    summary: dict[str, int] = {}
    for evtx_path in evtx_files:
        records = convert_file(evtx_path, label="benign", source_capture=args.source_capture)
        if not records:
            continue
        out_name = evtx_path.stem.replace("%4", "_") + ".json"
        out_path = args.out_dir / out_name
        with out_path.open("w") as fh:
            for rec in records:
                fh.write(json.dumps(rec, default=str) + "\n")
        summary[evtx_path.name] = len(records)
        total_events += len(records)
        print(f"  {evtx_path.name}: {len(records)} events -> {out_path}")

    print(f"\nTotal files converted: {len(summary)} / {len(evtx_files)} (rest had 0 events)")
    print(f"Total events: {total_events}")

    # Manifest is written to a sibling _manifests/ dir, not alongside the
    # event JSON files, so a bulk `for f in data/converted/benign/*.json`
    # ingest loop (see README.md) can never accidentally index it as an
    # event file -- this bit once during this project's own ingest (see
    # README.md ingest section) and is worth guarding against structurally.
    manifest_dir = args.out_dir.parent / "_manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / f"{args.out_dir.name}_manifest.json"
    manifest_path.write_text(json.dumps({"source_capture": args.source_capture, "per_file_counts": summary, "total_events": total_events}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
