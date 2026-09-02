#!/usr/bin/env python3
"""Convert an attack_data windows-xml.log file to Zircolite JSON-lines input.

Why this script exists: attack_data's windows-xml.log files are one
complete `<Event>...</Event>` XML document PER LINE, with no wrapping root
element across the whole file. Zircolite's native `-x/--xml-input` reader
(zircolite/streaming.py stream_xml_events) uses lxml.etree.iterparse on the
WHOLE FILE as a single XML document; against a multi-root file like this it
silently stops after the first top-level element and reports success (see
evidence/09_zircolite_correlation_attempt_stdout.txt and
evidence/10_zircolite_xml_truncation_repro.txt for the reproduction and
citation of the exact code path). That is reported as a finding, not
patched in Zircolite's code: this project does not modify vendored tools.

This script works around it for evaluation purposes only, by parsing each
line as its own XML document (lxml.etree.fromstring, one call per line,
which is well-formed since each line is a complete document on its own)
and flattening <System> and <EventData><Data Name="..."> children into one
flat JSON object per line, field names taken as-is from the XML (no
renaming). Output is JSON-lines, Zircolite's --json-input format.

Usage:
    python3 02_convert_xml_to_jsonl.py <input windows-xml.log> <output .jsonl>

Idempotent: re-running overwrites the output file with the same content
given the same input.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from lxml import etree

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def clean_tag(tag: str) -> str:
    return tag[len(NS):] if tag.startswith(NS) else tag


def parse_event_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    root = etree.fromstring(line.encode("utf-8"))
    flat: dict = {}
    for child in root:
        tag = clean_tag(child.tag)
        if tag == "System":
            for sub in child:
                subtag = clean_tag(sub.tag)
                if subtag == "Provider":
                    flat["Provider_Name"] = sub.get("Name")
                    if sub.get("Guid"):
                        flat["Guid"] = sub.get("Guid")
                elif subtag == "TimeCreated":
                    flat["SystemTime"] = sub.get("SystemTime")
                elif subtag == "Execution":
                    if sub.get("ProcessID"):
                        flat["Execution_ProcessID"] = sub.get("ProcessID")
                    if sub.get("ThreadID"):
                        flat["Execution_ThreadID"] = sub.get("ThreadID")
                elif subtag == "Correlation":
                    continue
                elif subtag == "Security":
                    continue
                else:
                    text = sub.text
                    if text is not None:
                        try:
                            flat[subtag] = int(text)
                        except ValueError:
                            flat[subtag] = text
        elif tag == "EventData" or tag == "UserData":
            for data in child:
                name = data.get("Name")
                if name:
                    flat[name] = data.text if data.text is not None else ""
    return flat


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <input windows-xml.log> <output .jsonl>", file=sys.stderr)
        return 2
    in_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    out_path.parent.mkdir(parents=True, exist_ok=True)

    total = 0
    skipped = 0
    with in_path.open("r", encoding="utf-8") as fh, out_path.open("w", encoding="utf-8") as out:
        for line in fh:
            if not line.strip():
                continue
            try:
                event = parse_event_line(line)
            except Exception as exc:  # noqa: BLE001 - report and continue
                skipped += 1
                print(f"skip malformed line: {exc}", file=sys.stderr)
                continue
            if event is None:
                continue
            out.write(json.dumps(event) + "\n")
            total += 1

    print(f"wrote {total} events to {out_path} ({skipped} lines skipped as malformed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
