#!/usr/bin/env python3
"""Load the manifest of selected cloud audit-log files into the NEW
`cloud_lab` Splunk index, one file per `splunk add oneshot` call, tagged
with the correct sourcetype per platform.

Does NOT touch main, history, summary, internal, detection_lab,
detection_lab_alerts, ingest_lab, or ingest_lab_naive -- every call below is
explicitly scoped to -index cloud_lab.

Run src/select_cloud_files.py first to produce data/manifest.csv; this
script reads that manifest rather than re-walking the corpus, so file
selection and ingestion are two separately auditable steps.

Usage:
    python3 src/ingest_cloud_lab.py [--manifest data/manifest.csv]
                                     [--splunk-home /home/kali/splunk]
                                     [--index cloud_lab]
"""

from __future__ import annotations

import argparse
import csv
import subprocess
import sys
from pathlib import Path

# Manifest platform label -> Splunk sourcetype. aws_cloudtrail_ocsf is
# intentionally absent: OCSF CloudTrail is out of scope for this phase (see
# conf/props.conf's "The OCSF CloudTrail variant" section for the full
# reasoning) and is skipped rather than ingested under a wrong sourcetype.
PLATFORM_TO_SOURCETYPE = {
    "aws_cloudtrail": "aws:cloudtrail",
    "azure_monitor": "azure:monitor:aad",
    "o365_management": "o365:management:activity",
}


def ingest_file(
    splunk_bin: Path,
    file_path: Path,
    sourcetype: str,
    index: str,
    technique_id: str,
) -> tuple[bool, str]:
    cmd = [
        str(splunk_bin),
        "add",
        "oneshot",
        str(file_path),
        "-index",
        index,
        "-sourcetype",
        sourcetype,
        # host set to the ATT&CK technique ID this file came from, so a
        # search can filter/group by originating technique without needing
        # a separate lookup -- the manifest's own technique_id column,
        # carried through into the indexed data itself.
        "-hostname",
        technique_id,
        "-auth",
        "admin:[REDACTED]",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    ok = result.returncode == 0
    output = (result.stdout + result.stderr).strip()
    return ok, output


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", default=str(Path(__file__).resolve().parents[1] / "data/manifest.csv"))
    ap.add_argument("--corpus-root", default=str(
        Path(__file__).resolve().parents[2] / "_corpora/attack_data/datasets/attack_techniques"
    ))
    ap.add_argument("--splunk-home", default="/home/kali/splunk")
    ap.add_argument("--index", default="cloud_lab")
    args = ap.parse_args()

    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"manifest not found: {manifest_path}. Run src/select_cloud_files.py first.", file=sys.stderr)
        return 1

    splunk_bin = Path(args.splunk_home) / "bin" / "splunk"
    if not splunk_bin.exists():
        print(f"splunk binary not found: {splunk_bin}", file=sys.stderr)
        return 1

    corpus_root = Path(args.corpus_root)

    counts = {"ok": 0, "fail": 0, "skipped_out_of_scope": 0}
    failures: list[str] = []

    with manifest_path.open() as fh:
        rows = list(csv.DictReader(fh))

    for row in rows:
        platform = row["platform"]
        sourcetype = PLATFORM_TO_SOURCETYPE.get(platform)
        if sourcetype is None:
            counts["skipped_out_of_scope"] += 1
            continue
        file_path = corpus_root / row["path"]
        ok, output = ingest_file(splunk_bin, file_path, sourcetype, args.index, row["technique_id"])
        if ok:
            counts["ok"] += 1
        else:
            counts["fail"] += 1
            failures.append(f"{row['path']}: {output}")
            print(f"FAILED: {row['path']}\n  {output}", file=sys.stderr)

    print(f"ingested ok: {counts['ok']}")
    print(f"failed: {counts['fail']}")
    print(f"skipped (out of scope, e.g. aws_cloudtrail_ocsf): {counts['skipped_out_of_scope']}")
    return 0 if counts["fail"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
