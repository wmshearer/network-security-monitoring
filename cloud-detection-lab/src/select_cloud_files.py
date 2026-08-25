#!/usr/bin/env python3
"""Find the cloud audit-log files in the attack_data corpus, classify each one
by platform using its actual JSON content (never the filename alone), apply
the documented exclusion list, and write a manifest.

Why content, not filename: several files in this corpus have misleading
names or shapes. A file named "azure_vidar_access.log" is not Azure data at
all (it is a Windows Security Event XML export), and several files with
"o365" in their path are actually a different JSON shape entirely (a Splunk
search-result export, key=value flattened, not the real O365 Management
Activity API shape). Filename matching alone would pull those in silently.

Classification rule, checked against the first non-blank line of each file:
  aws_cloudtrail   -- has "eventTime" AND "eventSource" AND "awsRegion"
                       (the raw/native CloudTrail record shape)
  aws_cloudtrail_ocsf -- has "metadata" AND ("time" as an epoch integer,
                       not a string) AND "cloud" -- this is the OCSF
                       (Open Cybersecurity Schema Framework) reshaping of
                       CloudTrail used by Amazon Security Lake exports, a
                       DIFFERENT wire format from raw CloudTrail. Its own
                       platform label so it never gets silently merged into
                       aws_cloudtrail's sourcetype.
  azure_monitor    -- has "operationName" AND "time" (string) AND
                       ("category" or "resourceId") -- Azure Monitor
                       Activity Log / Azure AD audit export shape.
  o365_management  -- has "CreationTime" AND "Operation" -- the real O365
                       Management Activity API event shape.

A file that matches none of these shapes, or matches the exclusion list
below, is left out of the manifest and counted separately so the "why not"
is visible, not silently dropped.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

# Exclusion list, established by direct inspection (per task brief) --
# these paths look like cloud audit data by name but are not, confirmed by
# reading their actual content. Matched as a path suffix so the script does
# not depend on this corpus living at one fixed absolute location.
EXCLUDE_SUFFIXES = [
    "T1528/vidar_azure_file_access/azure_vidar_access.log",
    # T1204 Falco shell-spawn logs are plain text, not JSON audit events.
    # Matched by directory pattern rather than one literal path since there
    # can be more than one file under that technique/dataset pair.
    "kubernetes_falco_shell_spawned",
    # T1212 nginx access logs, matched the same way (directory pattern).
    "kubernetes_nginx_",
    "T1537/aws_exfil_risk_events/aws_risk.log",
    "T1204.003/risk_dataset/aws_ecr_risk_dataset.log",
    # T1078 gcploit files are a pre-flattened Splunk search export, not raw
    # GCP audit log JSON.
    "T1078/gcploit_exploitation_framework",
    # The 4 O365 files using the {"preview":..,"result":{"Actor{}.ID":..}}
    # Splunk search-export shape, named explicitly (path, not a directory
    # pattern, since other files in the same T1136.003 directory ARE real
    # O365 data and must stay in).
    "T1136.003/o365_add_app_role_assignment_grant_user/o365_add_app_role_assignment_grant_user.json",
    "T1136.003/o365_added_service_principal/o365_added_service_principal.json",
    "T1136.003/o365_new_federated_domain_added/o365_new_federated_domain_added.json",
]

# A 4th preview-shaped O365 file is found by content match (KV_MODE-style
# "preview" key at top level) rather than hardcoded here, see
# _is_splunk_export_shape() below -- the brief says "4 O365 files" total
# using that shape; three are named above by path, the exclusion logic
# below also content-matches so a mislabeled 4th is still caught even if
# its path is not one of the three named here.

CANDIDATE_EXTENSIONS = {".json", ".log"}


def _first_json_line(path: Path) -> dict | None:
    try:
        with path.open("r", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    return None
    except OSError:
        return None
    return None


def _is_splunk_export_shape(obj: dict) -> bool:
    """The {"preview":..,"result":{...}} Splunk search-export shape --
    content-based catch-all for the "4 O365 files" the brief names, so a
    file matching this shape is excluded even if its path was not one of
    the three hardcoded above."""
    return "preview" in obj and "result" in obj and isinstance(obj.get("result"), dict)


def classify(obj: dict) -> str | None:
    if _is_splunk_export_shape(obj):
        return None
    if "eventTime" in obj and "eventSource" in obj and "awsRegion" in obj:
        return "aws_cloudtrail"
    if "metadata" in obj and "cloud" in obj and isinstance(obj.get("time"), (int, float)):
        return "aws_cloudtrail_ocsf"
    if "operationName" in obj and isinstance(obj.get("time"), str) and (
        "category" in obj or "resourceId" in obj
    ):
        return "azure_monitor"
    if "CreationTime" in obj and "Operation" in obj:
        return "o365_management"
    return None


def is_excluded(rel_path: str) -> bool:
    return any(suffix in rel_path for suffix in EXCLUDE_SUFFIXES)


@dataclass
class ManifestRow:
    path: str
    platform: str
    technique_id: str
    bytes: int


def technique_id_from_path(rel_path: str) -> str:
    # Corpus layout is attack_techniques/<TechniqueID>/<dataset>/<file>;
    # rel_path is already relative to attack_techniques/, so the first path
    # segment is the technique ID.
    parts = Path(rel_path).parts
    return parts[0] if parts else "unknown"


def scan(corpus_root: Path) -> tuple[list[ManifestRow], dict[str, int]]:
    rows: list[ManifestRow] = []
    skip_counts: dict[str, int] = {"excluded": 0, "unclassified": 0}
    for dirpath, _dirnames, filenames in os.walk(corpus_root):
        for name in filenames:
            fpath = Path(dirpath) / name
            if fpath.suffix.lower() not in CANDIDATE_EXTENSIONS:
                continue
            rel = str(fpath.relative_to(corpus_root))
            if is_excluded(rel):
                skip_counts["excluded"] += 1
                continue
            obj = _first_json_line(fpath)
            if obj is None:
                continue
            platform = classify(obj)
            if platform is None:
                skip_counts["unclassified"] += 1
                continue
            rows.append(
                ManifestRow(
                    path=rel,
                    platform=platform,
                    technique_id=technique_id_from_path(rel),
                    bytes=fpath.stat().st_size,
                )
            )
    return rows, skip_counts


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--corpus-root",
        default=str(
            Path(__file__).resolve().parents[2]
            / "_corpora/attack_data/datasets/attack_techniques"
        ),
        help="Root of the attack_techniques corpus (parameterized, no hardcoded absolute path required).",
    )
    ap.add_argument(
        "--out",
        default=str(Path(__file__).resolve().parents[1] / "data/manifest.csv"),
        help="Where to write the manifest CSV.",
    )
    args = ap.parse_args()

    corpus_root = Path(args.corpus_root)
    if not corpus_root.is_dir():
        print(f"corpus root not found: {corpus_root}", file=sys.stderr)
        return 1

    rows, skip_counts = scan(corpus_root)
    rows.sort(key=lambda r: (r.platform, r.path))

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["path", "platform", "technique_id", "bytes"])
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))

    by_platform: dict[str, int] = {}
    total_bytes_by_platform: dict[str, int] = {}
    for row in rows:
        by_platform[row.platform] = by_platform.get(row.platform, 0) + 1
        total_bytes_by_platform[row.platform] = total_bytes_by_platform.get(row.platform, 0) + row.bytes

    print(f"manifest written: {out_path} ({len(rows)} files)")
    for platform in sorted(by_platform):
        mb = total_bytes_by_platform[platform] / (1024 * 1024)
        print(f"  {platform}: {by_platform[platform]} files, {mb:.1f} MB")
    print(f"excluded (matched exclusion list): {skip_counts['excluded']}")
    print(f"unclassified (no shape matched, not counted as cloud data): {skip_counts['unclassified']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
