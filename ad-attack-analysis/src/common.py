"""Shared plumbing for the AD detection modules: run tshark, get fields back.

Every module in this project asks tshark the same kind of question: apply a
display filter, pull a handful of fields, get tab-separated lines back. That
subprocess call, and the fragile bits around it (a filter that matches nothing,
a field that renders in a form tshark did not document), are written once here
so each detector can stay about the traffic shape it is looking for and not
about subprocess plumbing.

DsGetNCChanges legitimacy also lives here rather than in dcsync.py, because
"which hosts are domain controllers" is an operational fact about the
environment, not something derivable from the capture. A capture only shows
what happened, not what was supposed to happen. Deriving the allow-list from
observed traffic would be circular: whatever replicated would define itself as
allowed to replicate.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


def run_tshark(pcap: Path, display_filter: str, fields: list[str],
                timeout: float = 3600.0) -> list[list[str]]:
    """Run tshark with a display filter and return rows of tab-split fields.

    One shared invocation point so every module builds the same command shape
    (-T fields, tab-separated, one -e per field) and handles the same failure
    mode: a filter with a typo returns empty output and a zero exit code, not
    an error. Callers see an empty list either way, which is why every
    extractor in this project treats "no rows" as a real, reportable result
    rather than something to distinguish from "tshark broke."
    """
    cmd = ["tshark", "-r", str(pcap), "-Y", display_filter,
           "-T", "fields", "-E", "separator=\t", "-E", "header=n"]
    for f in fields:
        cmd += ["-e", f]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0 and not proc.stdout:
        raise RuntimeError("tshark failed: %s" % proc.stderr[-400:])

    rows: list[list[str]] = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        rows.append(line.split("\t"))
    return rows


def frame_count(pcap: Path, timeout: float = 3600.0) -> int:
    """Total frame count in a capture, for reporting alongside a finding count."""
    cmd = ["tshark", "-r", str(pcap), "-T", "fields", "-e", "frame.number"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0 and not proc.stdout:
        return 0
    return sum(1 for line in proc.stdout.splitlines() if line.strip())


# Known domain controllers for the lab this project analyses. This is an
# operational fact, supplied by whoever runs the environment, not a value
# read out of the traffic. A detector that inferred "DC-ness" from who issues
# DsGetNCChanges would call the theft itself normal, because it is the only
# traffic that would ever look like a DC replicating.
#
# picklesworth.local, DC = snicklefritz.picklesworth.local
KNOWN_DCS: frozenset[str] = frozenset({"192.168.1.195"})
