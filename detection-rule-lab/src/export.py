"""Export the labeled corpus to the JSON-lines form Zircolite consumes.

Reuses the ai-triage-engine's normalization and contamination controls rather than
re-deriving them. That project already established, the hard way, that malicious and
benign records here come from different collection stacks and are trivially separable
by collection artifacts unless those are stripped. Rebuilding that from scratch would
mean rediscovering the same three leaks.

What gets written is `raw_event`, not the normalized AlertRecord: Sigma rules are
written against real Windows/Sysmon field names (Image, CommandLine, TargetObject,
ParentImage), which is what raw_event preserves.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

TRIAGE = Path("/home/kali/director/projects/ai-triage-engine")
if str(TRIAGE) not in sys.path:
    sys.path.insert(0, str(TRIAGE))


@dataclass(frozen=True)
class ExportResult:
    path: Path
    written: int
    skipped_no_eventid: int


def write_jsonl(records, out_path: Path) -> ExportResult:
    """Write each record's raw_event as one JSON object per line.

    Records without an EventID are skipped and COUNTED rather than dropped
    silently: Sigma rules key off EventID plus Channel, so a record lacking one
    cannot match anything, and a silent drop would quietly shrink the denominator
    that every later count is measured against.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    skipped = 0
    with out_path.open("w") as fh:
        for rec in records:
            raw = getattr(rec, "raw_event", None) or {}
            if not raw.get("EventID"):
                skipped += 1
                continue
            fh.write(json.dumps(raw, default=str))
            fh.write("\n")
            written += 1
    return ExportResult(path=out_path, written=written, skipped_no_eventid=skipped)


def load_labeled_corpus(mitigate_shortcuts: bool = True):
    """Load the triage engine's malicious and benign records, contamination-controlled.

    `mitigate_shortcuts=True` applies the same field-ablation and timestamp
    rebasing the triage evaluation used. It is on by default here for the same
    reason it was there: without it, the two classes are separable by which tool
    collected them rather than by behaviour.

    Note the asymmetry with the triage work: THIS project does not need the
    classes balanced, because Sigma rules are scored per class independently
    rather than trained on a mixed set. So no ratio control is applied.
    """
    from src.ingest.normalize import normalize_capture  # noqa: PLC0415
    from src.ingest.normalize_benign import normalize_evtx_capture  # noqa: PLC0415

    return normalize_capture, normalize_evtx_capture
