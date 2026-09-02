"""Shared constants and read-only loaders for the false-positive-economics project.

Nothing in this file writes to, or otherwise modifies, the two source
projects it reads from. Every function here opens a file with mode "r"
(the default) and never "w" or "a".
"""

from __future__ import annotations

import json
from pathlib import Path

# Absolute paths to the two source projects. Read-only inputs.
DETECTION_RULE_LAB = Path("/home/kali/director/projects/detection-rule-lab")
EBPF_CONTAINER_DETECTION = Path("/home/kali/director/projects/ebpf-container-detection")

SCORING_RUN_JSON = DETECTION_RULE_LAB / "reports" / "scoring-run.json"
EBPF_ANALYSIS_JSON = EBPF_CONTAINER_DETECTION / "evidence" / "analysis.json"

# This project's own directories.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = PROJECT_ROOT / "evidence"
CHARTS_DIR = PROJECT_ROOT / "charts"

# The caveat banner, reused verbatim (word-for-word) from
# detection-rule-lab/reports/findings.md, "## Limitations", items 1 and 4.
# This exact block must appear on every output artifact this project produces.
CAVEAT_BANNER = (
    "CAVEAT (verbatim from detection-rule-lab/reports/findings.md): "
    "\"These are counts on one corpus, not rates. The benign baseline is a "
    "single Windows Server 2022 host. A rule that is quiet here may be noisy "
    "on a workstation fleet, a developer machine, or a domain controller. "
    "Nothing here supports a claim about any rule's false-positive rate in "
    "general.\" And: \"Event counts are not alert counts. A rule matching "
    "4,000 events would not produce 4,000 alerts in a real SIEM, which would "
    "aggregate them. Counts here measure match volume, not analyst workload.\""
)


def load_scoring_run() -> dict:
    """Read detection-rule-lab's scoring-run.json. Read-only; raises if absent."""
    with open(SCORING_RUN_JSON, "r", encoding="utf-8") as f:
        return json.load(f)


def load_ebpf_analysis() -> dict:
    """Read ebpf-container-detection's analysis.json. Read-only; raises if absent."""
    with open(EBPF_ANALYSIS_JSON, "r", encoding="utf-8") as f:
        return json.load(f)


def rules_touching_benign(scoring_run: dict) -> list[dict]:
    """The subset of the 135 fired rules that produced at least one benign hit."""
    return [r for r in scoring_run["results"] if r["benign_hits"] > 0]
