"""Shared data shapes for the poller and both playbooks.

Kept as plain dataclasses (no ORM, no external schema library) because the
whole pipeline is a few hundred events end to end, not a production case
management system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Alert:
    """One row pulled from the detection_lab_alerts index."""

    detection: str
    technique: str
    search_name: str
    result_count: int
    sid: str
    time: str
    raw: str


@dataclass
class Indicator:
    """One indicator-shaped value pulled out of an alert's underlying raw
    event. kind is one of: process_image, registry_path, parent_image,
    hostname, command_line. There is no ip / hash / domain kind produced by
    this portfolio's current detections -- see enrichment.py.
    """

    kind: str
    value: str


@dataclass
class SourceCall:
    """Record of one enrichment source that was actually called, or
    explicitly not called, and why. Every source in ENRICHMENT_SOURCES
    produces exactly one of these per alert, so the log always shows the
    full set of what was tried.
    """

    source: str
    called: bool
    reason: str
    result: Optional[dict] = None


@dataclass
class Verdict:
    label: str  # "malicious" | "suspicious" | "benign" | "unresolved"
    confidence: str  # "high" | "low" | "none"
    rule: str  # the decision rule text that produced this label
    evidence: list = field(default_factory=list)


@dataclass
class EnrichmentRecord:
    alert: Alert
    indicators: list  # list[Indicator]
    source_calls: list  # list[SourceCall]
    verdict: Verdict


@dataclass
class SimulatedAction:
    alert_detection: str
    technique: str
    action: str  # e.g. "isolate_host", "disable_account", "block_ip", "no_action"
    target: str  # what the action would apply to (hostname, process, etc)
    reasoning: str
    label: str = "SIMULATED_ACTION"
