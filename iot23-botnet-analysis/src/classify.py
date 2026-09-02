"""Reproduce the IoT-23 behaviour labels with a few readable rules, and measure how well.

The dataset already labels each connection (DDoS, C&C, port scan, or benign). The
question this project asks is a fair one for a detection engineer: how much of that
labelling can a handful of simple, explainable rules reproduce on their own? A rule
you can read and argue with is worth more in a SOC than a black box, but only if it
actually holds up against ground truth. So every rule here is scored against the
dataset's own labels and reported as precision and recall, not asserted.

The rules come from what the traffic in this capture actually does:
  - Botnet C&C in this family rides IRC on TCP 6667.
  - The DDoS phase is a flood of TCP connections to a victim's port 80.
  - Scanning shows up as TCP connections to one unusual high port across many hosts.
Everything else is left unlabelled by the rules, which is deliberate: a rule that
guesses on traffic it has no signal for would score well by luck and badly in life.

WHAT THIS IS NOT
    Not a claim that these ports define these attacks everywhere. They are what this
    malware family did in this capture. The value is the method: write a readable
    rule, score it against ground truth, and report where it holds and where it does
    not, rather than trusting it because it sounds right.
"""

from __future__ import annotations

from dataclasses import dataclass

from .labels import Connection

# Behaviour names, matching the dataset's detailed labels.
C2 = "C&C"
DDOS = "DDoS"
SCAN = "PortScan"
BENIGN = "Benign"
UNLABELLED = "-"


def rule_label(conn: Connection) -> str:
    """Apply the readable rules to one connection. Returns a behaviour or UNLABELLED.

    Order matters only where rules could overlap; here they key on distinct ports,
    so each connection matches at most one.
    """
    if conn.proto == "tcp" and conn.resp_port == "6667":
        return C2
    if conn.proto == "tcp" and conn.resp_port == "80":
        return DDOS
    if conn.proto == "tcp" and conn.resp_port == "63798":
        return SCAN
    return UNLABELLED


# Map the dataset's detailed labels onto the same behaviour names the rules produce,
# so the two can be compared directly. Detailed labels the rules do not target
# (benign chatter, other families) map to BENIGN or UNLABELLED accordingly.
def truth_behaviour(conn: Connection) -> str:
    """The ground-truth behaviour for one connection, in the rules' vocabulary."""
    d = conn.detail
    if d == "C&C" or d.startswith("C&C"):
        return C2
    if d == "DDoS":
        return DDOS
    if d == "PartOfAHorizontalPortScan":
        return SCAN
    if conn.label == "Benign":
        return BENIGN
    return UNLABELLED


@dataclass(frozen=True)
class Score:
    """Precision and recall for one behaviour, measured against ground truth."""

    behaviour: str
    true_positives: int
    false_positives: int
    false_negatives: int

    @property
    def precision(self) -> float | None:
        hits = self.true_positives + self.false_positives
        return self.true_positives / hits if hits else None

    @property
    def recall(self) -> float | None:
        real = self.true_positives + self.false_negatives
        return self.true_positives / real if real else None

    def as_row(self) -> dict:
        return {
            "behaviour": self.behaviour,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": None if self.precision is None else round(self.precision, 4),
            "recall": None if self.recall is None else round(self.recall, 4),
        }


def score_behaviour(connections: list[Connection], behaviour: str) -> Score:
    """Score the rule for one behaviour against the dataset's labels."""
    tp = fp = fn = 0
    for c in connections:
        predicted = rule_label(c) == behaviour
        actual = truth_behaviour(c) == behaviour
        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
        elif actual and not predicted:
            fn += 1
    return Score(behaviour=behaviour, true_positives=tp,
                 false_positives=fp, false_negatives=fn)


def score_all(connections: list[Connection]) -> list[Score]:
    """Score every attack behaviour the rules target."""
    return [score_behaviour(connections, b) for b in (C2, DDOS, SCAN)]
