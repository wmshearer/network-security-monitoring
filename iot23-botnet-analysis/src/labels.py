"""Read the ground-truth labels out of an IoT-23 Zeek conn log.

IoT-23 ships each capture with a Zeek conn.log.labeled file. Every row is one
network connection, and the last part of the row carries two labels added by the
dataset authors: a plain label (Benign or Malicious) and a detailed label naming
the behaviour (C&C, DDoS, PartOfAHorizontalPortScan, and so on).

The catch is that the files are not all formatted the same way. Some scenarios
write the two labels as their own tab-separated columns, so a row splits into 23
fields. Others pack both labels into a single trailing field separated by runs of
spaces, so the same row splits into 21 fields. Reading the label from a fixed
column number works on one format and quietly returns the wrong thing on the other.
This module handles both so the count cannot come out wrong depending on which
capture it was handed.

WHAT THIS IS NOT
    Not a classifier. It reads the labels the dataset already assigned. The point of
    the project is to measure how well simple, readable rules reproduce these labels,
    so the labels themselves are the ground truth being measured against, not a guess.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

# A Zeek conn.log row split on tabs has this many fields when the two labels are
# their own columns. Fewer than this means the labels are packed into the last
# field instead.
TABBED_LABEL_COLUMNS = 23


@dataclass(frozen=True)
class Connection:
    """One connection row, reduced to the parts this project uses."""

    proto: str          # tcp, udp, icmp
    resp_port: str      # the destination port, as a string (it can be "-")
    label: str          # Benign or Malicious
    detail: str         # the detailed behaviour: C&C, DDoS, and so on, or "-"


def _labels_from_row(fields: list[str]) -> tuple[str, str] | None:
    """Pull (label, detail) out of one already-tab-split row.

    Two layouts exist. When the row has the full column count, the label and detail
    are the last two tab fields. Otherwise they are packed into the final field,
    separated by runs of whitespace, as "<tunnel> <label> <detail>".
    """
    if len(fields) >= TABBED_LABEL_COLUMNS:
        label, detail = fields[-2], fields[-1]
    else:
        # The last tab field looks like "-   Benign   -". Split on whitespace and
        # take the last two words, which are the label and the detail.
        parts = fields[-1].split()
        if len(parts) < 2:
            return None
        label, detail = parts[-2], parts[-1]
    return _normalise(label), detail.strip()


def _normalise(label: str) -> str:
    """One capitalisation for the plain label. Some files write 'benign' lowercase."""
    l = label.strip().lower()
    if l == "benign":
        return "Benign"
    if l == "malicious":
        return "Malicious"
    return label.strip()


def read_connections(labeled_log: Path) -> list[Connection]:
    """Read every labelled connection from one Zeek conn.log.labeled file."""
    out: list[Connection] = []
    with open(labeled_log, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            fields = line.rstrip("\n").split("\t")
            if len(fields) < 7:
                continue
            labels = _labels_from_row(fields)
            if labels is None:
                continue
            label, detail = labels
            out.append(Connection(
                proto=fields[6],
                resp_port=fields[5],
                label=label,
                detail=detail,
            ))
    return out


def label_counts(connections: list[Connection]) -> Counter:
    """Count connections by their plain label (Benign or Malicious)."""
    return Counter(c.label for c in connections)


def detail_counts(connections: list[Connection]) -> Counter:
    """Count connections by their detailed behaviour label."""
    return Counter(c.detail for c in connections)
