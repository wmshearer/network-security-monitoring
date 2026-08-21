#!/usr/bin/env python3
"""Lint detection rules against this document's own lifecycle requirements.

This is NOT a Sigma parser. Sigma's real spec allows nested conditions, lists,
modifiers, and correlation rules, and a correct parser for that is a real project
(pySigma exists for a reason). This script reads a much smaller, flat subset:
top-level `key: value` pairs, plus a small number of block scalars for multi-line
fields (falsepositives, validation_steps, references), each written as a YAML
block list (lines starting with "  - "). That subset is Sigma-SHAPED: a file that
passes this linter is not guaranteed to be valid Sigma, and a file rejected by
this linter may still be valid Sigma. Anywhere this matters, the docs say
Sigma-shaped, not Sigma-valid.

Fields checked, and why:

  status              Must be one of the five values SigmaHQ's spec defines:
                       experimental, test, stable, deprecated, unsupported.
                       (See docs/LIFECYCLE.md for the two states this document
                       adds on top of the spec: muted and retired. Those are NOT
                       Sigma values and this linter does not accept them in
                       `status`, they are tracked separately, see MUTED_FIELDS
                       and RETIRED_FIELDS below.)

  Mandatory ADS-derived fields (adapted from Palantir's Alerting and Detection
  Strategy framework, see docs/LIFECYCLE.md for the mapping). These must be
  present and non-empty for a rule to exist at all, regardless of status:
    - title
    - id
    - status
    - goal                  (ADS: Goal)
    - logsource              (ADS: Technical Context, narrowed to "what data")
    - detection              (the actual match logic)
    - falsepositives         (ADS: False Positives), must be a non-empty list
    - level                  (ADS: Priority)

  Additional requirements gated on status:
    - stable   rules must also have a non-empty `validation_steps` list
               (ADS: Validation) AND a non-empty `falsepositives` list already
               required above. A rule cannot be promoted to stable just
               because someone feels good about it.
    - deprecated rules must name `replaced_by` (a rule id) OR set
               `retired: true` with a `retired_reason`. Sigma's own status
               field only has one deprecated value for both "replaced" and
               "gone for good", so this linter is stricter than the spec here
               on purpose, because that conflation is the exact gap this
               document argues the spec has.

Usage:
    python3 lint_detection.py <file-or-directory> [<file-or-directory> ...]

Exit code is 0 if every rule passes, 1 if any rule fails.
"""

from __future__ import annotations

import sys
from pathlib import Path

VALID_SIGMA_STATUS = {"experimental", "test", "stable", "deprecated", "unsupported"}

# Fields this document's lifecycle requires on every rule, regardless of status.
# These are adapted from Palantir's ADS framework fields (see docs/LIFECYCLE.md),
# narrowed to what a single flat rule file can practically carry.
MANDATORY_FIELDS = ["title", "id", "status", "goal", "logsource", "detection", "falsepositives", "level"]

# Fields that are optional everywhere but required once a rule reaches a given
# status. Each entry: (status, field, kind) where kind is "scalar" or "list".
STATUS_GATED_FIELDS = [
    ("stable", "validation_steps", "list"),
]

# Sigma's own five-value enum has no state for "in production but currently
# silenced" and no state for "retired because the underlying threat is gone,"
# as distinct from "replaced by a better rule." Both are additions THIS
# document makes on top of the spec, not part of SigmaHQ's status field. They
# are tracked as separate boolean/annotation fields rather than folded into
# `status`, so `status` stays a valid Sigma value at all times.
MUTED_FIELD = "muted"
MUTED_REASON_FIELD = "muted_reason"
RETIRED_FIELD = "retired"
RETIRED_REASON_FIELD = "retired_reason"
REPLACED_BY_FIELD = "replaced_by"


class RuleError(list):
    """A list of human-readable problems found in one rule file."""


def parse_rule_file(path: Path) -> dict:
    """Parse the small key:value / block-list subset described in the module
    docstring. Returns a dict of field name -> str (scalar) or list[str] (block
    list). Comments (#) and blank lines are ignored. This does not understand
    YAML nesting, flow collections, anchors, or multi-document files.
    """
    fields: dict[str, object] = {}
    current_list_key: str | None = None

    for raw_line in path.read_text().splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Block-list item: "  - value"
        if line.startswith(("  - ", "\t- ")) or stripped.startswith("- "):
            if current_list_key is None:
                raise ValueError(f"{path}: list item with no preceding 'key:' line: {raw_line!r}")
            value = stripped[2:].strip().strip('"').strip("'")
            existing = fields.setdefault(current_list_key, [])
            if not isinstance(existing, list):
                raise ValueError(f"{path}: {current_list_key!r} used as both scalar and list")
            existing.append(value)
            continue

        # "key:" (starts a block list) or "key: value" (scalar)
        if ":" not in stripped:
            raise ValueError(f"{path}: unparseable line: {raw_line!r}")
        key, _, rest = stripped.partition(":")
        key = key.strip()
        rest = rest.strip()

        if rest == "":
            # Opens a block list. The following "  - " lines belong to it.
            current_list_key = key
            fields.setdefault(key, [])
        else:
            current_list_key = None
            fields[key] = rest.strip('"').strip("'")

    return fields


def _is_empty(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    if isinstance(value, list):
        return len(value) == 0
    return False


def lint_rule(fields: dict) -> list[str]:
    """Return a list of problem strings. Empty list means the rule passes."""
    problems: list[str] = []

    # 1. status must be a valid Sigma value.
    status = fields.get("status")
    if _is_empty(status):
        problems.append("missing required field: status")
    elif status not in VALID_SIGMA_STATUS:
        problems.append(
            f"status {status!r} is not one of the five Sigma values: "
            f"{sorted(VALID_SIGMA_STATUS)}"
        )

    # 2. mandatory ADS-derived fields present and non-empty.
    for field in MANDATORY_FIELDS:
        if field == "status":
            continue  # already checked above with a more specific message
        if _is_empty(fields.get(field)):
            problems.append(f"missing required field: {field}")

    # 3. falsepositives, if present at all, must be a non-empty list, not a
    # bare scalar string. A single string here usually means someone wrote
    # "falsepositives: unknown" instead of an actual list, which is exactly
    # the kind of unexamined placeholder this document argues against.
    fp = fields.get("falsepositives")
    if fp is not None and not isinstance(fp, list):
        problems.append("falsepositives must be a list, not a single scalar value")

    # 4. status-gated requirements.
    if status == "stable":
        for gated_status, field, kind in STATUS_GATED_FIELDS:
            if gated_status != "stable":
                continue
            value = fields.get(field)
            if _is_empty(value):
                problems.append(f"status is 'stable' but missing required field: {field}")
            elif kind == "list" and not isinstance(value, list):
                problems.append(f"status is 'stable' but {field!r} must be a list, not a scalar")
        if _is_empty(fields.get("falsepositives")):
            problems.append("status is 'stable' but falsepositives list is empty")

    if status == "deprecated":
        replaced_by = fields.get(REPLACED_BY_FIELD)
        retired = str(fields.get(RETIRED_FIELD, "")).strip().lower() == "true"
        retired_reason = fields.get(RETIRED_REASON_FIELD)
        if _is_empty(replaced_by) and not retired:
            problems.append(
                "status is 'deprecated' but neither replaced_by (a rule id) nor "
                "retired: true is set. Sigma's spec conflates 'replaced' and "
                "'obsolete' under one status value; this linter requires the "
                "rule to say which one it means"
            )
        if retired and _is_empty(retired_reason):
            problems.append("retired: true but retired_reason is missing")
        if not _is_empty(replaced_by) and retired:
            problems.append(
                "rule sets both replaced_by and retired: true. A rule is either "
                "replaced by a named successor or retired outright, not both"
            )

    # 5. muted is a lifecycle addition, not a Sigma status. If set, it needs a
    # reason, and it should not be combined with a status of deprecated
    # (a rule cannot be simultaneously "replaced/gone" and "temporarily silenced").
    muted = str(fields.get(MUTED_FIELD, "")).strip().lower() == "true"
    if muted and _is_empty(fields.get(MUTED_REASON_FIELD)):
        problems.append("muted: true but muted_reason is missing")
    if muted and status == "deprecated":
        problems.append("rule is both muted: true and status: deprecated, pick one")

    return problems


def find_rule_files(targets: list[str]) -> list[Path]:
    files: list[Path] = []
    for target in targets:
        path = Path(target)
        if path.is_dir():
            files.extend(sorted(path.glob("*.yml")))
            files.extend(sorted(path.glob("*.yaml")))
        elif path.is_file():
            files.append(path)
        else:
            print(f"warning: {target} is not a file or directory, skipping", file=sys.stderr)
    return files


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 1

    files = find_rule_files(argv)
    if not files:
        print("no rule files found", file=sys.stderr)
        return 1

    overall_ok = True
    for path in files:
        try:
            fields = parse_rule_file(path)
        except ValueError as exc:
            print(f"FAIL {path}")
            print(f"  parse error: {exc}")
            overall_ok = False
            continue

        problems = lint_rule(fields)
        title = fields.get("title", path.name)
        if problems:
            overall_ok = False
            print(f"FAIL {path}  ({title})")
            for problem in problems:
                print(f"  - {problem}")
        else:
            status = fields.get("status", "?")
            print(f"PASS {path}  ({title}, status={status})")

    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
