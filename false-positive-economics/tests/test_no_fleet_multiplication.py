"""Guard test: this project must never compute or claim an absolute dollar
figure by multiplying a per-alert cost by a fleet size or host count.

That framing is explicitly rejected in the project brief:
"REJECTED and forbidden: absolute cost per alert times fleet size. Do not
build it, do not include it 'for comparison.'"

This test does not depend on either source project, so it never skips.
"""

from __future__ import annotations

from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"

FORBIDDEN_TOKENS = [
    "fleet_size",
    "num_hosts",
    "host_count",
    "n_hosts",
    "fleet_multiplier",
    "workstation_count",
]


def test_no_forbidden_fleet_tokens_in_scripts():
    offending = []
    for path in SCRIPTS_DIR.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for token in FORBIDDEN_TOKENS:
            if token in text.lower():
                offending.append((path.name, token))
    assert not offending, f"forbidden fleet-multiplication tokens found: {offending}"


def test_readme_does_not_assert_absolute_fleet_dollar_total():
    readme = Path(__file__).resolve().parent.parent / "README.md"
    if not readme.exists():
        return  # nothing to check yet
    text = readme.read_text(encoding="utf-8").lower()
    for token in FORBIDDEN_TOKENS:
        assert token not in text
