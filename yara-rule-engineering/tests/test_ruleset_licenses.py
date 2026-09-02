"""Pins the four ruleset licence classifications, read from the actual
cloned LICENSE files, not from a hardcoded table."""
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
RULESETS_DIR = PROJECT_DIR / ".rulesets"


def _read_license(repo_name: str, filenames):
    repo_dir = RULESETS_DIR / repo_name
    if not repo_dir.exists():
        pytest.skip(f"ruleset not cloned: .rulesets/{repo_name}")
    for fn in filenames:
        p = repo_dir / fn
        if p.exists():
            return p.read_text()
    pytest.fail(f"no license file found for {repo_name} (looked for {filenames})")


def test_yara_rules_is_gplv2():
    text = _read_license("yara-rules", ["LICENSE"])
    assert "GNU GENERAL PUBLIC LICENSE" in text
    assert "Version 2" in text


def test_reversinglabs_is_mit_2020():
    text = _read_license("reversinglabs", ["LICENSE"])
    assert "Copyright (c) 2020 ReversingLabs" in text
    assert "Permission is hereby granted, free of charge" in text
    # This license text never labels itself "MIT" (no line says "MIT License"
    # verbatim); it is classified as MIT by content/structure match, not by
    # a self-declared label. "MIT" as a whole word must not appear (note:
    # the substring "MIT" DOES appear inside "LIMITED"/"MERCHANTABILITY",
    # so this checks for it as an isolated word, not a bare substring).
    import re

    assert re.search(r"\bMIT\b", text) is None


def test_signature_base_is_detection_rule_license_not_osi():
    text = _read_license("signature-base", ["LICENSE"])
    assert "Detection Rule License" in text
    assert "DRL" in text
    # DRL requires attribution retention -- confirm the actual clause is present.
    assert "identification of the authors" in text


def test_protections_artifacts_is_elastic_license_2():
    text = _read_license("protections-artifacts", ["LICENSE.txt"])
    assert "Elastic License 2.0" in text
    normalized = " ".join(text.split())  # collapse line-wrap whitespace before matching the clause
    assert "hosted or managed service" in normalized  # the non-OSI-critical clause
