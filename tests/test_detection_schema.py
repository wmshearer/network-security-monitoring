"""Pure unit tests over detections/sigma/*.yml and detections/spl/*.yml.
No live Splunk needed. Checks the schema completeness the task brief
requires: every SPL detection carries an id, description, search,
mitre_attack_id, a non-blank known_false_positives, and a filter-macro
reference at the end of its search; every Sigma file is valid YAML with
the required Sigma fields.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

SIGMA_DIR = Path(__file__).parent.parent / "detections/sigma"
SPL_DIR = Path(__file__).parent.parent / "detections/spl"


def _load_all_sigma_docs():
    """Load every YAML document in every sigma file (some files are
    multi-document: a base rule plus a correlation rule)."""
    docs = []
    for f in sorted(SIGMA_DIR.glob("*.yml")):
        for doc in yaml.safe_load_all(f.open()):
            docs.append((f.name, doc))
    return docs


def _load_spl_detections():
    out = []
    for f in sorted(SPL_DIR.glob("*.yml")):
        with f.open() as fh:
            out.append((f.name, yaml.safe_load(fh)))
    return out


def test_at_least_eight_spl_detections_exist():
    detections = _load_spl_detections()
    assert len(detections) >= 8, f"expected at least 8 SPL detections, found {len(detections)}"


def test_every_spl_detection_has_non_blank_known_false_positives():
    """The task brief requires known_false_positives on every detection,
    never blank, never the word 'none'. This is the field the research
    (security_content, the ADS framework) calls out as mandatory."""
    for fname, d in _load_spl_detections():
        kfp = d.get("known_false_positives")
        assert kfp is not None, f"{fname}: missing known_false_positives"
        assert kfp.strip(), f"{fname}: known_false_positives is blank"
        assert kfp.strip().lower() not in ("none", "n/a", "none known"), (
            f"{fname}: known_false_positives is a non-answer ('{kfp.strip()}')"
        )


def test_every_spl_detection_has_required_schema_fields():
    required = ["name", "id", "description", "search", "mitre_attack_id",
                "known_false_positives", "target_technique_id"]
    for fname, d in _load_spl_detections():
        for field in required:
            assert field in d, f"{fname}: missing required field '{field}'"


def test_every_spl_detection_search_ends_with_filter_macro():
    """Every detection's search must end with a `<name>_filter` macro
    reference, the site-allowlist mechanism security_content uses on all
    318 of its cloud detections (see research/cloud-detection-methodology.md)."""
    macro_pattern = re.compile(r"`\w+_filter`\s*$")
    for fname, d in _load_spl_detections():
        search = d["search"].strip()
        assert macro_pattern.search(search), (
            f"{fname}: search does not end with a `<name>_filter` macro reference"
        )


def test_every_spl_detection_mitre_id_matches_target_technique():
    for fname, d in _load_spl_detections():
        mids = d["mitre_attack_id"]
        assert d["target_technique_id"] in mids, (
            f"{fname}: target_technique_id {d['target_technique_id']!r} not in mitre_attack_id {mids!r}"
        )


def test_every_sigma_document_is_valid_yaml_with_required_fields():
    docs = _load_all_sigma_docs()
    assert len(docs) > 0
    for fname, doc in docs:
        assert "title" in doc, f"{fname}: a document is missing 'title'"
        assert "id" in doc or "correlation" in doc, (
            f"{fname}: a document has neither 'id' (base rule) nor 'correlation' (correlation rule)"
        )
        # A base detection rule (not a correlation document) must carry a
        # logsource and a detection block.
        if "correlation" not in doc:
            assert "logsource" in doc, f"{fname}: base rule missing logsource"
            assert "detection" in doc, f"{fname}: base rule missing detection"


def test_no_sigma_rule_uses_the_deprecated_pipe_count_syntax():
    """Regression test for the real bug caught during this build: an
    earlier draft of 4 detections used `condition: selection | count(...) by
    ... > N`, syntax pySigma 1.5.0's parser rejects outright
    ('The pipe syntax in Sigma conditions has been deprecated and replaced
    by Sigma correlations'). Proven able to fail: this exact assertion was
    run against the pre-fix files (git stash of the original single-document
    aggregation rules) and failed with a match on 4 files before the fix;
    see README.md for the literal error text pySigma raised."""
    for f in sorted(SIGMA_DIR.glob("*.yml")):
        text = f.read_text()
        for doc in yaml.safe_load_all(text):
            if doc is None or "correlation" in doc:
                continue
            condition = doc.get("detection", {}).get("condition", "")
            assert "|" not in condition, (
                f"{f.name}: condition {condition!r} uses deprecated pipe syntax"
            )


def test_every_correlation_rule_references_an_existing_base_rule_name():
    docs = _load_all_sigma_docs()
    base_names = {doc.get("name") for _, doc in docs if "correlation" not in doc and doc.get("name")}
    for fname, doc in docs:
        if "correlation" not in doc:
            continue
        referenced = doc["correlation"]["rules"]
        for r in referenced:
            assert r in base_names, (
                f"{fname}: correlation rule references base rule '{r}' which does not exist"
            )
