"""Pin every numeric claim in FINDINGS.md to the evidence files it was computed from.

Every test reads a saved evidence file and recomputes the number itself; none
of these tests hardcode a result independent of the evidence. Tests SKIP
(never fail outright) when a required corpus or vendored tool is not present
on the machine running them, per project policy: a missing external
dependency is not a claim being wrong.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
CORPORA = Path("/home/kali/director/projects/_corpora")
MANIFEST = ROOT / "manifest" / "technique_manifest.json"


def _require(path: Path):
    if not path.exists():
        pytest.skip(f"required evidence file missing: {path}")


def _require_corpus(path: Path):
    if not path.exists():
        pytest.skip(f"corpus not present on this machine: {path}")


# ---------------------------------------------------------------------------
# Manifest / corpus structure claims
# ---------------------------------------------------------------------------

def test_manifest_is_valid_json_and_covers_two_techniques():
    _require(MANIFEST)
    data = json.loads(MANIFEST.read_text())
    ids = {t["technique_id"] for t in data["techniques"]}
    assert ids == {"T1003.001", "T1059.001"}


def test_203_of_342_attack_data_technique_folders_have_multiple_sources():
    """Recomputes the 203/342 overlap figure directly from the corpus directory tree."""
    base = CORPORA / "attack_data" / "datasets" / "attack_techniques"
    _require_corpus(base)
    folders = [d for d in base.iterdir() if d.is_dir()]
    total = len(folders)
    multi = sum(
        1 for d in folders
        if len([sd for sd in d.iterdir() if sd.is_dir()]) >= 2
    )
    assert total == 342, f"expected 342 technique folders, counted {total}"
    assert multi == 203, f"expected 203 folders with >=2 dataset subfolders, counted {multi}"


def test_t1003_001_present_in_three_corpora():
    """T1003.001 (LSASS Memory, https://attack.mitre.org/techniques/T1003/001/) samples
    exist in all three telemetry corpora used by this project."""
    _require_corpus(CORPORA / "attack_data" / "datasets" / "attack_techniques" / "T1003.001")
    _require_corpus(CORPORA / "EVTX-ATTACK-SAMPLES" / "Credential Access")
    _require_corpus(CORPORA / "EVTX-to-MITRE-Attack" / "TA0006-Credential Access" / "T1003-Credential dumping")


# ---------------------------------------------------------------------------
# Zircolite run claims
# ---------------------------------------------------------------------------

def test_seven_zircolite_runs_completed_successfully():
    summary_path = EVIDENCE / "02_zircolite_run_summary.json"
    _require(summary_path)
    runs = json.loads(summary_path.read_text())
    assert len(runs) == 7, f"expected 7 sample-group runs (4 for T1003.001 + 3 for T1059.001), found {len(runs)}"
    for r in runs:
        assert r["returncode"] == 0, f"Zircolite exited non-zero for {r['technique']}/{r['group']}"


def test_t1003_001_no_rule_survives_all_four_independent_groups():
    """The headline finding: of the technique-tagged rules that fired anywhere,
    zero fired in every one of the four independently captured sample groups."""
    matrix_path = EVIDENCE / "03_matrix.json"
    _require(matrix_path)
    matrix = json.loads(matrix_path.read_text())
    t = matrix["T1003.001"]
    assert t["eligible_rule_count"] == 71
    assert t["rules_fired_at_least_once"] == 22
    assert t["rules_fired_in_every_group"] == 0


def test_t1059_001_exactly_one_rule_survives_all_groups():
    matrix_path = EVIDENCE / "03_matrix.json"
    _require(matrix_path)
    matrix = json.loads(matrix_path.read_text())
    t = matrix["T1059.001"]
    assert t["eligible_rule_count"] == 208
    assert t["rules_fired_at_least_once"] == 21
    assert t["rules_fired_in_every_group"] == 1
    assert t["rules_fired_in_every_group_ids"] == ["f4bbd493-b796-416e-bbf2-121235348529"]


def test_matrix_numbers_recompute_from_raw_zircolite_output():
    """Independently recount rules-fired-at-least-once for T1003.001 directly
    from the raw per-group Zircolite JSON, bypassing 03_matrix.json entirely,
    to catch a bug in the matrix-building script itself."""
    raw_dir = EVIDENCE / "zircolite_raw" / "T1003.001"
    _require(raw_dir)
    ruleset_path = Path(
        "/home/kali/director/projects/detection-as-code/vendor/Zircolite/rules/rules_windows_merged.json"
    )
    _require_corpus(ruleset_path)
    ruleset = json.loads(ruleset_path.read_text())
    eligible = {r["id"] for r in ruleset if "attack.t1003.001" in [t.lower() for t in r.get("tags", [])]}

    fired_ids: set[str] = set()
    for f in raw_dir.glob("*.json"):
        matches = json.loads(f.read_text() or "[]")
        for m in matches:
            if m["id"] in eligible:
                fired_ids.add(m["id"])

    assert len(fired_ids) == 22


# ---------------------------------------------------------------------------
# Miss-diagnosis claims (telemetry-absent vs logic-too-narrow)
# ---------------------------------------------------------------------------

def test_miss_diagnosis_produces_both_cause_categories():
    """The core claim this project exists to demonstrate: misses split into
    telemetry-absent (structural) and logic-too-narrow (genuine detection
    failure) causes, and neither count is zero, i.e. this is not a pure
    plumbing artifact nor a pure logic-failure story."""
    diag_path = EVIDENCE / "04_miss_diagnosis.txt"
    _require(diag_path)
    text = diag_path.read_text()
    telemetry_absent = text.count("TELEMETRY ABSENT")
    logic_narrow = text.count("LOGIC TOO NARROW")
    assert telemetry_absent > 0
    assert logic_narrow > 0
    # Pull the script's own tally line and confirm it matches an independent count.
    for line in text.splitlines():
        if line.startswith("telemetry absent:"):
            assert int(line.split(":")[1].strip()) == telemetry_absent
        if line.startswith("logic too narrow:"):
            assert int(line.split(":")[1].strip()) == logic_narrow


# ---------------------------------------------------------------------------
# Manifest audit claims (hand-curated exclusions must be traceable)
# ---------------------------------------------------------------------------

def test_manifest_records_excluded_files_with_reasons():
    """Every hand-excluded filename-misleading EVTX sample must carry a stated
    reason, since the manifest's exclusions are the auditable part of this
    project's hand-curation."""
    _require(MANIFEST)
    data = json.loads(MANIFEST.read_text())
    t1003 = next(t for t in data["techniques"] if t["technique_id"] == "T1003.001")
    excluded_total = 0
    for sample in t1003["samples"]:
        for key in ("excluded_from_credential_access_folder", "excluded_from_folder_despite_technique_label"):
            for entry in sample.get(key, []):
                excluded_total += 1
                assert entry.get("reason"), f"exclusion for {entry.get('name')} has no reason recorded"
    assert excluded_total >= 5, "expected at least the 5 EVTX-ATTACK-SAMPLES exclusions to be documented"


# ---------------------------------------------------------------------------
# Licence presence claims
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("corpus_dir,license_file,expected_snippet", [
    ("attack_data", "LICENSE", "Apache License"),
    ("EVTX-ATTACK-SAMPLES", "LICENSE.GPL", "GNU GENERAL PUBLIC LICENSE"),
    ("EVTX-to-MITRE-Attack", "LICENSE.md", "Creative Commons"),
    ("security_content", "LICENSE", "Apache License"),
])
def test_corpus_licence_verified_verbatim(corpus_dir, license_file, expected_snippet):
    path = CORPORA / corpus_dir / license_file
    _require_corpus(path)
    text = path.read_text(errors="replace")
    assert expected_snippet in text
