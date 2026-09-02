"""Pins every specific, named claim this project makes in README.md and
FINDINGS.md to a re-derivable check against the actual evidence files, so a
future change to the manifest, corpus, or scripts cannot silently invalidate
a published claim without a test failing.

SKIP (not FAIL) when the source corpora are absent on this machine.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORPUS_ROOT = Path("/home/kali/director/projects/_corpora/attack_data/datasets/malware")
SECURITY_CONTENT_ROOT = Path("/home/kali/director/projects/_corpora/security_content")

CORPUS_AVAILABLE = CORPUS_ROOT.is_dir()
SECURITY_CONTENT_AVAILABLE = SECURITY_CONTENT_ROOT.is_dir()

skip_if_no_corpus = pytest.mark.skipif(not CORPUS_AVAILABLE, reason=f"corpus not found at {CORPUS_ROOT}")
skip_if_no_security_content = pytest.mark.skipif(not SECURITY_CONTENT_AVAILABLE, reason=f"security_content not found at {SECURITY_CONTENT_ROOT}")


@skip_if_no_corpus
def test_t1490_anchor_finding_file_counts():
    """The director-verified anchor finding: grep -rliE 'vssadmin|wbadmin|bcdedit|shadowcopy'
    over each family's raw corpus directory yields these exact per-family file
    counts. This is the single most load-bearing number in the project and is
    re-derived here directly from grep, independent of any of this project's
    own scripts, so a bug in scripts/01 could never make this test pass by
    accident."""
    expected = {
        "conti": 0,
        "ryuk": 0,
        "lockbit_ransomware": 0,
        "revil": 1,
        "prestige_ransomware": 1,
        "chaos_ransomware": 2,
        "ransomware_ttp": 5,
    }
    for family, expected_count in expected.items():
        proc = subprocess.run(
            ["grep", "-rliE", "vssadmin|wbadmin|bcdedit|shadowcopy", family],
            cwd=CORPUS_ROOT, capture_output=True, text=True,
        )
        actual_count = len(proc.stdout.splitlines())
        assert actual_count == expected_count, (
            f"family={family}: expected {expected_count} files with T1490 evidence, got {actual_count}"
        )


@skip_if_no_security_content
def test_conti_has_no_dedicated_analytic_story():
    """Verifies the 'conti has no dedicated Splunk analytic_story' finding by
    grepping every story file's `name:` field directly, independent of the
    detection index script."""
    stories_dir = SECURITY_CONTENT_ROOT / "stories"
    conti_stories = [
        f for f in stories_dir.glob("*.yml")
        if "conti" in (f.read_text().splitlines()[0] if f.read_text() else "").lower()
    ]
    # Direct, narrow check: no story YAML's name: field contains "conti"
    matching_names = []
    for f in stories_dir.glob("*.yml"):
        for line in f.read_text().splitlines():
            if line.startswith("name:") and "conti" in line.lower():
                matching_names.append((f.name, line))
    assert matching_names == [], f"expected no analytic_story named 'Conti...', found: {matching_names}"


@skip_if_no_security_content
def test_t1562_003_has_zero_detections_in_security_content():
    """Verifies the specific claim that Splunk ships zero detections tagged
    to T1562.003 (Impair Command History Logging), which is why that row is
    RED-TELEMETRY/GREY for every family by construction."""
    endpoint_dir = SECURITY_CONTENT_ROOT / "detections" / "endpoint"
    proc = subprocess.run(["grep", "-rl", "T1562.003", "."], cwd=endpoint_dir, capture_output=True, text=True)
    matches = [l for l in proc.stdout.splitlines() if l]
    assert matches == [], f"expected zero detections tagged T1562.003, found: {matches}"


@skip_if_no_security_content
def test_deprecated_mitre_map_never_included_a_ransomware_family():
    """Verifies the 'Splunk built this exact artifact shape for Trickbot/Qakbot/
    AgentTesla but never for a ransomware family' claim."""
    mitre_map_dir = SECURITY_CONTENT_ROOT / "deprecated" / "mitre-map"
    assert mitre_map_dir.is_dir(), "deprecated/mitre-map directory not found; claim cannot be checked"
    all_coverage_files = list(mitre_map_dir.rglob("*_sec_content_mitre_coverage.json"))
    assert len(all_coverage_files) > 0, "expected at least one coverage file under deprecated/mitre-map"
    ransomware_family_names = {
        "conti", "ryuk", "revil", "lockbit", "prestige", "chaos", "ransomware",
        "blackbasta", "blacksuit", "clop", "medusa", "darkside",
    }
    for f in all_coverage_files:
        stem_lower = f.stem.lower()
        assert not any(name in stem_lower for name in ransomware_family_names), (
            f"found a ransomware-family-named coverage file in deprecated/mitre-map: {f}; "
            f"the 'never included ransomware' claim is false"
        )


@skip_if_no_corpus
def test_matrix_cell_counts_match_readme_headline():
    """Pins the exact headline numbers reported in README.md so a silent
    manifest or script change cannot drift the published claim without this
    test catching it. If this fails, update BOTH the code/manifest AND
    README.md/FINDINGS.md together, never just this test."""
    matrix_path = ROOT / "matrix" / "coverage_matrix.json"
    assert matrix_path.exists(), "matrix/coverage_matrix.json not built; run scripts/04_build_matrix.py first"
    matrix = json.loads(matrix_path.read_text())
    assert matrix["state_counts"] == {"GREEN": 13, "RED-LOGIC": 0, "RED-TELEMETRY": 5, "GREY": 52}
    assert matrix["total_cells"] == 70


@skip_if_no_corpus
def test_falsifiable_claim_failed_red_logic_is_zero():
    """The project's original stated claim (Splunk's ransomware detection
    content does not uniformly cover the same core technique set across
    families) required at least one real RED-LOGIC cell. A live test against
    Splunk Enterprise 10.4.2 (evidence/07_spl_backslash_resolved.txt)
    resolved the open interpretive question in FINDINGS.md section 6 and
    flipped the two candidate RED-LOGIC cells to GREEN. The claim FAILED:
    RED-LOGIC is zero. This pins that result so the corrected,
    capture-completeness conclusion cannot silently regress."""
    matrix = json.loads((ROOT / "matrix" / "coverage_matrix.json").read_text())
    assert matrix["state_counts"]["RED-LOGIC"] == 0, (
        "RED-LOGIC is non-zero: the corrected conclusion (capture-completeness story, "
        "original detection-gap claim failed) no longer holds and README/FINDINGS must "
        "be revisited"
    )
