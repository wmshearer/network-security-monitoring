"""
Verify the ground-truth claims this project's README and FINDINGS rest on,
directly against the security_content and attack_data corpora.

Every test SKIPs (not fails) if the corpus it needs is absent, so this suite
is safe to run in an environment that has not cloned security_content or
attack_data.
"""
import csv
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SECURITY_CONTENT = Path("/home/kali/director/projects/_corpora/security_content")
ATTACK_DATA = Path("/home/kali/director/projects/_corpora/attack_data")

pytestmark = pytest.mark.skipif(
    not SECURITY_CONTENT.exists(),
    reason="security_content corpus not present at expected path",
)


def read(relpath):
    p = SECURITY_CONTENT / relpath
    if not p.exists():
        pytest.skip(f"{relpath} not found in security_content")
    return p.read_text(errors="replace")


def test_sunburst_is_experimental_and_hardcodes_incident_indicators():
    text = read("detections/endpoint/sunburst_correlation_dll_and_network_event.yml")
    assert re.search(r"^status:\s*experimental\s*$", text, re.MULTILINE)
    assert "SolarWinds.Orion.Core.BusinessLayer.dll" in text
    assert "avsvmcloud.com" in text


def test_sunburst_is_tagged_t1203_not_t1195():
    text = read("detections/endpoint/sunburst_correlation_dll_and_network_event.yml")
    m = re.search(r"^mitre_attack_id:\n((?:\s+-\s+\S+\n?)+)", text, re.MULTILINE)
    assert m, "mitre_attack_id block not found"
    ids = re.findall(r"-\s+(\S+)", m.group(1))
    assert ids == ["T1203"]
    assert not any(i.startswith("T1195") for i in ids)


def test_shai_hulud_workflow_detection_is_production_and_hardcodes_filenames():
    text = read("detections/endpoint/shai_hulud_workflow_file_creation_or_modification.yml")
    assert re.search(r"^status:\s*production\s*$", text, re.MULTILINE)
    assert "shai-hulud-workflow.yaml" in text or "shai-hulud-workflow.yml" in text
    assert "discussion.yaml" in text


def test_python_network_traffic_detection_is_behavioral_not_incident_named():
    text = read("detections/endpoint/python_network_traffic_during_package_build.yml")
    assert re.search(r"^status:\s*production\s*$", text, re.MULTILINE)
    assert "build_wheel" in text
    # No specific incident name, C2 domain, or malicious package name hardcoded.
    for banned in ("SolarWinds", "avsvmcloud", "shai-hulud", "3CXDesktopApp"):
        assert banned not in text


def test_all_t1195_tagged_detections_are_production():
    detections_dir = SECURITY_CONTENT / "detections"
    if not detections_dir.exists():
        pytest.skip("detections/ not found")
    non_production = []
    count = 0
    for path in sorted(detections_dir.rglob("*.yml")):
        text = path.read_text(errors="replace")
        if not re.search(r"^\s*-\s+T1195(\.\d+)?\s*$", text, re.MULTILINE):
            continue
        count += 1
        status_m = re.search(r"^status:\s*(\S+)\s*$", text, re.MULTILINE)
        status = status_m.group(1) if status_m else None
        if status != "production":
            non_production.append((str(path.relative_to(SECURITY_CONTENT)), status))
    assert count == 28, f"expected 28 T1195-tagged detections, found {count}"
    assert non_production == [], f"non-production T1195 detections found: {non_production}"


def test_xz_utils_has_zero_detections():
    detections_dir = SECURITY_CONTENT / "detections"
    if not detections_dir.exists():
        pytest.skip("detections/ not found")
    pattern = re.compile(r"xz-utils|liblzma|xz_utils|CVE-2024-3094", re.IGNORECASE)
    hits = []
    for path in detections_dir.rglob("*.yml"):
        if pattern.search(path.read_text(errors="replace")):
            hits.append(str(path))
    assert hits == []


def test_codecov_has_zero_detections():
    detections_dir = SECURITY_CONTENT / "detections"
    if not detections_dir.exists():
        pytest.skip("detections/ not found")
    hits = []
    for path in detections_dir.rglob("*.yml"):
        if "codecov" in path.read_text(errors="replace").lower():
            hits.append(str(path))
    assert hits == []


def test_security_content_license_is_apache2():
    p = SECURITY_CONTENT / "LICENSE"
    if not p.exists():
        pytest.skip("LICENSE not found")
    head = p.read_text(errors="replace")[:200]
    assert "Apache License" in head
    assert "Version 2.0" in head


@pytest.mark.skipif(not ATTACK_DATA.exists(), reason="attack_data corpus not present")
def test_attack_data_license_is_apache2():
    p = ATTACK_DATA / "LICENSE"
    if not p.exists():
        pytest.skip("LICENSE not found")
    head = p.read_text(errors="replace")[:200]
    assert "Apache License" in head
    assert "Version 2.0" in head


@pytest.mark.skipif(not ATTACK_DATA.exists(), reason="attack_data corpus not present")
def test_npm_and_3cx_telemetry_datasets_exist():
    npm_log = ATTACK_DATA / "datasets/attack_techniques/T1195.001/npm/shai_hulud_workflow_sysmon.log"
    cx3_log = ATTACK_DATA / "datasets/attack_techniques/T1195.002/3CX/3cx_windows-sysmon.log"
    assert npm_log.exists()
    assert cx3_log.exists()
    assert npm_log.stat().st_size > 0
    assert cx3_log.stat().st_size > 0
