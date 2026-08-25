import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import stix2

from emit_stix import build_bundle, validate_bundle


def _tiny_filtered():
    return {
        "ips": {"kept": ["1.2.3.4"], "dropped": []},
        "dns": {"kept": ["evil.example.net"], "dropped": []},
        "sha256_kept": ["A" * 64],
    }


def test_bundle_has_correct_object_count():
    bundle = build_bundle(_tiny_filtered())
    # 1 identity + 3 indicators (1 ip + 1 dns + 1 sha256)
    assert len(bundle.objects) == 4


def test_indicator_pattern_syntax_ipv4():
    bundle = build_bundle(_tiny_filtered())
    ip_indicators = [
        o for o in bundle.objects
        if o["type"] == "indicator" and "ipv4-addr" in o["pattern"]
    ]
    assert len(ip_indicators) == 1
    assert ip_indicators[0]["pattern"] == "[ipv4-addr:value = '1.2.3.4']"


def test_indicator_pattern_syntax_sha256():
    bundle = build_bundle(_tiny_filtered())
    hash_indicators = [
        o for o in bundle.objects
        if o["type"] == "indicator" and "SHA-256" in o["pattern"]
    ]
    assert len(hash_indicators) == 1
    assert "file:hashes.'SHA-256'" in hash_indicators[0]["pattern"]


def test_all_objects_are_spec_version_21():
    bundle = build_bundle(_tiny_filtered())
    for obj in bundle.objects:
        assert obj["spec_version"] == "2.1"


def test_bundle_validates_via_reparse():
    bundle = build_bundle(_tiny_filtered())
    result = validate_bundle(bundle)
    assert result["valid"] is True
    assert result["total_objects"] == 4
    assert result["indicator_objects"] == 3
    assert result["spec_versions_seen"] == ["2.1"]


def test_malformed_pattern_is_rejected_by_stix2_library():
    """Proves the library actually validates: a syntactically invalid
    STIX pattern (missing closing bracket) must raise, not silently
    produce an Indicator.
    """
    raised = False
    try:
        stix2.Indicator(
            pattern="[ipv4-addr:value = '1.2.3.4'",  # missing closing bracket
            pattern_type="stix",
            spec_version="2.1",
        )
    except Exception:
        raised = True
    assert raised, "stix2 library should reject a malformed pattern"
