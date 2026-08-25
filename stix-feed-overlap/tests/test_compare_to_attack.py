import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from compare_to_attack import ATTACK_BUNDLE_PATH, load_attack_indicator_count


def test_attack_bundle_exists_on_disk():
    assert ATTACK_BUNDLE_PATH.exists(), (
        f"expected the ATT&CK bundle at {ATTACK_BUNDLE_PATH}; this project "
        "reads it read-only, it must already exist from cloud-detection-coverage"
    )


def test_attack_bundle_has_zero_indicator_objects():
    """This is the load-bearing fact that makes the ATT&CK fallback
    comparison a weaker, different kind of comparison than the CIRCL
    overlap measurement: ATT&CK publishes no raw IOCs to match against.
    If MITRE ever adds STIX indicator objects to this bundle, this test
    should fail so the fallback comparison's caveat gets revisited.
    """
    result = load_attack_indicator_count()
    assert result["indicator_objects"] == 0


def test_attack_bundle_object_count_is_over_20000():
    result = load_attack_indicator_count()
    assert result["total_objects"] > 20000
