"""Tests for the ranking module (scripts/01_rank_by_noise.py).

Per the project brief, these SKIP (never FAIL) when the source project
detection-rule-lab, or its scoring-run.json, is not present on disk. That
lets this test suite run in an environment where the source projects have
not been checked out, without reporting a false failure.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from common import SCORING_RUN_JSON, load_scoring_run  # noqa: E402

pytestmark = pytest.mark.skipif(
    not SCORING_RUN_JSON.exists(),
    reason=f"source project file not found: {SCORING_RUN_JSON} (detection-rule-lab absent)",
)


def _load_ranking_module():
    spec = importlib.util.spec_from_file_location("rank_by_noise", SCRIPTS_DIR / "01_rank_by_noise.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_exactly_four_rules_touch_benign():
    scoring_run = load_scoring_run()
    from common import rules_touching_benign

    touching = rules_touching_benign(scoring_run)
    assert len(touching) == 4


def test_total_benign_hits_is_62():
    scoring_run = load_scoring_run()
    from common import rules_touching_benign

    touching = rules_touching_benign(scoring_run)
    assert sum(r["benign_hits"] for r in touching) == 62


def test_anchor_rule_is_modification_of_ie_registry_settings():
    scoring_run = load_scoring_run()
    from common import rules_touching_benign

    touching = rules_touching_benign(scoring_run)
    anchor = max(touching, key=lambda r: r["benign_hits"])
    assert anchor["title"] == "Modification of IE Registry Settings"
    assert anchor["malicious_hits"] == 0
    assert anchor["benign_hits"] == 56
    assert anchor["precision"] == 0.0


def test_anchor_rule_is_90_percent_of_total_benign_hits():
    scoring_run = load_scoring_run()
    from common import rules_touching_benign

    touching = rules_touching_benign(scoring_run)
    total = sum(r["benign_hits"] for r in touching)
    anchor_hits = max(r["benign_hits"] for r in touching)
    pct = anchor_hits / total * 100
    assert 89.0 < pct < 91.0


def test_ranking_places_anchor_first():
    mod = _load_ranking_module()
    scoring_run = load_scoring_run()
    ranked = mod.build_ranking(scoring_run)
    assert ranked[0]["title"] == "Modification of IE Registry Settings"
    assert ranked[0]["ratio_is_undefined_infinite"] is True


def test_ranking_covers_all_four_touching_rules():
    mod = _load_ranking_module()
    scoring_run = load_scoring_run()
    ranked = mod.build_ranking(scoring_run)
    assert len(ranked) == 4
    titles = {r["title"] for r in ranked}
    assert titles == {
        "Modification of IE Registry Settings",
        "Suspicious High IntegrityLevel Conhost Legacy Option",
        "Disable Windows Defender Functionalities Via Registry Keys",
        "RunMRU Registry Key Deletion - Registry",
    }


def test_precision_matches_source_json_exactly():
    """Recompute precision from raw hits and compare to the source file's own
    precision field, to catch any drift between the two."""
    scoring_run = load_scoring_run()
    from common import rules_touching_benign

    for r in rules_touching_benign(scoring_run):
        mal, ben = r["malicious_hits"], r["benign_hits"]
        expected = mal / (mal + ben) if (mal + ben) else 0.0
        assert abs(r["precision"] - expected) < 1e-9
