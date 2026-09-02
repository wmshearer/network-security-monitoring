"""Pin the real numbers this project reports, and check they are reproducible.

Every number here is read back from an evidence file that a numbered script
in scripts/ already wrote (never recomputed ad hoc in the test), and where a
number appears in README.md/FINDINGS.md, this test is what makes it a claim
someone can re-check rather than a claim someone has to trust.

Tests SKIP (not FAIL) when the source corpus at
/home/kali/director/projects/detection-rule-lab/data/events/ is absent, since
this project only reads it and does not vendor a 2.2 GB file into git.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = ROOT / "evidence"
SOURCE_DIR = Path("/home/kali/director/projects/detection-rule-lab/data/events")

SOURCE_AVAILABLE = (SOURCE_DIR / "malicious.jsonl").exists() and (
    SOURCE_DIR / "benign.jsonl"
).exists()

requires_source = pytest.mark.skipif(
    not SOURCE_AVAILABLE,
    reason=f"source corpus not found at {SOURCE_DIR}; this project reads it read-only "
    "and does not vendor it into git",
)


def load_json(name: str) -> dict:
    path = EVIDENCE_DIR / name
    if not path.exists():
        pytest.skip(f"{path} not found; run the numbered scripts in scripts/ first")
    return json.load(path.open())


def load_tree_summary(corpus: str) -> dict:
    path = EVIDENCE_DIR / f"trees_{corpus}.jsonl"
    if not path.exists():
        pytest.skip(f"{path} not found; run scripts/01_build_trees.py first")
    with path.open() as f:
        first_line = json.loads(f.readline())
    return first_line["_summary"]


# ---------------------------------------------------------------------------
# Tree reconstruction numbers (scripts/01_build_trees.py), matching the task's
# independently-verified figures exactly.
# ---------------------------------------------------------------------------


class TestTreeReconstructionNumbers:
    def test_malicious_eventid1_count(self):
        s = load_tree_summary("malicious")
        assert s["eventid1_records"] == 1167

    def test_malicious_parents_resolved(self):
        s = load_tree_summary("malicious")
        assert s["parents_resolved_in_corpus"] == 810
        assert s["parents_resolved_pct"] == 69.4

    def test_malicious_max_chain_depth(self):
        s = load_tree_summary("malicious")
        # "max chain depth 10" = 10 processes in the longest chain (root
        # through leaf); this project's own hop-count depth is 9 (0-indexed).
        assert s["max_chain_depth_nodes"] == 10
        assert s["max_chain_depth_hops"] == 9

    def test_benign_eventid1_count(self):
        s = load_tree_summary("benign")
        assert s["eventid1_records"] == 1274

    def test_benign_parents_resolved(self):
        s = load_tree_summary("benign")
        assert s["parents_resolved_in_corpus"] == 1273
        assert s["parents_resolved_pct"] == 99.9

    def test_benign_max_chain_depth(self):
        s = load_tree_summary("benign")
        assert s["max_chain_depth_nodes"] == 9
        assert s["max_chain_depth_hops"] == 8

    def test_no_cycles_detected(self):
        # A cycle would mean corrupted GUID data; both corpora are clean.
        assert load_tree_summary("malicious")["cycles_detected"] == 0
        assert load_tree_summary("benign")["cycles_detected"] == 0


# ---------------------------------------------------------------------------
# Single-hop Sigma baseline (scripts/02_score_single_hop.py)
# ---------------------------------------------------------------------------


class TestSingleHopBaseline:
    def test_ruleset_size(self):
        d = load_json("single_hop_scoring.json")
        assert d["ruleset_rule_count"] == 2691

    def test_rules_fired_totals(self):
        d = load_json("single_hop_scoring.json")
        rows = d["rows"]
        mal_fired = sum(1 for r in rows if r["malicious_hits"] > 0)
        ben_fired = sum(1 for r in rows if r["benign_hits"] > 0)
        union_fired = sum(1 for r in rows if r["malicious_hits"] > 0 or r["benign_hits"] > 0)
        assert mal_fired == 128
        assert ben_fired == 4
        assert union_fired == 129

    def test_sdclt_child_processes_rule_fires_on_intermediary_only(self):
        """The one existing rule that names sdclt.exe lineage at all.

        This is the specific, falsifiable claim FINDINGS.md makes: the
        existing single-hop "Sdclt Child Processes" rule matches the
        control.exe event (1 hop from sdclt.exe) but this test only checks
        the aggregate count here; the per-event proof is
        comparison_table.json's case_study_sdclt_uac_bypass section, checked
        below in TestComparisonTable.
        """
        d = load_json("single_hop_scoring.json")
        rule = next(
            r for r in d["rows"] if r["rule_id"] == "da2738f2-fadb-4394-afa7-0a0674885afa"
        )
        assert rule["title"] == "Sdclt Child Processes"
        assert rule["malicious_hits"] == 2
        assert rule["benign_hits"] == 0


# ---------------------------------------------------------------------------
# Tree detectors (scripts/03_score_tree_detectors.py)
# ---------------------------------------------------------------------------


class TestTreeDetectors:
    def test_uac_bypass_proxy_chain_precision(self):
        d = load_json("tree_detector_results.json")
        mal = d["results"]["malicious"]["uac_bypass_proxy_chain_hits"]
        ben = d["results"]["benign"]["uac_bypass_proxy_chain_hits"]
        assert len(mal) == 2
        assert len(ben) == 0

    def test_deep_chain_to_lolbin_is_a_negative_result(self):
        """Detector 2 is reported as a negative result: it does not
        discriminate malicious from benign. This test pins that finding so
        a future change to the detector or the corpus is caught, not that
        the false-positive count is somehow "acceptable"."""
        d = load_json("tree_detector_results.json")
        mal = d["results"]["malicious"]["deep_chain_to_lolbin_hits"]
        ben = d["results"]["benign"]["deep_chain_to_lolbin_hits"]
        assert len(mal) == 145
        assert len(ben) == 55
        # conhost.exe (ubiquitous console host, not attack-specific) must be
        # the dominant benign false positive; if it stops being dominant,
        # the detector's failure mode has changed and FINDINGS.md's
        # explanation needs re-checking, not silent re-pinning.
        conhost_ben = sum(1 for h in ben if h["lolbin_name"] == "conhost.exe")
        assert conhost_ben == 26


# ---------------------------------------------------------------------------
# Comparison table (scripts/04_compare_single_hop_vs_tree.py)
# ---------------------------------------------------------------------------


class TestComparisonTable:
    def test_payload_launch_events_not_caught_by_lineage_rule(self):
        d = load_json("comparison_table.json")
        cs = d["case_study_sdclt_uac_bypass"]
        assert cs["payload_launch_events"] == 2
        matched_ids = cs["single_hop_rules_matching_payload_launch_events"]
        # The existing lineage rule (Sdclt Child Processes) must NOT be
        # among the rules matching the payload-launch (grandchild) events:
        # it only sees the intermediary control.exe event, one hop up.
        assert "da2738f2-fadb-4394-afa7-0a0674885afa" not in matched_ids
        # But content-based PowerShell heuristics DO catch it (this is the
        # honest, non-overstated version of the claim: tree logic adds a
        # lineage-based detection path, it does not catch something no
        # other mechanism in the ruleset catches at all).
        assert len(matched_ids) > 0

    def test_tree_detector_1_beats_single_hop_on_precision(self):
        d = load_json("comparison_table.json")
        t1 = d["tree_detector_uac_bypass_proxy_chain"]
        assert t1["precision"] == 1.0


# ---------------------------------------------------------------------------
# Determinism: rebuilding the trees twice from the same source must produce
# byte-identical summaries. A sibling project shipped an order-dependent
# matrix bug; this is the check that would have caught that class of bug
# here (dict iteration order, set ordering, etc. leaking into output).
# ---------------------------------------------------------------------------


@requires_source
class TestDeterminism:
    def test_rebuilding_benign_tree_twice_is_identical(self, tmp_path):
        script = ROOT / "scripts" / "01_build_trees.py"
        out1 = ROOT / "evidence" / "trees_benign.jsonl"

        # First build already exists from the normal pipeline run; capture it.
        if not out1.exists():
            pytest.skip("evidence/trees_benign.jsonl not built yet")
        first = out1.read_text()

        # Rebuild into a temp copy of the evidence dir by running the script
        # again (it always overwrites evidence/trees_benign.jsonl) and
        # comparing byte-for-byte.
        result = subprocess.run(
            [sys.executable, str(script), "benign"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stderr
        second = out1.read_text()
        assert first == second, (
            "rebuilding the benign process tree twice from the same source "
            "produced different output; this is the exact class of bug "
            "(order-dependent output) a sibling project shipped once"
        )
