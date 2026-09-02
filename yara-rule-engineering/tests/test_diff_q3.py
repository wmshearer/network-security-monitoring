"""
Pins the Q3 runtime-agreement numbers: near-total agreement between
yara-python and yara-x on files both engines compile, plus the one real
timeout disagreement and the two Big_Numbers1 disagreements.
"""


def test_overall_agreement_is_near_total(diff_results):
    total_agree = 0
    total_disagree = 0
    for ruleset_result in diff_results.values():
        for corpus_result in ruleset_result["corpora"].values():
            total_agree += corpus_result["agree"]
            total_disagree += corpus_result["disagree"]
    assert total_agree == 14869
    assert total_disagree == 2
    # error-only disagreements (e.g. a yara-python timeout) are tracked
    # separately, so agree+disagree does not have to equal every sampled file.
    agreement_rate = total_agree / (total_agree + total_disagree)
    assert agreement_rate > 0.999


def test_libqt_disagreement_is_big_numbers1(diff_results):
    c = diff_results["yara-rules-official-index"]["corpora"]["usr_lib_x86_64"]
    assert c["disagree"] == 2
    paths_with_big_numbers1 = [
        d["path"] for d in c["disagreements"] if "yara_python_only" in d and "ns2:Big_Numbers1" in d["yara_python_only"]
    ]
    assert any("libQt5Core" in p for p in paths_with_big_numbers1)
    assert any("libQt6Core" in p for p in paths_with_big_numbers1)


def test_iotgoat_fat32_partition_yara_python_timeout(diff_results):
    """yara-python's 5s per-file timeout was exceeded on a 20MB FAT32
    partition image; yara-x completed the same scan and found 17 matches
    within its own 5s timeout on the SAME rules and SAME file."""
    c = diff_results["yara-rules-official-index"]["corpora"]["iotgoat_firmware"]
    timeout_entries = [d for d in c["disagreements"] if d.get("reason") == "scan_error"]
    assert len(timeout_entries) == 1
    entry = timeout_entries[0]
    assert "FAT32_partition" in entry["path"]
    assert entry["yara_python"] == {"error": "scanning timed out"}
    assert len(entry["yara_x"]) == 17


def test_reversinglabs_and_protections_artifacts_perfect_agreement(diff_results):
    for ruleset_name in ("reversinglabs", "protections-artifacts"):
        for corpus_result in diff_results[ruleset_name]["corpora"].values():
            assert corpus_result["disagree"] == 0


def test_yara_x_faster_on_yara_rules_official_index(diff_results):
    c = diff_results["yara-rules-official-index"]["corpora"]["usr_bin"]
    py_s = c["scan_seconds"]["yara_python"]
    x_s = c["scan_seconds"]["yara_x"]
    assert py_s > 5 * x_s, f"expected yara-x to be at least 5x faster, got py={py_s}s x={x_s}s"
