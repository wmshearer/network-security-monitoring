"""
Pins the Q1 false-positive numbers: match counts per ruleset per corpus, and
the specific rules identified in the manual inspection.
"""


def test_yara_rules_naive_near_universal_false_positive_rate(scan_results):
    c = scan_results["yara-rules"]["corpora"]
    assert c["usr_bin"]["files_matched"] == 395
    assert c["usr_bin"]["files_scanned"] == 400
    assert c["usr_lib_x86_64"]["files_matched"] == 398
    assert c["openwrt_firmware"]["files_matched"] == 2159
    assert c["openwrt_firmware"]["files_scanned"] == 2181
    assert c["iotgoat_firmware"]["files_matched"] == 1001
    assert c["iotgoat_firmware"]["files_scanned"] == 1012


def test_yara_rules_official_index_much_lower_rate(scan_results):
    """Excluding utils/ and mobile_malware/ (the maintainers' own index.yar
    scope) drops the match rate by roughly an order of magnitude."""
    c = scan_results["yara-rules-official-index"]["corpora"]
    assert c["usr_bin"]["files_matched"] == 45
    assert c["usr_bin"]["files_scanned"] == 400
    assert c["usr_lib_x86_64"]["files_matched"] == 76
    assert c["openwrt_firmware"]["files_matched"] == 183
    assert c["iotgoat_firmware"]["files_matched"] == 69


def test_domain_url_ip_base64_are_the_naive_run_top_rules(scan_results):
    r = scan_results["yara-rules"]["corpora"]["usr_bin"]["matches_by_rule"]
    domain = [v for k, v in r.items() if k.endswith(":domain")]
    base64 = [v for k, v in r.items() if k.endswith(":contains_base64")]
    assert domain and domain[0]["file_count"] == 395
    assert base64 and base64[0]["file_count"] == 386


def test_big_numbers1_and_ldpreload_fire_in_official_index_run(scan_results):
    r = scan_results["yara-rules-official-index"]["corpora"]["openwrt_firmware"]["matches_by_rule"]
    big_numbers1 = [v for k, v in r.items() if k.endswith(":Big_Numbers1")]
    assert big_numbers1 and big_numbers1[0]["file_count"] == 135


def test_distfeeds_conf_is_the_big_numbers1_coincidence_example(scan_results):
    """The manual-inspection example: a benign OpenWrt package feed config
    file containing a 32-hex-char kernel ABI hash, matched by a rule whose
    whole detection surface is 'looks like a 32-char hex string'."""
    r = scan_results["yara-rules-official-index"]["corpora"]["openwrt_firmware"]["matches_by_rule"]
    big_numbers1 = next(v for k, v in r.items() if k.endswith(":Big_Numbers1"))
    assert any(f.endswith("etc/opkg/distfeeds.conf") for f in big_numbers1["files"])


def test_bash_matched_by_ldpreload(scan_results):
    r = scan_results["yara-rules-official-index"]["corpora"]["usr_bin"]["matches_by_rule"]
    ldpreload = next(v for k, v in r.items() if k.endswith(":ldpreload"))
    assert "/usr/bin/bash" in ldpreload["files"]


def test_signature_base_usr_bin_matches_are_real_kali_hacktools(scan_results):
    """The 3 signature-base matches on usr_bin are not false positives:
    they correctly identify Kali's own dsniff MITM toolkit."""
    r = scan_results["signature-base"]["corpora"]["usr_bin"]["matches_by_rule"]
    dsniff = next(v for k, v in r.items() if k.endswith(":HKTL_Dsniff"))
    assert set(dsniff["files"]) == {"/usr/bin/dsniff", "/usr/bin/sshmitm", "/usr/bin/webmitm"}


def test_protections_artifacts_usr_bin_matches_are_real_kali_hacktools(scan_results):
    """The 3 protections-artifacts matches on usr_bin correctly identify
    aircrack-ng, masscan (twice), and sliver-client (twice) -- all real
    offensive tools installed on this Kali machine."""
    r = scan_results["protections-artifacts"]["corpora"]["usr_bin"]["matches_by_rule"]
    all_files = set()
    for v in r.values():
        all_files.update(v["files"])
    assert all_files == {"/usr/bin/aircrack-ng", "/usr/bin/masscan", "/usr/bin/sliver-client"}
    masscan_rules = [k for k, v in r.items() if "/usr/bin/masscan" in v["files"]]
    sliver_rules = [k for k, v in r.items() if "/usr/bin/sliver-client" in v["files"]]
    assert len(masscan_rules) == 2
    assert len(sliver_rules) == 2


def test_reversinglabs_zero_matches_on_clean_corpus(scan_results):
    c = scan_results["reversinglabs"]["corpora"]
    for corpus_name in ("usr_bin", "usr_lib_x86_64", "openwrt_firmware", "iotgoat_firmware"):
        assert c[corpus_name]["files_matched"] == 0


def test_signature_base_and_protections_artifacts_near_zero(scan_results):
    assert scan_results["signature-base"]["corpora"]["usr_bin"]["files_matched"] == 3
    assert scan_results["protections-artifacts"]["corpora"]["usr_bin"]["files_matched"] == 3
    for ruleset in ("signature-base", "protections-artifacts"):
        for corpus_name in ("usr_lib_x86_64", "openwrt_firmware", "iotgoat_firmware"):
            assert scan_results[ruleset]["corpora"][corpus_name]["files_matched"] == 0


def test_usr_bin_and_usr_lib_capped_for_yara_rules_variants_only(scan_results):
    for rs in ("yara-rules", "yara-rules-official-index"):
        assert scan_results[rs]["corpora"]["usr_bin"]["capped_to"] == 400
        assert scan_results[rs]["corpora"]["usr_lib_x86_64"]["capped_to"] == 400
    for rs in ("reversinglabs", "signature-base", "protections-artifacts"):
        assert scan_results[rs]["corpora"]["usr_bin"]["capped_to"] is None
        assert scan_results[rs]["corpora"]["usr_bin"]["files_scanned"] == 3239
