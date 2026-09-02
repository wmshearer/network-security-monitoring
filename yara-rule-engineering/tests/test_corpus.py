"""Pins the clean-corpus file counts reported in README/FINDINGS."""


def test_usr_bin_file_count(corpus_manifest):
    c = corpus_manifest["corpora"]["usr_bin"]
    assert c["file_count"] == 3239
    assert c["root"] == "/usr/bin"


def test_usr_lib_file_count(corpus_manifest):
    c = corpus_manifest["corpora"]["usr_lib_x86_64"]
    assert c["file_count"] == 1683
    assert c["recursive"] is False


def test_openwrt_firmware_file_count(corpus_manifest):
    c = corpus_manifest["corpora"]["openwrt_firmware"]
    assert c["file_count"] == 2181


def test_iotgoat_firmware_file_count(corpus_manifest):
    c = corpus_manifest["corpora"]["iotgoat_firmware"]
    assert c["file_count"] == 1012


def test_usr_bin_symlinks_excluded_not_double_counted(corpus_manifest):
    # /usr/bin has 3244 filesystem entries reported by `find -type f`
    # (symlinks excluded) and 1123 symlinks on top of that; the manifest
    # must match `find -type f`, not double-count symlink targets.
    c = corpus_manifest["corpora"]["usr_bin"]
    assert c["file_count"] + c["excluded_too_large_count"] == 3244


def test_no_unreadable_files_in_usr_bin_or_usr_lib(corpus_manifest):
    for name in ("usr_bin", "usr_lib_x86_64"):
        assert corpus_manifest["corpora"][name]["excluded_unreadable_count"] == 0


def test_size_cap_documented_and_applied(corpus_manifest):
    for name in ("usr_bin", "usr_lib_x86_64"):
        c = corpus_manifest["corpora"][name]
        assert c["cap_bytes"] == 50 * 1024 * 1024
        for f in c["files"]:
            assert f["size_bytes"] <= c["cap_bytes"]
