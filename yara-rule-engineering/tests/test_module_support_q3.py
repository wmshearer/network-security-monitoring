"""Pins which YARA modules each engine's Python binding compiles against."""


def test_hash_and_cuckoo_only_supported_by_yara_x(module_support_results):
    for mod in ("hash", "cuckoo"):
        assert module_support_results[mod]["yara_python_compiles"] is False
        assert module_support_results[mod]["yara_x_compiles"] is True


def test_pe_elf_math_supported_by_both(module_support_results):
    for mod in ("pe", "elf", "math"):
        assert module_support_results[mod]["yara_python_compiles"] is True
        assert module_support_results[mod]["yara_x_compiles"] is True


def test_androguard_and_magic_supported_by_neither(module_support_results):
    for mod in ("androguard", "magic"):
        assert module_support_results[mod]["yara_python_compiles"] is False
        assert module_support_results[mod]["yara_x_compiles"] is False
