import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from extract_lockbit import extract
from src.corpora_path import lockbit_sysmon_log

LOG_PATH = (
    lockbit_sysmon_log()
)


def test_log_file_exists():
    assert LOG_PATH.exists(), f"expected LockBit log at {LOG_PATH}"


def test_extracted_counts_match_known_values():
    """These exact counts were independently verified by the director
    before this project was scoped (316 raw IP regex matches, 602 SHA256,
    238 DNS names) and re-confirmed by direct regex during this build.
    If the source file or extraction logic ever changes, this test should
    fail loudly rather than silently accept a different number.
    """
    result = extract(LOG_PATH)
    assert result["raw_ip_regex_matches"] == 316
    assert len(result["ips"]) == 315  # one raw match (11.491.2.10) is not a valid IPv4
    assert len(result["sha256"]) == 602
    assert len(result["dns"]) == 238


def test_all_sha256_are_64_hex_chars():
    result = extract(LOG_PATH)
    for h in result["sha256"]:
        assert len(h) == 64
        assert all(c in "0123456789ABCDEF" for c in h)


def test_all_ips_are_valid_ipv4_octets():
    import ipaddress

    result = extract(LOG_PATH)
    for ip in result["ips"]:
        addr = ipaddress.IPv4Address(ip)  # raises ValueError if invalid
        assert str(addr) == ip or ip.count(".") == 3


def test_invalid_octet_ip_is_rejected():
    """11.491.2.10 has an octet (491) outside the valid 0-255 range and
    must never appear in the validated IP list even though it matches the
    dotted-quad regex.
    """
    result = extract(LOG_PATH)
    assert "11.491.2.10" not in result["ips"]
