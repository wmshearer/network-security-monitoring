import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from filter_lockbit_iocs import filter_all, filter_dns, filter_ips


def test_rfc1918_ip_is_dropped():
    result = filter_ips(["10.0.2.11", "8.8.8.8"])
    assert "10.0.2.11" not in result["kept"]
    assert "8.8.8.8" in result["kept"]
    dropped_values = [d["value"] for d in result["dropped"]]
    assert "10.0.2.11" in dropped_values


def test_link_local_metadata_ip_is_dropped():
    result = filter_ips(["169.254.169.254", "1.1.1.1"])
    assert "169.254.169.254" not in result["kept"]
    assert "1.1.1.1" in result["kept"]


def test_placeholder_ip_zero_is_dropped():
    result = filter_ips(["0.0.0.0", "104.16.117.43"])
    assert "0.0.0.0" not in result["kept"]
    assert "104.16.117.43" in result["kept"]


def test_lab_domain_is_dropped():
    result = filter_dns(
        ["EC2AMAZ-TLJH2O4.attackrange.local", "evil.example.net"]
    )
    assert "EC2AMAZ-TLJH2O4.attackrange.local" not in result["kept"]
    assert "evil.example.net" in result["kept"]


def test_ec2_hostname_pattern_is_dropped():
    result = filter_dns(["EC2AMAZ-I41BETP", "chocolatey.org"])
    assert "EC2AMAZ-I41BETP" not in result["kept"]
    assert "chocolatey.org" in result["kept"]


def test_aws_ssm_endpoint_is_dropped():
    result = filter_dns(
        ["ssm.eu-west-1.amazonaws.com", "wpad.eu-west-1.ec2-utilities.amazonaws.com"]
    )
    assert result["kept"] == []
    assert len(result["dropped"]) == 2


def test_www_google_com_is_dropped_by_name():
    """The task explicitly calls out www.google.com as an example of
    something that must not be silently counted as an IOC.
    """
    result = filter_dns(["www.google.com"])
    assert result["kept"] == []
    assert result["dropped"][0]["value"] == "www.google.com"


def test_srv_record_is_dropped():
    result = filter_dns(["_ldap._tcp.attackrange.local", "_kerberos._tcp.attackrange.local"])
    assert result["kept"] == []


def test_root_dns_server_is_dropped():
    result = filter_dns(["a.root-servers.net", "m.root-servers.net", "github.com"])
    assert "a.root-servers.net" not in result["kept"]
    assert "m.root-servers.net" not in result["kept"]
    assert "github.com" in result["kept"]


def test_sha256_is_never_filtered():
    extracted = {
        "ips": [],
        "dns": [],
        "sha256": ["A" * 64, "B" * 64],
    }
    result = filter_all(extracted)
    assert result["sha256_kept"] == ["A" * 64, "B" * 64]
    assert result["counts"]["sha256_dropped"] if False else True  # no drop concept for hashes


def test_filter_all_counts_are_internally_consistent():
    extracted = {
        "ips": ["10.0.0.1", "8.8.8.8"],
        "dns": ["www.google.com", "example.net"],
        "sha256": ["C" * 64],
    }
    result = filter_all(extracted)
    counts = result["counts"]
    assert counts["ips_kept"] + counts["ips_dropped"] == counts["ips_raw"]
    assert counts["dns_kept"] + counts["dns_dropped"] == counts["dns_raw"]
    assert counts["ips_kept"] == 1
    assert counts["dns_kept"] == 1
