"""
Extract indicators from the portfolio's own captured LockBit intrusion.

Source log: ir-activemq-lockbit / _corpora attack_data dataset
  ActiveMQ_exploit_Lockbit_Ransomware/windows-sysmon.log
This is a Sysmon operational log (one XML <Event>...</Event> element per
line) captured from a lab reproduction of the ActiveMQ RCE (CVE-2023-46604)
to LockBit 3.0 ransomware chain, documented in the sibling project
`ir-activemq-lockbit`.

Extraction method (regex over the raw XML text, not an XML parser, because
the file is one well-formed <Event> per line and the fields needed sit in
predictable attribute/tag shapes):
  - IPv4: dotted-quad pattern anywhere in the line. This regex over-
    matches on purpose (e.g. it will also match version-number-shaped strings that
    happen to look like an IP, and it does not validate octet range
    0-255), so results are a raw candidate set, not a validated IP list,
    until they pass through octet-range validation and noise filtering.
  - SHA256: the `Hashes` field on Sysmon file/process events contains a
    comma-separated `SHA256=<64 hex>` component. Only true 64-hex-char
    values following `SHA256=` are captured, so this list needs no further
    validation before it counts as syntactically real SHA256 hashes.
  - DNS: Sysmon Event ID 22 (DNS query) events carry the queried name in
    `<Data Name='QueryName'>...</Data>`.

Noise filtering (see filter_lockbit_iocs.py) is a SEPARATE step. This
module's job is only to extract candidates, honestly, with no filtering
applied here.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHA256_RE = re.compile(r"SHA256=([0-9A-Fa-f]{64})")
DNS_RE = re.compile(r"<Data Name='QueryName'>([^<]+)</Data>")


def _valid_ipv4(candidate: str) -> bool:
    try:
        ipaddress.IPv4Address(candidate)
        return True
    except ValueError:
        return False


def extract(log_path: str | Path) -> dict:
    """Return raw extracted indicator sets from a Sysmon log.

    Keys: 'ips', 'sha256', 'dns' -> sorted lists of distinct values.
    IPs are validated as real IPv4 addresses (octets 0-255); the regex
    match itself does not check octet range, so that check happens here
    before anything is counted as an IP.
    """
    text = Path(log_path).read_text(encoding="utf-8", errors="replace")

    raw_ips = set(IP_RE.findall(text))
    valid_ips = {ip for ip in raw_ips if _valid_ipv4(ip)}

    sha256 = set(SHA256_RE.findall(text))
    sha256 = {h.upper() for h in sha256}

    dns = set(DNS_RE.findall(text))

    return {
        "ips": sorted(valid_ips),
        "sha256": sorted(sha256),
        "dns": sorted(dns),
        "raw_ip_regex_matches": len(raw_ips),
        "ip_regex_matches_rejected_invalid_octet": len(raw_ips) - len(valid_ips),
    }


if __name__ == "__main__":
    import json
    import sys

    default_path = (
        Path(__file__).resolve().parent.parent.parent
        / "_corpora/attack_data/datasets/apt_simulations/"
        "ActiveMQ_exploit_Lockbit_Ransomware/windows-sysmon.log"
    )
    log_path = sys.argv[1] if len(sys.argv) > 1 else default_path
    result = extract(log_path)
    print(json.dumps(
        {
            "ips_count": len(result["ips"]),
            "sha256_count": len(result["sha256"]),
            "dns_count": len(result["dns"]),
            "raw_ip_regex_matches": result["raw_ip_regex_matches"],
            "ip_regex_matches_rejected_invalid_octet": result[
                "ip_regex_matches_rejected_invalid_octet"
            ],
        },
        indent=2,
    ))
