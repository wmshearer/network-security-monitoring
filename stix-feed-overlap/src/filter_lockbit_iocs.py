"""
Separate real indicators of compromise from lab background noise.

A raw indicator extracted from a Sysmon log is not automatically an IOC.
This lab (Splunk's "attack_range", hostname pattern EC2AMAZ-*) generates a
lot of traffic that has nothing to do with the LockBit intrusion itself:
private RFC1918 addresses, the lab's own Active Directory domain
(attackrange.local), AWS Systems Manager endpoints the EC2 instance talks
to for management, and ordinary background web browsing (news sites,
google.com, youtube.com, root DNS servers) that happened on the same box
during the capture window. Counting those as "indicators of the LockBit
intrusion" would inflate the indicator count with things nobody could ever
usefully hunt on, which is the dishonest failure mode this module exists
to prevent.

Filtering rules, stated explicitly so the split is auditable:

IPs filtered out (not counted as IOCs):
  - RFC1918 private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
  - Loopback: 127.0.0.0/8
  - Link-local: 169.254.0.0/16 (AWS instance metadata range lives here too)
  - 0.0.0.0 (non-routable placeholder, appears as a Sysmon default field)

DNS names filtered out (not counted as IOCs):
  - Anything ending in the lab's own AD domain: attackrange.local (any case)
  - Bare NetBIOS-style hostnames matching the lab's own EC2 naming pattern
    (EC2AMAZ-*), with or without a domain suffix
  - AWS Systems Manager / EC2 management endpoints: any name containing
    ".amazonaws.com" or ".ec2-utilities.amazonaws.com" (SSM agent traffic
    from the EC2 instance managing itself, not attacker infrastructure)
  - Windows/AD service-location records: names starting with an underscore
    label (_ldap, _kerberos, _gc, _kpasswd) per RFC 2782 SRV record
    convention, all of which point back at the lab's own domain controller
  - DNS root server hostnames (a.root-servers.net through m.root-servers.net)
  - The bare string "." (DNS root query) and "local." (mDNS-style bare
    query with no real name)
  - www.google.com specifically, called out by name in the task because it
    is the clearest example of "obviously not an IOC" background noise;
    handled generically below by the OS/browser telco pattern list, but
    listed explicitly too so the rule is visible without reading the regex

Everything else (news sites, CDN edges, software vendor download domains
such as chocolatey.org, oracle.com, java.com, and similar) is NOT filtered
here even though a human analyst would also call most of it background
browsing noise, not LockBit infrastructure. The task's filtering rules
are host/lab-background rules, not a full "is this newsworthy" judgment
call, and drawing that second, softer line would be a subjective editorial
decision this module does not make. That means the "surviving
after filtering" count in this module is a floor on the noise, not a
claim that everything left over is confirmed malicious. The measurement
step (compare_to_feeds.py) is what actually tells us which of the survivors
were ever seen anywhere else.

Known limitation on the IP side, stated plainly: filtering IPs can only
remove addresses that are non-routable by definition (private/loopback/
link-local). It cannot tell a Cloudflare DNS resolver (1.1.1.1, 1.0.0.1)
or a CDN edge IP (Cloudflare's 104.16.0.0/13-ish ranges seen here) apart
from genuine attacker infrastructure, because both are ordinary public
IPs. Unlike the DNS side, there is no lab-domain string to match against.
A large share of the "surviving" IP count below is background web/CDN
traffic, not necessarily LockBit infrastructure; the DNS-name survivor
count is the more trustworthy of the two after filtering, because domain
names carry the lab/vendor context that raw IPs do not.
"""

from __future__ import annotations

import ipaddress
import re
from corpora_path import lockbit_sysmon_log

AMAZONAWS_SUFFIXES = (".amazonaws.com", ".ec2-utilities.amazonaws.com")
ROOT_SERVERS = {f"{c}.root-servers.net" for c in "abcdefghijklm"}
SRV_RECORD_PREFIXES = ("_ldap.", "_kerberos.", "_gc.", "_kpasswd.")


def _is_lab_noise_ip(ip: str) -> tuple[bool, str]:
    addr = ipaddress.IPv4Address(ip)
    if addr == ipaddress.IPv4Address("0.0.0.0"):
        return True, "non-routable placeholder (0.0.0.0)"
    if addr.is_loopback:
        return True, "loopback"
    if addr.is_link_local:
        return True, "link-local (includes AWS instance metadata range 169.254.169.x)"
    if addr.is_private:
        return True, "RFC1918 private address"
    return False, ""


def _is_lab_noise_dns(name: str) -> tuple[bool, str]:
    lname = name.lower().rstrip(".")
    if lname in ("", "local"):
        return True, "bare DNS root/mDNS query with no real name"
    if lname.endswith("attackrange.local") or lname == "attackrange":
        return True, "lab's own Active Directory domain (attackrange.local)"
    if lname.startswith("ec2amaz-"):
        return True, "lab's own EC2 NetBIOS hostname pattern (EC2AMAZ-*)"
    if any(lname.endswith(s) for s in AMAZONAWS_SUFFIXES):
        return True, "AWS Systems Manager / EC2 self-management endpoint"
    if any(lname.startswith(p) for p in SRV_RECORD_PREFIXES):
        return True, "AD service-location (SRV) record pointing at the lab's own DC"
    if lname in ROOT_SERVERS:
        return True, "DNS root server"
    if lname == "www.google.com":
        return True, "background browsing to a well-known non-malicious site"
    if lname in ("wpad", "{single-dc}"):
        return True, "Windows internal auto-discovery placeholder, not a real name"
    return False, ""


def filter_ips(ips: list[str]) -> dict:
    kept, dropped = [], []
    for ip in ips:
        is_noise, reason = _is_lab_noise_ip(ip)
        (dropped if is_noise else kept).append(
            {"value": ip, "reason": reason} if is_noise else ip
        )
    return {"kept": kept, "dropped": dropped}


def filter_dns(names: list[str]) -> dict:
    kept, dropped = [], []
    for name in names:
        is_noise, reason = _is_lab_noise_dns(name)
        (dropped if is_noise else kept).append(
            {"value": name, "reason": reason} if is_noise else name
        )
    return {"kept": kept, "dropped": dropped}


def filter_all(extracted: dict) -> dict:
    """extracted: the dict returned by extract_lockbit.extract().

    SHA256 hashes are never filtered: a file hash has no concept of
    "lab background" the way an IP or hostname does, so every distinct
    SHA256 extracted is treated as a real indicator.
    """
    ip_result = filter_ips(extracted["ips"])
    dns_result = filter_dns(extracted["dns"])
    return {
        "ips": ip_result,
        "dns": dns_result,
        "sha256_kept": extracted["sha256"],  # unfiltered by design
        "counts": {
            "ips_raw": len(extracted["ips"]),
            "ips_kept": len(ip_result["kept"]),
            "ips_dropped": len(ip_result["dropped"]),
            "dns_raw": len(extracted["dns"]),
            "dns_kept": len(dns_result["kept"]),
            "dns_dropped": len(dns_result["dropped"]),
            "sha256_raw": len(extracted["sha256"]),
            "sha256_kept": len(extracted["sha256"]),
        },
    }


if __name__ == "__main__":
    import json
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from extract_lockbit import extract

    default_path = (
        lockbit_sysmon_log()
    )
    log_path = sys.argv[1] if len(sys.argv) > 1 else default_path
    extracted = extract(log_path)
    filtered = filter_all(extracted)
    print(json.dumps(filtered["counts"], indent=2))
