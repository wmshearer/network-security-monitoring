"""
THE MEASUREMENT.

Compare the LockBit intrusion's surviving indicators (after noise
filtering, see filter_lockbit_iocs.py) against the CIRCL OSINT feed's
indicators (see normalize_circl.py) and report the exact overlap: how many
of the intrusion's indicators were ever seen in the public feed data, as a
count and a percentage, per indicator type and combined.

If a fallback comparison against the on-disk MITRE ATT&CK STIX bundle is
also run (see compare_to_attack.py), that is a SEPARATE, weaker comparison
against technique/tool metadata, not raw IOCs, and is not mixed into this
module's numbers.

Matching is exact string equality after normalization already applied
upstream (IPs as given, DNS lowercased, SHA256 uppercased). No fuzzy
matching, no substring matching, no wildcarding: an indicator either
appears verbatim in the feed data or it does not count as a match.
"""

from __future__ import annotations

import json
from pathlib import Path


def compare(lockbit_filtered: dict, circl_indicators: dict) -> dict:
    lb_ips = set(lockbit_filtered["ips"]["kept"])
    lb_dns = set(lockbit_filtered["dns"]["kept"])
    lb_sha256 = set(lockbit_filtered["sha256_kept"])

    feed_ips = set(circl_indicators["ips"])
    feed_dns = set(circl_indicators["dns"])
    feed_sha256 = set(circl_indicators["sha256"])

    ip_matches = sorted(lb_ips & feed_ips)
    dns_matches = sorted(lb_dns & feed_dns)
    sha256_matches = sorted(lb_sha256 & feed_sha256)

    total_lb = len(lb_ips) + len(lb_dns) + len(lb_sha256)
    total_matches = len(ip_matches) + len(dns_matches) + len(sha256_matches)

    def pct(n: int, d: int) -> float:
        return round(100.0 * n / d, 4) if d else 0.0

    return {
        "lockbit_surviving_indicators": {
            "ips": len(lb_ips),
            "dns": len(lb_dns),
            "sha256": len(lb_sha256),
            "total": total_lb,
        },
        "circl_feed_indicators": {
            "ips": len(feed_ips),
            "dns": len(feed_dns),
            "sha256": len(feed_sha256),
            "total": len(feed_ips) + len(feed_dns) + len(feed_sha256),
        },
        "matches": {
            "ips": ip_matches,
            "dns": dns_matches,
            "sha256": sha256_matches,
        },
        "match_counts": {
            "ips": len(ip_matches),
            "dns": len(dns_matches),
            "sha256": len(sha256_matches),
            "total": total_matches,
        },
        "overlap_percentage": {
            "ips": pct(len(ip_matches), len(lb_ips)),
            "dns": pct(len(dns_matches), len(lb_dns)),
            "sha256": pct(len(sha256_matches), len(lb_sha256)),
            "total": pct(total_matches, total_lb),
        },
    }


if __name__ == "__main__":
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from extract_lockbit import extract
    from filter_lockbit_iocs import filter_all
    from normalize_circl import load_circl_indicators

    default_path = (
        Path(__file__).resolve().parent.parent.parent
        / "_corpora/attack_data/datasets/apt_simulations/"
        "ActiveMQ_exploit_Lockbit_Ransomware/windows-sysmon.log"
    )
    log_path = sys.argv[1] if len(sys.argv) > 1 else default_path

    extracted = extract(log_path)
    filtered = filter_all(extracted)
    circl = load_circl_indicators()
    result = compare(filtered, circl)

    out_path = Path(__file__).resolve().parent.parent / "data" / "overlap_measurement.json"
    out_path.write_text(json.dumps(result, indent=2))

    print(json.dumps(
        {
            "lockbit_surviving_indicators": result["lockbit_surviving_indicators"],
            "circl_feed_indicators": result["circl_feed_indicators"],
            "match_counts": result["match_counts"],
            "overlap_percentage": result["overlap_percentage"],
        },
        indent=2,
    ))
