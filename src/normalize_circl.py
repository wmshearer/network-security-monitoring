"""
Normalize the CIRCL OSINT feed (MISP JSON format) into the same three
indicator-value sets used for the LockBit intrusion: IPs, SHA256 hashes,
DNS names. This is the "public feed" side of the overlap measurement.

CIRCL's feed is MISP-native JSON (one file per MISP "event", each holding
a flat list of "Attribute" objects with a `type` and `value`), not STIX.
Per the task's design ("normalize indicators ... onto STIX 2.1"), the
values pulled out here are fed through emit_stix.py's same pattern-
building logic so both sides of the comparison end up as STIX 2.1
Indicator objects before being compared, even though CIRCL never
publishes STIX itself.

MISP attribute types mapped here (the ones seen in this feed's data,
confirmed by direct inspection of a sample event file):
  - 'sha256'            -> SHA256 hash (uppercased to match LockBit side)
  - 'domain', 'hostname' -> DNS name
  - 'ip-src', 'ip-dst'   -> IPv4 (present in some CIRCL events even though
                            not observed in the specific sample checked
                            during development; included because they are
                            standard MISP attribute types for this feed)
  - 'filename|sha256'    -> SHA256 hash extracted from the "filename|hash"
                            compound value MISP uses when a hash was seen
                            attached to a specific filename

Attribute types NOT mapped (md5, sha1, link, text, campaign-name, and
others) are counted but not converted, because the LockBit side only
extracts SHA256/IP/DNS, so there's nothing on the other side to compare
them against; converting them would create indicator types with no
possible match, adding STIX object count without adding measurement
value.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "circl_cache"

MAPPED_TYPES = {
    "sha256": "sha256",
    "filename|sha256": "sha256_pair",  # value is "filename|hash", hash extracted below
    "domain": "dns",
    "hostname": "dns",
    "ip-src": "ip",
    "ip-dst": "ip",
}

SHA256_HEX_RE = re.compile(r"^[0-9A-Fa-f]{64}$")


def load_circl_indicators(cache_dir: Path = CACHE_DIR) -> dict:
    """Read every cached CIRCL event JSON file and pull out sha256/ip/dns
    attribute values.

    Returns dict with 'ips', 'sha256', 'dns' -> sorted distinct lists, plus
    'events_loaded' and 'attribute_type_counts' (all types seen, mapped or
    not, for transparency about what was in the feed).
    """
    ips, sha256s, dns = set(), set(), set()
    type_counts: dict[str, int] = {}
    events_loaded = 0
    parse_errors = 0

    event_files = sorted(cache_dir.glob("*.json"))
    event_files = [f for f in event_files if f.name != "manifest.json"]

    for f in event_files:
        try:
            data = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            parse_errors += 1
            continue

        event = data.get("Event", data)
        attrs = event.get("Attribute", [])
        events_loaded += 1

        for attr in attrs:
            t = attr.get("type", "")
            v = attr.get("value", "")
            type_counts[t] = type_counts.get(t, 0) + 1

            mapped = MAPPED_TYPES.get(t)
            if mapped == "sha256" and SHA256_HEX_RE.match(v):
                sha256s.add(v.upper())
            elif mapped == "sha256_pair" and "|" in v:
                hash_part = v.split("|", 1)[1]
                if SHA256_HEX_RE.match(hash_part):
                    sha256s.add(hash_part.upper())
            elif mapped == "dns" and v:
                dns.add(v.strip().lower())
            elif mapped == "ip" and v:
                ips.add(v.strip())

    return {
        "ips": sorted(ips),
        "sha256": sorted(sha256s),
        "dns": sorted(dns),
        "events_loaded": events_loaded,
        "event_files_found": len(event_files),
        "parse_errors": parse_errors,
        "attribute_type_counts": dict(
            sorted(type_counts.items(), key=lambda x: -x[1])
        ),
    }


if __name__ == "__main__":
    result = load_circl_indicators()
    print(json.dumps(
        {
            "events_loaded": result["events_loaded"],
            "event_files_found": result["event_files_found"],
            "parse_errors": result["parse_errors"],
            "ips_count": len(result["ips"]),
            "sha256_count": len(result["sha256"]),
            "dns_count": len(result["dns"]),
            "attribute_type_counts": result["attribute_type_counts"],
        },
        indent=2,
    ))
