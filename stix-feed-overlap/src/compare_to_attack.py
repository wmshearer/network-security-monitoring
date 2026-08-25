"""
Fallback comparison against the on-disk MITRE ATT&CK Enterprise STIX 2.1
bundle (cloud-detection-coverage/data/enterprise-attack.json, 26,086
objects). This is explicitly a DIFFERENT and WEAKER comparison than the
CIRCL overlap measurement in compare_to_feeds.py, not a substitute for it.

Why it is weaker, stated directly: the ATT&CK bundle contains zero STIX
`indicator` objects. It is a knowledge base of techniques
(attack-pattern), software (malware/tool), threat actors (intrusion-set),
and campaigns, not a feed of raw observables like IPs, hashes, or domains.
Confirmed by direct inspection: this bundle has 0 objects of type
`indicator` out of 26,086 total. So there is structurally no way to ask
"does this SHA256 or this IP appear in ATT&CK" the way the question is
asked of CIRCL, because ATT&CK does not publish that kind of data at all.

What CAN legitimately be checked here instead: whether any known
malware/tool NAME in ATT&CK's `malware`/`tool` objects appears as
substring text anywhere in the LockBit dataset (e.g. does the string
"LockBit" itself appear as an ATT&CK-catalogued software name). That is a
name-matching exercise, not an indicator-overlap measurement, and is
reported separately and clearly labeled as such.
"""

from __future__ import annotations

import json
from pathlib import Path

ATTACK_BUNDLE_PATH = Path(
    "/home/kali/director/projects/cloud-detection-coverage/data/enterprise-attack.json"
)


def load_attack_indicator_count(bundle_path: Path = ATTACK_BUNDLE_PATH) -> dict:
    """Confirm, directly, whether the ATT&CK bundle has any STIX indicator
    objects to compare against at all.
    """
    data = json.loads(bundle_path.read_text())
    objects = data.get("objects", [])
    type_counts: dict[str, int] = {}
    for obj in objects:
        t = obj.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    software_names = sorted(
        {
            obj["name"]
            for obj in objects
            if obj.get("type") in ("malware", "tool") and obj.get("name")
        }
    )

    return {
        "bundle_path": str(bundle_path),
        "total_objects": len(objects),
        "indicator_objects": type_counts.get("indicator", 0),
        "type_counts": dict(sorted(type_counts.items(), key=lambda x: -x[1])),
        "software_name_count": len(software_names),
        "software_names": software_names,
    }


def name_match_against_lockbit(software_names: list[str], log_text: str) -> list[str]:
    """Case-insensitive substring search: which ATT&CK software names appear
    literally in the raw LockBit Sysmon log text. This is a name-matching
    check, not an IOC-overlap measurement.

    Known problem with this check, found while running it: many ATT&CK
    software names are short strings that double as ordinary Windows
    command names (e.g. "at", "Net", "Ping", "cmd", "ftp", "Reg",
    "attrib", "certutil", "ipconfig", "netsh", "netstat", "route",
    "Expand", "Wevtutil"). These will match any Windows Sysmon log almost
    by construction and are not evidence that the specific named ATT&CK
    software was present. A short-name match here should not be read as
    a real technique-level finding without further checking; see
    matches_excluding_short_generic_names below for a coarse filter on
    that noise.
    """
    lower_text = log_text.lower()
    return sorted(
        name for name in software_names if name.lower() in lower_text
    )


# Windows built-in commands/utilities that also happen to be catalogued as
# ATT&CK software names, seen as false-positive matches during development.
# Excluding these by exact name (not by length) keeps this list auditable.
KNOWN_LOLBIN_FALSE_POSITIVES = {
    "at", "Net", "Ping", "cmd", "ftp", "Reg", "attrib", "certutil",
    "ipconfig", "netsh", "netstat", "route", "Expand", "Wevtutil", "PS1",
    "Arp",
}

# Additional false positives found by manually checking surrounding text
# for the remaining short/common matches: "Tor" matched inside ordinary
# words ("monitor", "Directory"), "Epic" matched inside an unrelated
# Windows service GUID substring, and "ABK" matched inside base64-encoded
# PowerShell content that has nothing to do with the ABK malware family.
# This is the reason a short substring match is not treated as a finding
# anywhere in this project without manually checking the surrounding text
# the way this comment documents having done for these three.
KNOWN_COINCIDENTAL_SUBSTRING_FALSE_POSITIVES = {"Tor", "Epic", "ABK"}


def matches_excluding_known_false_positives(matches: list[str]) -> list[str]:
    excluded = KNOWN_LOLBIN_FALSE_POSITIVES | KNOWN_COINCIDENTAL_SUBSTRING_FALSE_POSITIVES
    return sorted(m for m in matches if m not in excluded)


if __name__ == "__main__":
    result = load_attack_indicator_count()
    print(json.dumps(
        {
            "total_objects": result["total_objects"],
            "indicator_objects": result["indicator_objects"],
            "software_name_count": result["software_name_count"],
        },
        indent=2,
    ))

    if result["indicator_objects"] == 0:
        print(
            "\nCONFIRMED: the ATT&CK bundle has zero STIX indicator "
            "objects. An IOC-level overlap measurement against this "
            "bundle is not possible, only a technique/software NAME "
            "check, run separately below.\n"
        )

    default_log = (
        Path(__file__).resolve().parent.parent.parent
        / "_corpora/attack_data/datasets/apt_simulations/"
        "ActiveMQ_exploit_Lockbit_Ransomware/windows-sysmon.log"
    )
    text = default_log.read_text(encoding="utf-8", errors="replace")
    matches = name_match_against_lockbit(result["software_names"], text)
    filtered_matches = matches_excluding_known_false_positives(matches)
    print(json.dumps(
        {
            "attack_software_names_found_in_log_text": matches,
            "after_excluding_known_lolbin_false_positives": filtered_matches,
        },
        indent=2,
    ))
