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
    """
    lower_text = log_text.lower()
    return sorted(
        name for name in software_names if name.lower() in lower_text
    )


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
    print(json.dumps({"attack_software_names_found_in_log_text": matches}, indent=2))
