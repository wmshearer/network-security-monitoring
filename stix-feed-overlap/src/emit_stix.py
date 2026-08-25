"""
Emit real STIX 2.1 Indicator objects for the LockBit intrusion's
surviving indicators, using the `stix2` library (not hand-rolled JSON),
so the pattern syntax and object structure are validated by a library that
implements the OASIS STIX 2.1 spec rather than merely looking right.

STIX 2.1 pattern syntax used here (per
https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html section 9,
STIX Patterning):
  - IPv4:   [ipv4-addr:value = '<ip>']
  - SHA256: [file:hashes.'SHA-256' = '<hex>']
  - DNS:    [domain-name:value = '<name>']

Each Indicator is created with `stix2.Indicator(...)`, which parses and
validates the pattern string against STIX 2.1 patterning grammar at
construction time; a malformed pattern raises an exception rather than
silently producing bad STIX. `pattern_type='stix'` and `spec_version='2.1'`
are set explicitly.
"""

from __future__ import annotations

import json
from pathlib import Path

import stix2
from corpora_path import lockbit_sysmon_log

IDENTITY_NAME = "stix-feed-overlap research project (portfolio measurement)"


def _identity() -> stix2.Identity:
    return stix2.Identity(
        name=IDENTITY_NAME,
        identity_class="organization",
        description=(
            "Source identity for indicators extracted from the portfolio's "
            "own captured LockBit/ActiveMQ lab intrusion (ir-activemq-lockbit "
            "/ _corpora attack_data dataset), used only for STIX object "
            "attribution within this measurement project."
        ),
    )


def build_indicators(filtered: dict, created_by_ref: str) -> list[stix2.Indicator]:
    """filtered: the dict returned by filter_lockbit_iocs.filter_all().

    Returns a list of stix2.Indicator objects, one per surviving IP, DNS
    name, and SHA256 hash. Each carries the pattern, a description saying
    which extraction rule produced it, and labels marking it as coming
    from a lab-reproduced intrusion rather than an in-the-wild capture,
    which matters later when interpreting the overlap measurement.
    """
    indicators: list[stix2.Indicator] = []

    for ip in filtered["ips"]["kept"]:
        indicators.append(
            stix2.Indicator(
                pattern=f"[ipv4-addr:value = '{ip}']",
                pattern_type="stix",
                spec_version="2.1",
                created_by_ref=created_by_ref,
                indicator_types=["unknown"],
                name=f"IPv4 observed in LockBit lab intrusion: {ip}",
                description=(
                    "Extracted by regex from Sysmon network/DNS-adjacent "
                    "fields in the ir-activemq-lockbit dataset's "
                    "windows-sysmon.log. Survived RFC1918/loopback/"
                    "link-local filtering; see filter_lockbit_iocs.py for "
                    "the exact rule. Not independently confirmed malicious."
                ),
                labels=["lab-reproduction-source"],
            )
        )

    for name in filtered["dns"]["kept"]:
        indicators.append(
            stix2.Indicator(
                pattern=f"[domain-name:value = '{name}']",
                pattern_type="stix",
                spec_version="2.1",
                created_by_ref=created_by_ref,
                indicator_types=["unknown"],
                name=f"DNS name observed in LockBit lab intrusion: {name}",
                description=(
                    "Extracted from Sysmon Event ID 22 (DNS query) "
                    "QueryName fields. Survived lab-domain/AWS-SSM/root-"
                    "server filtering; see filter_lockbit_iocs.py for the "
                    "exact rule. Not independently confirmed malicious."
                ),
                labels=["lab-reproduction-source"],
            )
        )

    for sha256 in filtered["sha256_kept"]:
        indicators.append(
            stix2.Indicator(
                pattern=f"[file:hashes.'SHA-256' = '{sha256}']",
                pattern_type="stix",
                spec_version="2.1",
                created_by_ref=created_by_ref,
                indicator_types=["malicious-activity"],
                name=f"File SHA-256 observed in LockBit lab intrusion: {sha256}",
                description=(
                    "Extracted from the Hashes field on Sysmon file/process "
                    "events (SHA256=<64 hex> component). File hashes are "
                    "not filtered for lab noise, see filter_lockbit_iocs.py "
                    "docstring for why."
                ),
                labels=["lab-reproduction-source"],
            )
        )

    return indicators


def build_bundle(filtered: dict) -> stix2.Bundle:
    identity = _identity()
    indicators = build_indicators(filtered, created_by_ref=identity.id)
    return stix2.Bundle(objects=[identity, *indicators])


def validate_bundle(bundle: stix2.Bundle) -> dict:
    """Re-parse the serialized bundle through stix2 to prove it is valid
    STIX 2.1, independent of the objects having been built via the
    library's own constructors (which already validate on construction,
    but re-parsing from the JSON text is a stronger, independent check
    that catches any hand-editing after construction).
    """
    raw = bundle.serialize()
    reparsed = stix2.parse(raw, allow_custom=False)
    n_indicators = sum(
        1 for obj in reparsed.objects if obj["type"] == "indicator"
    )
    n_identities = sum(
        1 for obj in reparsed.objects if obj["type"] == "identity"
    )
    return {
        "valid": True,
        "bundle_type": reparsed["type"],
        "total_objects": len(reparsed.objects),
        "indicator_objects": n_indicators,
        "identity_objects": n_identities,
        "spec_versions_seen": sorted(
            {obj.get("spec_version", "2.0-implicit") for obj in reparsed.objects}
        ),
    }


if __name__ == "__main__":
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from extract_lockbit import extract
    from filter_lockbit_iocs import filter_all

    default_path = (
        lockbit_sysmon_log()
    )
    log_path = sys.argv[1] if len(sys.argv) > 1 else default_path
    out_path = (
        Path(sys.argv[2])
        if len(sys.argv) > 2
        else Path(__file__).resolve().parent.parent / "data" / "lockbit_stix_bundle.json"
    )

    extracted = extract(log_path)
    filtered = filter_all(extracted)
    bundle = build_bundle(filtered)
    out_path.write_text(bundle.serialize(pretty=True))

    validation = validate_bundle(bundle)
    print(json.dumps(
        {"output_path": str(out_path), "validation": validation},
        indent=2,
    ))
