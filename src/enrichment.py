"""Indicator extraction and enrichment.

Extraction: pulls the raw Sysmon-derived event(s) behind an alert (via the
alert's sid, falling back to re-running the detection's own SPL if the
search job's results have aged out of Splunk's job cache) and reports
which indicator kinds are actually present. This portfolio's six
detections (D1-D6) are process-creation, process-access, and
registry-SetValue Sysmon events. None of them carry a source/destination
IP, a URL, a domain, or a populated file hash -- confirmed by inspecting
the raw converted event data directly (data/converted/attack/*.json under
splunk-detection-lab) before writing this file. The Hashes field Sysmon
can carry only appears on EventID 7 (image load) and EventID 23 (file
delete) events in this dataset, and D1-D6 do not match on either. So the
indicator kinds this pipeline can genuinely extract are: process image
path, parent process image path, registry target path, and hostname. It
does not fabricate an IP or a hash to have something to feed to
IP/hash-oriented sources.

Enrichment sources, and exactly what each one is used for:

- GreyNoise Community API: genuinely keyless (no API key, no signup,
  confirmed by a live unauthenticated call during development that
  returned a real 200 response body). Accepts only IPv4 addresses. Since
  D1-D6 never produce an IP indicator, this source is always called with
  a documented "skipped: no IP indicator present" and the code path that
  WOULD call it is real and unit-tested against a fake IP, not just
  written and left untested.
- VirusTotal / AbuseIPDB: both require a free-registration API key per
  their own docs. Per this project's constraints, no account was created
  and no key obtained. Both are read from environment variables
  (VT_API_KEY, ABUSEIPDB_API_KEY) with NO default. If unset, each call is
  recorded as "skipped: no API key in environment" rather than silently
  omitted, so the enrichment log always shows what was and was not tried.
- MITRE ATT&CK technique context: NOT a live threat-intel lookup. This is
  a local, offline join against the ATT&CK Enterprise STIX bundle already
  on disk at cloud-detection-coverage/data/enterprise-attack.json (read
  only, that project is not modified). It resolves technique_id ->
  technique name/description/tactics for the verdict record. Labeled
  "local" everywhere it appears in output, never presented as a live call.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import requests

from models import Indicator, SourceCall

ATTACK_STIX_PATH = Path(
    "/home/kali/director/projects/cloud-detection-coverage/data/enterprise-attack.json"
)

_attack_cache: dict = {}


def _load_attack_techniques() -> dict:
    """Build technique_id -> {name, description, tactics} once, from the
    local STIX bundle. Cached in-process; this file is 53MB so we do not
    want to reparse it per alert.
    """
    if _attack_cache:
        return _attack_cache
    if not ATTACK_STIX_PATH.exists():
        return {}
    with open(ATTACK_STIX_PATH) as fh:
        bundle = json.load(fh)
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        ext_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id")
                break
        if not ext_id:
            continue
        tactics = [p.get("phase_name") for p in obj.get("kill_chain_phases", [])]
        _attack_cache[ext_id] = {
            "name": obj.get("name"),
            "description": (obj.get("description") or "").split("\n")[0][:300],
            "tactics": tactics,
        }
    return _attack_cache


def attack_technique_context(technique_id: str) -> dict | None:
    """Local, offline lookup. Returns None if the technique id is not in
    the on-disk STIX bundle (e.g. a sub-technique id typo).
    """
    techs = _load_attack_techniques()
    return techs.get(technique_id)


# --- Indicator extraction -------------------------------------------------

INDICATOR_FIELDS = [
    ("process_image", "Image"),
    ("parent_image", "ParentImage"),
    ("registry_path", "TargetObject"),
    ("hostname", "Hostname"),
]

IP_FIELDS = ["SourceIp", "DestinationIp", "SourceAddress", "DestAddress"]
HASH_FIELDS = ["Hashes"]


def extract_indicators(raw_event: dict) -> list:
    """Pull whatever indicator-shaped fields are actually populated on one
    raw Sysmon event dict (as returned by Splunk's REST search API, so
    keys are the Splunk field names, values are strings). Only returns
    indicators that are non-empty and not the Splunk placeholder "-".
    """
    found = []
    for kind, field in INDICATOR_FIELDS:
        val = raw_event.get(field)
        if val and val != "-":
            found.append(Indicator(kind=kind, value=val))
    return found


def which_kinds_absent(raw_event: dict) -> dict:
    """Report, explicitly, which IOC-shaped field families this event does
    NOT populate, so the enrichment log can say plainly "no IP present"
    rather than silently doing nothing.
    """
    ip_present = any(raw_event.get(f) and raw_event.get(f) != "-" for f in IP_FIELDS)
    hash_present = any(raw_event.get(f) and raw_event.get(f) != "-" for f in HASH_FIELDS)
    return {"ip": ip_present, "hash": hash_present}


# --- Enrichment sources -----------------------------------------------------

def enrich_ip_greynoise(ip: str) -> SourceCall:
    """Genuinely keyless call to GreyNoise's Community API. No API key,
    no Authorization header. Confirmed live during development: a plain
    GET against api.greynoise.io/v3/community/<ip> with zero auth returns
    a real 200 with noise/riot classification. This function makes the
    real HTTP call every time it runs; it is not a stub.
    """
    try:
        resp = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            timeout=15,
        )
    except requests.RequestException as exc:
        return SourceCall(source="greynoise_community", called=True, reason=f"request failed: {exc}")
    if resp.status_code == 404:
        return SourceCall(
            source="greynoise_community",
            called=True,
            # GreyNoise returns HTTP 404 with a structured JSON body to mean
            # "this IP is not in our dataset". That is a successful lookup with
            # a negative answer, not a failed call, so it counts as called.
            # Do not describe it as a 200; the status code is really 404.
            reason="404 with a JSON body: IP not observed, so a successful lookup with a negative answer",
            result={"status_code": 404, "body": resp.json() if resp.content else None},
        )
    if resp.status_code != 200:
        return SourceCall(
            source="greynoise_community",
            called=True,
            reason=f"non-200 response: {resp.status_code}",
            result={"status_code": resp.status_code},
        )
    return SourceCall(
        source="greynoise_community",
        called=True,
        reason="200 OK",
        result=resp.json(),
    )


def enrich_ip_abuseipdb(ip: str) -> SourceCall:
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if not key:
        return SourceCall(
            source="abuseipdb",
            called=False,
            reason="skipped: ABUSEIPDB_API_KEY not set in environment (free tier needs registration)",
        )
    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip},
        headers={"Key": key, "Accept": "application/json"},
        timeout=15,
    )
    return SourceCall(
        source="abuseipdb",
        called=True,
        reason=f"HTTP {resp.status_code}",
        result=resp.json() if resp.ok else {"status_code": resp.status_code},
    )


def enrich_hash_virustotal(file_hash: str) -> SourceCall:
    key = os.environ.get("VT_API_KEY")
    if not key:
        return SourceCall(
            source="virustotal",
            called=False,
            reason="skipped: VT_API_KEY not set in environment (free tier needs registration)",
        )
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers={"x-apikey": key},
        timeout=15,
    )
    return SourceCall(
        source="virustotal",
        called=True,
        reason=f"HTTP {resp.status_code}",
        result=resp.json() if resp.ok else {"status_code": resp.status_code},
    )


def enrich_indicators(indicators: list, absent: dict) -> list:
    """Run every configured source against the indicators that are
    actually present, and record an explicit skip for every source that
    was not applicable or not callable. Always returns one SourceCall per
    (source, reason-it-would-or-wouldn't-apply), so nothing is silently
    omitted from the record.
    """
    calls = []

    ip_indicators = [i for i in indicators if i.kind in ("source_ip", "dest_ip")]
    if not absent["ip"]:
        calls.append(SourceCall(
            source="greynoise_community",
            called=False,
            reason="skipped: no IP-shaped field populated on this event (Sysmon EventID 1/10/13 process/registry events do not carry a network IP)",
        ))
        calls.append(SourceCall(
            source="abuseipdb",
            called=False,
            reason="skipped: no IP-shaped field populated on this event",
        ))
    else:
        for ind in ip_indicators:
            calls.append(enrich_ip_greynoise(ind.value))
            calls.append(enrich_ip_abuseipdb(ind.value))

    hash_indicators = [i for i in indicators if i.kind == "file_hash"]
    if not absent["hash"]:
        calls.append(SourceCall(
            source="virustotal",
            called=False,
            reason="skipped: no Hashes field populated on this event (only Sysmon EventID 7/23 carry Hashes in this dataset; D1-D6 match on EventID 1/10/13)",
        ))
    else:
        for ind in hash_indicators:
            calls.append(enrich_hash_virustotal(ind.value))

    return calls
