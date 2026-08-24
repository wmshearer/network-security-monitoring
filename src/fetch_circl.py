"""
Download the CIRCL OSINT feed (MISP JSON format, TLP:CLEAR, no API key).

Source: https://www.circl.lu/doc/misp/feed-osint/
This is the one feed identified in prior research
(projects/wshearer-site/research/misp-stix-taxii.md) that is reachable with
no signup and no API key. Live-checked 2026-08-24: manifest.json returns
HTTP 200.

Constraints enforced here, not assumed:
- No API key is ever sent (none exists for this feed).
- Total download is capped at 4 GB. The cap is checked after every file and
  the run stops the moment it would be exceeded, logging how much was
  actually pulled.
- Every event file is written to data/circl_cache/ (gitignored) plus a
  download_log.json in data/ (NOT gitignored) recording exactly what was
  requested, the HTTP status, byte count, and running total, so the actual
  bytes downloaded are provable after the fact rather than just claimed.
"""

from __future__ import annotations

import json
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

MANIFEST_URL = "https://www.circl.lu/doc/misp/feed-osint/manifest.json"
EVENT_URL_TMPL = "https://www.circl.lu/doc/misp/feed-osint/{uuid}.json"
MAX_DOWNLOAD_BYTES = 4 * 1024 * 1024 * 1024  # 4 GB hard cap, per task constraint
USER_AGENT = "stix-feed-overlap-research/1.0 (portfolio measurement project)"
TIMEOUT_S = 10
# Belt-and-suspenders: urllib's per-call timeout does not always bound TLS
# handshake time reliably, so also set a process-wide socket default. A
# first run of this script hung indefinitely on one request past its
# per-call timeout; this fixes that.
socket.setdefaulttimeout(TIMEOUT_S)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
CACHE_DIR = DATA_DIR / "circl_cache"
LOG_PATH = DATA_DIR / "download_log.json"


def _get(url: str) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, b""
    except urllib.error.URLError as e:
        return 0, str(e).encode()


def fetch_all(limit: int | None = None) -> dict:
    """Fetch the manifest, then every event file it lists, honoring the 4 GB cap.

    Returns a summary dict. Writes data/download_log.json with a full record
    of every request made, in order, whether it succeeded, and its size.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    log = {
        "manifest_url": MANIFEST_URL,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "max_download_bytes": MAX_DOWNLOAD_BYTES,
        "requests": [],
        "total_bytes_downloaded": 0,
        "stopped_early_at_cap": False,
        "api_key_used": False,
    }

    status, body = _get(MANIFEST_URL)
    manifest_bytes = len(body)
    log["requests"].append(
        {"url": MANIFEST_URL, "status": status, "bytes": manifest_bytes}
    )
    log["total_bytes_downloaded"] += manifest_bytes

    if status != 200:
        log["error"] = f"manifest fetch failed, HTTP {status}"
        LOG_PATH.write_text(json.dumps(log, indent=2))
        return log

    manifest_path = CACHE_DIR / "manifest.json"
    manifest_path.write_bytes(body)
    manifest = json.loads(body)
    event_uuids = list(manifest.keys())
    if limit is not None:
        event_uuids = event_uuids[:limit]

    fetched = 0
    already_cached = 0
    skipped_cap = 0
    for uuid in event_uuids:
        if log["total_bytes_downloaded"] >= MAX_DOWNLOAD_BYTES:
            log["stopped_early_at_cap"] = True
            skipped_cap = len(event_uuids) - fetched
            break

        # Resume support: a prior run may have already fetched this event
        # (e.g. after being interrupted by a network hang). Don't re-download
        # or re-count bytes already on disk.
        cache_path = CACHE_DIR / f"{uuid}.json"
        if cache_path.exists():
            already_cached += 1
            fetched += 1
            continue

        url = EVENT_URL_TMPL.format(uuid=uuid)
        status, body = _get(url)
        n = len(body)

        # Stop BEFORE writing/counting a file that would push us over the cap.
        if log["total_bytes_downloaded"] + n > MAX_DOWNLOAD_BYTES:
            log["stopped_early_at_cap"] = True
            log["requests"].append(
                {"url": url, "status": status, "bytes": n, "written": False,
                 "reason": "would exceed 4GB cap"}
            )
            skipped_cap = len(event_uuids) - fetched
            break

        log["requests"].append({"url": url, "status": status, "bytes": n})
        log["total_bytes_downloaded"] += n

        if status == 200 and n > 0:
            (CACHE_DIR / f"{uuid}.json").write_bytes(body)
            fetched += 1

        # Write the log incrementally so progress is provable even if this
        # run is interrupted or backgrounded and checked mid-flight.
        if fetched % 25 == 0:
            log["events_in_manifest"] = len(manifest)
            log["events_fetched"] = fetched
            LOG_PATH.write_text(json.dumps(log, indent=2))

    log["events_in_manifest"] = len(manifest)
    log["events_fetched"] = fetched
    log["events_already_cached_from_prior_run"] = already_cached
    log["events_skipped_due_to_cap"] = skipped_cap
    log["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    LOG_PATH.write_text(json.dumps(log, indent=2))
    return log


if __name__ == "__main__":
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None
    result = fetch_all(limit=limit)
    print(json.dumps(
        {k: v for k, v in result.items() if k != "requests"}, indent=2
    ))
