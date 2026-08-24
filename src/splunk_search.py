#!/usr/bin/env python3
"""Small helper to run one-shot SPL searches against the local Splunk REST API
and print/save JSON results. Same pattern as cloud-detection-lab's and
splunk-ingest-pipeline's src/splunk_search.py (both done, not touched here),
reused because SPL containing backslashes/quotes/wildcards is fragile to
shell-escape correctly from bash, and a misquoted search silently returns an
empty result set rather than erroring loudly.

Credentials are read from environment variables, never hardcoded, per the
"never hardcode secrets" constraint -- SPLUNK_USER/SPLUNK_PASS default to
this lab's own documented values (see README.md) only as a local-dev
fallback, matching this host's actual Splunk instance.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_URL = os.environ.get("SPLUNK_URL", "https://localhost:8089")
SPLUNK_USER = os.environ.get("SPLUNK_USER", "admin")
# No default. Set SPLUNK_PASS in the environment before running:
#   export SPLUNK_PASS='your-splunk-admin-password'
SPLUNK_PASS = os.environ.get("SPLUNK_PASS")
if not SPLUNK_PASS:
    raise SystemExit(
        "SPLUNK_PASS is not set. Export it before running:\n"
        "  export SPLUNK_PASS='your-splunk-admin-password'"
    )


def run_search(search: str, earliest: str = "0", latest: str = "now") -> dict:
    if not search.strip().startswith(("search", "|")):
        search = "search " + search
    resp = requests.post(
        f"{SPLUNK_URL}/services/search/jobs",
        data={
            "search": search,
            "exec_mode": "oneshot",
            "output_mode": "json",
            "earliest_time": earliest,
            "latest_time": latest,
            "count": 0,
        },
        auth=(SPLUNK_USER, SPLUNK_PASS),
        verify=False,
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()


def result_count(search: str, earliest: str = "0", latest: str = "now") -> int:
    """Run search | stats count and return the integer count."""
    data = run_search(f"{search} | stats count", earliest, latest)
    results = data.get("results", [])
    if not results:
        return 0
    return int(results[0]["count"])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("search", help="SPL search string")
    ap.add_argument("--out", help="write JSON result to this path")
    ap.add_argument("--earliest", default="0")
    ap.add_argument("--latest", default="now")
    args = ap.parse_args()

    data = run_search(args.search, args.earliest, args.latest)
    text = json.dumps(data, indent=2)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(text)
        print(f"wrote {args.out}", file=sys.stderr)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
