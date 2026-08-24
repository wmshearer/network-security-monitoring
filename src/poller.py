"""External poller. Reads new rows from detection_lab_alerts via Splunk's
REST search API and hands each unseen one to both playbooks.

Why a poller and not a Splunk-native alert action: this Splunk instance is
on an Enterprise trial that converts to Splunk Free in roughly ten days
(confirmed from the trial license files on disk). Splunk's own docs state
plainly that alerting/monitoring -- the scheduler that fires a saved
search's alert action (which is what would call a webhook the instant an
alert fires) -- is disabled on Free. Ad-hoc search and the REST API are
NOT disabled on Free. Everything in this poller uses oneshot search jobs
against /services/search/jobs, the same mechanism that survives. The
tradeoff is real and stated here rather than glossed over: this design
means "alert observed, up to POLL_INTERVAL_SECONDS late", not "reacted the
instant the alert fired". That is a materially weaker latency claim than a
live webhook, and it is the one this project can actually keep making after
the license converts.

Dedupe: each alert row in detection_lab_alerts carries a sid (the search
job ID of the run that produced it) plus a Splunk-assigned _cd (bucket:offset)
that is unique per event. This poller tracks _cd values it has already
handed to the playbooks in a local JSON state file, so re-running the poll
loop (or restarting it) never reprocesses an alert twice.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from models import Alert
from splunk_client import SplunkClient

STATE_FILE = Path(__file__).resolve().parent.parent / "data" / "poller_state.json"


def load_seen() -> set:
    if not STATE_FILE.exists():
        return set()
    with open(STATE_FILE) as fh:
        return set(json.load(fh))


def save_seen(seen: set) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w") as fh:
        json.dump(sorted(seen), fh, indent=2)


def fetch_alerts(client: SplunkClient, max_results: int = 200) -> list:
    """Pull rows from detection_lab_alerts, newest first, each tagged with
    its Splunk-assigned _cd so we can dedupe. Parses the flat
    'key=value key="quoted value"' _raw format action.logevent writes.
    """
    data = client.search(
        f"search index=detection_lab_alerts | head {max_results}",
        earliest="0",
        latest="now",
    )
    alerts = []
    for row in data.get("results", []):
        raw = row.get("_raw", "")
        fields = _parse_logevent_raw(raw)
        alerts.append(
            {
                "_cd": row.get("_cd"),
                "_time": row.get("_time"),
                "raw": raw,
                "fields": fields,
            }
        )
    return alerts


def _parse_logevent_raw(raw: str) -> dict:
    """Parse 'detection=X technique=Y search_name="..." result_count=N sid="..."'
    into a dict. This is the exact format action.logevent.param.event writes
    in savedsearches.conf, not a general log parser.
    """
    out = {}
    i = 0
    n = len(raw)
    while i < n:
        while i < n and raw[i] == " ":
            i += 1
        eq = raw.find("=", i)
        if eq == -1:
            break
        key = raw[i:eq]
        i = eq + 1
        if i < n and raw[i] == '"':
            end = raw.find('"', i + 1)
            val = raw[i + 1:end]
            i = end + 1
        else:
            sp = raw.find(" ", i)
            if sp == -1:
                sp = n
            val = raw[i:sp]
            i = sp
        out[key] = val
    return out


def new_alerts(client: SplunkClient, seen: set, max_results: int = 200) -> tuple:
    fetched = fetch_alerts(client, max_results=max_results)
    fresh = [a for a in fetched if a["_cd"] not in seen]
    result = []
    for a in fresh:
        f = a["fields"]
        result.append(
            Alert(
                detection=f.get("detection", ""),
                technique=f.get("technique", ""),
                search_name=f.get("search_name", ""),
                result_count=int(f.get("result_count", 0) or 0),
                sid=f.get("sid", ""),
                time=a["_time"],
                raw=a["raw"],
            )
        )
    return result, {a["_cd"] for a in fetched}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--loop", action="store_true", help="poll repeatedly on --interval instead of a single pass")
    ap.add_argument("--interval", type=int, default=300, help="seconds between polls if not --once")
    ap.add_argument("--max-results", type=int, default=200)
    ap.add_argument("--reset-state", action="store_true", help="forget all previously-seen alerts")
    args = ap.parse_args()

    if args.reset_state and STATE_FILE.exists():
        STATE_FILE.unlink()

    client = SplunkClient()
    seen = load_seen()

    def one_pass():
        fresh, all_cds = new_alerts(client, seen, max_results=args.max_results)
        for alert in fresh:
            print(json.dumps({
                "event": "new_alert",
                "detection": alert.detection,
                "technique": alert.technique,
                "result_count": alert.result_count,
                "sid": alert.sid,
                "time": alert.time,
            }))
        seen.update(all_cds)
        save_seen(seen)
        return fresh

    if not args.loop:
        fresh = one_pass()
        print(json.dumps({"event": "poll_complete", "new_count": len(fresh), "total_seen": len(seen)}))
        return 0

    while True:  # pragma: no cover - long-running mode, not exercised in tests
        fresh = one_pass()
        print(json.dumps({"event": "poll_complete", "new_count": len(fresh), "total_seen": len(seen)}))
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
