"""End-to-end run: poll for new alerts, run both playbooks on each, log
every record, and print a measured summary. This is the single entry
point that ties poller.py + playbook_enrich.py + playbook_response.py
together; there is no separate SOAR engine process, see README.md
"Platform decision" for why.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from playbook_enrich import record_to_dict as enrich_to_dict, run_playbook
from playbook_response import recommend, record_to_dict as response_to_dict
from poller import load_seen, new_alerts, save_seen
from splunk_client import SplunkClient

LOG_DIR = Path(__file__).resolve().parent.parent / "evidence" / "runs"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--max-results", type=int, default=500, help="max alert rows to pull from Splunk")
    ap.add_argument("--reset-state", action="store_true", help="reprocess all alerts, ignoring poller state")
    ap.add_argument("--out", help="write the full JSON run record here (default: evidence/runs/<timestamp>.json)")
    args = ap.parse_args()

    start = time.time()
    client = SplunkClient()

    seen = set() if args.reset_state else load_seen()
    fresh, all_cds = new_alerts(client, seen, max_results=args.max_results)

    enrich_records = []
    response_records = []
    extraction_failures = 0

    for alert in fresh:
        rec, events = run_playbook(client, alert)
        enrich_records.append(rec)

        target_hint = "unknown"
        if events:
            ev = events[0]
            target_hint = ev.get("Hostname") or ev.get("dest") or ev.get("Image") or "unknown"
        else:
            extraction_failures += 1

        action = recommend(alert.detection, alert.technique, rec.verdict, target_hint)
        response_records.append(action)

    seen.update(all_cds)
    save_seen(seen)

    elapsed = time.time() - start

    verdict_counts = {}
    for rec in enrich_records:
        verdict_counts[rec.verdict.label] = verdict_counts.get(rec.verdict.label, 0) + 1

    action_counts = {}
    for a in response_records:
        action_counts[a.action] = action_counts.get(a.action, 0) + 1

    indicator_counts = {}
    total_indicators = 0
    for rec in enrich_records:
        total_indicators += len(rec.indicators)
        for i in rec.indicators:
            indicator_counts[i.kind] = indicator_counts.get(i.kind, 0) + 1

    sources_called = {}
    sources_skipped = {}
    for rec in enrich_records:
        for c in rec.source_calls:
            bucket = sources_called if c.called else sources_skipped
            bucket[c.source] = bucket.get(c.source, 0) + 1

    summary = {
        "alerts_polled_total": len(all_cds),
        "alerts_new_this_run": len(fresh),
        "extraction_failures": extraction_failures,
        "indicators_extracted_total": total_indicators,
        "indicators_by_kind": indicator_counts,
        "verdicts": verdict_counts,
        "simulated_actions": action_counts,
        "elapsed_seconds": round(elapsed, 3),
        "sources_called_count": sources_called,
        "sources_skipped_count": sources_skipped,
    }

    run_record = {
        "summary": summary,
        "enrichment_records": [enrich_to_dict(r) for r in enrich_records],
        "simulated_actions": [response_to_dict(a) for a in response_records],
    }

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    out_path = args.out or str(LOG_DIR / f"run_{int(start)}.json")
    with open(out_path, "w") as fh:
        json.dump(run_record, fh, indent=2)

    print(json.dumps(summary, indent=2))
    print(f"full record written to {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
