#!/usr/bin/env bash
# Split an EVTX-exported plain-text security log into one file per event
# (splitting on the "MM/DD/YYYY HH:MM:SS PM" line that starts each record
# in this corpus's *-security.log text export format), then run YARA once
# per event so a match cannot spuriously combine text from two different
# events. Idempotent: overwrites its own output directory each run.
#
# Usage: 03_run_yara_per_event.sh <input .log> <output-dir> <yara-rule-file>
set -euo pipefail

IN="$1"
OUTDIR="$2"
RULE="$3"

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

python3 - "$IN" "$OUTDIR" <<'PYEOF'
import re, sys, pathlib
in_path, outdir = sys.argv[1], pathlib.Path(sys.argv[2])
text = pathlib.Path(in_path).read_text(errors="replace")
# Each event starts with a line like "02/11/2022 07:26:42 PM"
parts = re.split(r"(?=^\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} [AP]M$)", text, flags=re.MULTILINE)
n = 0
for p in parts:
    if not p.strip():
        continue
    n += 1
    (outdir / f"event_{n:05d}.txt").write_text(p)
print(f"split into {n} per-event files under {outdir}")
PYEOF

echo "=== running YARA per-event ==="
for f in "$OUTDIR"/*.txt; do
    out=$(yara -s "$RULE" "$f" 2>&1)
    if [[ -n "$out" ]]; then
        echo "--- $f ---"
        echo "$out"
    fi
done
