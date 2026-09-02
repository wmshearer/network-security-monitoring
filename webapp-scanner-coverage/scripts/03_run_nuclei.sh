#!/usr/bin/env bash
# Run nuclei against the local Juice Shop container only. Short, single run.
# Idempotent: overwrites its own output file each time it is rerun.
set -euo pipefail

TARGET="http://127.0.0.1:3000"
OUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/evidence/nuclei"
mkdir -p "$OUT_DIR"

if [[ "$TARGET" != "http://127.0.0.1:3000" ]]; then
  echo "refusing: target is not the local container" >&2
  exit 1
fi

nuclei \
  -u "$TARGET" \
  -jsonl -o "$OUT_DIR/nuclei-results.jsonl" \
  -stats \
  -timeout 5 \
  -rate-limit 50 \
  2>&1 | tee "$OUT_DIR/nuclei-run.log"

echo "nuclei run complete, results in $OUT_DIR"
