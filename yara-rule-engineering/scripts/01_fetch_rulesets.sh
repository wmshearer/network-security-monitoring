#!/usr/bin/env bash
# Clone public YARA rulesets at runtime. Idempotent: re-running just fetches
# (git pull) if the clone already exists.
#
# We do NOT vendor rule files from Neo23x0/signature-base (Detection Rule
# License 1.1, not OSI open source) or elastic/protections-artifacts (Elastic
# License 2.0, source-available, not open source) into this repo. Both are
# cloned here, at runtime, into a gitignored directory, exactly like the
# GPLv2/MIT sets. Nothing under RULESETS_DIR is committed; see .gitignore.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RULESETS_DIR="$PROJECT_DIR/.rulesets"
EVIDENCE_DIR="$PROJECT_DIR/evidence"

mkdir -p "$RULESETS_DIR" "$EVIDENCE_DIR"

declare -A REPOS=(
  [yara-rules]="https://github.com/Yara-Rules/rules.git"
  [reversinglabs]="https://github.com/reversinglabs/reversinglabs-yara-rules.git"
  [signature-base]="https://github.com/Neo23x0/signature-base.git"
  [protections-artifacts]="https://github.com/elastic/protections-artifacts.git"
)

LOG="$EVIDENCE_DIR/01_fetch_rulesets.log"
: > "$LOG"

for name in "${!REPOS[@]}"; do
  url="${REPOS[$name]}"
  dest="$RULESETS_DIR/$name"
  echo "=== $name ($url) ===" | tee -a "$LOG"
  if [ -d "$dest/.git" ]; then
    echo "already cloned, pulling latest" | tee -a "$LOG"
    git -C "$dest" pull --ff-only 2>&1 | tee -a "$LOG"
  else
    git clone --depth 1 "$url" "$dest" 2>&1 | tee -a "$LOG"
  fi
  echo "commit: $(git -C "$dest" rev-parse HEAD)" | tee -a "$LOG"
  echo "" | tee -a "$LOG"
done

echo "Done. Rulesets in $RULESETS_DIR" | tee -a "$LOG"

# Record what licence file (if any) each repo actually ships, verbatim,
# rather than trusting the table in the task brief without checking on disk.
LICENSE_EVIDENCE="$EVIDENCE_DIR/ruleset_licenses.txt"
: > "$LICENSE_EVIDENCE"
for name in "${!REPOS[@]}"; do
  dest="$RULESETS_DIR/$name"
  echo "=== $name ===" >> "$LICENSE_EVIDENCE"
  found=0
  for f in LICENSE LICENSE.txt LICENSE.md license.txt LICENSE-DRL.txt; do
    if [ -f "$dest/$f" ]; then
      echo "--- $f ---" >> "$LICENSE_EVIDENCE"
      cat "$dest/$f" >> "$LICENSE_EVIDENCE"
      echo "" >> "$LICENSE_EVIDENCE"
      found=1
    fi
  done
  if [ "$found" -eq 0 ]; then
    echo "(no LICENSE/LICENSE.txt/LICENSE.md file found at repo root)" >> "$LICENSE_EVIDENCE"
  fi
  echo "" >> "$LICENSE_EVIDENCE"
done
echo "Wrote $LICENSE_EVIDENCE"
