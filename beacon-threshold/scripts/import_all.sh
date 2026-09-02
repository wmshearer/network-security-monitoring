#!/usr/bin/env bash
# Import every Zeek log set into its own RITA database.
#
# Each capture configuration becomes a separate database so the scores can be
# compared side by side without one dataset's traffic influencing another's
# prevalence or first-seen modifiers.
set -uo pipefail

LOGS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../data/logs" && pwd)"
RITA=/usr/local/bin/rita
OUT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/data/csv"
mkdir -p "$OUT"

# RITA database names must start with a lowercase letter, contain only
# alphanumerics and underscores, and not end with one. The directory names use
# a trailing _1H/_24H and contain "var", so they are mapped rather than reused.
dbname() {
    echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's/_var//; s/[^a-z0-9_]/_/g; s/_\+/_/g; s/_$//'
}

for d in "$LOGS_DIR"/*/; do
    set_name="$(basename "$d")"
    db="$(dbname "$set_name")"

    echo "=== $set_name -> $db ==="
    if sudo "$RITA" import -d "$db" -l "$d" >/dev/null 2>&1; then
        echo "  imported"
    else
        echo "  IMPORT FAILED"
        continue
    fi

    # Strip the wrapper's docker-compose chatter and the "Viewing database"
    # banner so the file starts at the CSV header row.
    if sudo "$RITA" view --stdout "$db" 2>/dev/null \
        | grep -vE '^ (Container|Network|Volume)|^Viewing database:' \
        > "$OUT/${set_name}.csv"; then
        rows=$(( $(wc -l < "$OUT/${set_name}.csv") - 1 ))
        echo "  exported $rows rows"
    else
        echo "  EXPORT FAILED"
    fi
done

echo "=== done ==="
ls -1 "$OUT" | wc -l
