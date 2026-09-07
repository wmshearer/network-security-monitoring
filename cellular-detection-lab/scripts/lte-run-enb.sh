#!/bin/bash
# Launch srsenb detached from any controlling shell/session (see
# scripts/lte-run-ue.sh for why this wrapper exists instead of a bare
# `... & disown` one-liner).
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$LAB_DIR/config/srsran" || exit 1
exec "$LAB_DIR/build/srsRAN_4G/build/srsenb/src/srsenb" enb.conf \
  > "$LAB_DIR/logs/srsran/enb.log" 2>&1
