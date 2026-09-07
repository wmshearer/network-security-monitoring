#!/bin/bash
# Launch srsue detached from any controlling shell/session, so it survives
# the invoking shell exiting (needed because this process requires
# CAP_NET_ADMIN for its TUN device and so must run under sudo - see
# docs/4G-TIER.md). Used instead of a bare `sudo ... & disown` one-liner,
# which was observed to NOT reliably survive the parent shell exiting in
# this environment (see NOTES.md).
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$LAB_DIR/config/srsran" || exit 1
exec "$LAB_DIR/build/srsRAN_4G/build/srsue/src/srsue" ue.conf \
  > "$LAB_DIR/logs/srsran/ue.log" 2>&1
