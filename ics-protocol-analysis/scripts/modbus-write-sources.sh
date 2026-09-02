#!/usr/bin/env bash
# The exact documented tshark filter from section 02, step 5 ("Trace every
# write function code back to its source"), condensed with sort -u for a
# readable screenshot. Wrapped in its own script because the embedded quotes
# and length break termcap.sh's echoed-command heredoc.
set -euo pipefail
cd "$(dirname "$0")/.."
tshark -r data/pcaps/4sics-151022.pcap \
  -Y "modbus.func_code==5 or modbus.func_code==6 or modbus.func_code==15 or modbus.func_code==16 or modbus.func_code==23" \
  -T fields -e ip.src -e ip.dst -e modbus.func_code | sort -u
