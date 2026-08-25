#!/usr/bin/env bash
# Ingests the three ActiveMQ/LockBit XmlWinEventLog files into the
# ir_activemq_lockbit Splunk index.
#
# Prerequisite: the Splunk app at
# /home/kali/splunk/etc/apps/ir_activemq_lockbit/local/{indexes,props,app}.conf
# and metadata/local.meta must already exist (checked into this repo under
# splunk_app/ as a copy for reference; the live copy lives under $SPLUNK_HOME
# because that is where splunkd reads config from, not inside this project
# repo). Restart splunkd after any props.conf change before ingesting, since
# TIME_PREFIX/TIME_FORMAT/TZ are read at startup, not per-search.
#
# Usage: SPLUNK_HOME=/home/kali/splunk SPLUNK_AUTH=admin:yourpass ./ingest.sh /path/to/dataset/dir

set -euo pipefail

SPLUNK_HOME="${SPLUNK_HOME:-/home/kali/splunk}"
SPLUNK_AUTH="${SPLUNK_AUTH:?Set SPLUNK_AUTH=user:pass before running}"
DATA_DIR="${1:?Usage: $0 /path/to/ActiveMQ_exploit_Lockbit_Ransomware}"
INDEX=ir_activemq_lockbit

oneshot() {
  local file="$1" source_name="$2"
  "$SPLUNK_HOME/bin/splunk" add oneshot "$file" \
    -index "$INDEX" \
    -sourcetype XmlWinEventLog \
    -rename-source "$source_name" \
    -auth "$SPLUNK_AUTH"
}

oneshot "$DATA_DIR/windows-sysmon.log"     'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational'
oneshot "$DATA_DIR/windows-security.log"   'XmlWinEventLog:Security'
oneshot "$DATA_DIR/windows-powershell.log" 'XmlWinEventLog:Microsoft-Windows-PowerShell/Operational'

echo "Oneshot ingest submitted. Poll with:"
echo "  $SPLUNK_HOME/bin/splunk search '| tstats count where index=$INDEX' -auth \$SPLUNK_AUTH"
