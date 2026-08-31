# Third-party content

This project analyses event telemetry drawn from three public corpora. The
telemetry is forensic log data recording attacks that were run by those
projects, not runnable attack tooling.

## EVTX-ATTACK-SAMPLES

- Source: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- Licence: GNU General Public License v3.0
- Full licence text included here as `LICENSE-GPL-3.0`

Some records derived from this corpus contain base64 blobs captured inside
PowerShell `ScriptBlockText` fields. Those are log records of what was executed
during the original sample capture. They are retained unmodified because
truncating them would change what a detection rule sees, which is the thing this
project measures.

## attack_data (Splunk)

- Source: https://github.com/splunk/attack_data
- Licence: Apache License 2.0

## EVTX-to-MITRE-Attack

- Source: https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack
- Licence: CC0 1.0 Universal
