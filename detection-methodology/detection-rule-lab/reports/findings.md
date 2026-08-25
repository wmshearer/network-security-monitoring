# Sigma rule scoring against a labeled corpus

## What was measured

Every rule in Zircolite's Windows/Sysmon ruleset was run against two
separately-labeled bodies of Windows telemetry, and each rule's matches were
counted per class.

|  | Value |
|---|---|
| Sigma rules evaluated | 2,691 |
| Malicious events | 834,226 |
| Benign events | 110,095 |
| Attack captures | 7 |
| Benign source | Windows Server 2022 baseline, 3 channels |

## Headline

**135 of 2,691 rules (5.0%) fired at all. 2,556 (95.0%) never matched anything.**

- 131 rules fired only on attack data
- 4 rules fired on the benign baseline
- 1 rules fired on benign data and caught nothing

### The silence is not a corpus-coverage artifact

The obvious explanation for 90%+ silence is that the corpus lacks the event
types those rules need. That was tested and is not what happened:
**94.6% of the ruleset targets EventIDs the corpus actually contains.**
Those rules saw eligible events and did not match.

## Rules that fired only on attacks

These matched malicious activity and never touched the benign baseline.

| Rule | Severity | Attack hits | Benign hits | ATT&CK | Author |
|---|---|---|---|---|---|
| Alternate PowerShell Hosts - PowerShell Module | medium | 4,124 | 0 | T1059.001 | Roberto Rodriguez @Cyb3rWard0g |
| PowerShell Decompress Commands | informational | 620 | 0 | T1140 | Roberto Rodriguez (Cyb3rWard0g), OTR (Op |
| User Logoff Event | informational | 534 | 0 | T1531 | frack113 |
| Potential Binary Or Script Dropper Via PowerShell | medium | 293 | 0 | - | frack113, Nasreddine Bencherchali (Nextr |
| Suspicious Svchost Process Access | high | 74 | 0 | T1685.001 | Tim Burrell |
| HackTool - SysmonEnte Execution | high | 62 | 0 | T1685.001 | Florian Roth (Nextron Systems) |
| New Root or CA or AuthRoot Certificate to Store | medium | 32 | 0 | T1490 | frack113 |
| New PowerShell Instance Created | informational | 29 | 0 | T1059.001 | Roberto Rodriguez (Cyb3rWard0g), OTR (Op |
| Potentially Suspicious AccessMask Requested From LSASS | medium | 27 | 0 | T1003.001 | Roberto Rodriguez, Teymur Kheirkhabarov, |
| Windows Defender Exclusions Added - Registry | medium | 26 | 0 | T1685 | Christian Burkard (Nextron Systems) |
| Password Policy Enumerated | medium | 23 | 0 | T1201 | Zach Mathis |
| Potential Remote PowerShell Session Initiated | high | 22 | 0 | T1021.006, T1059.001 | Roberto Rodriguez @Cyb3rWard0g |
| Remote PowerShell Sessions Network Connections (WinRM) | high | 22 | 0 | T1059.001 | Roberto Rodriguez @Cyb3rWard0g |
| Suspicious Process Discovery With Get-Process | low | 20 | 0 | T1057 | frack113 |
| Unsigned DLL Loaded by Windows Utility | medium | 19 | 0 | T1218.010, T1218.011 | Swachchhanda Shrawan Poudel |
| Non Interactive PowerShell Process Spawned | low | 17 | 0 | T1059.001 | Roberto Rodriguez @Cyb3rWard0g (rule), o |
| First Time Seen Remote Named Pipe | high | 16 | 0 | T1021.002 | Samir Bousseaden |
| Suspicious PowerShell Download - Powershell Script | medium | 16 | 0 | T1059.001 | Florian Roth (Nextron Systems) |
| Suspicious PowerShell Get Current User | low | 16 | 0 | T1033 | frack113 |
| Elevated System Shell Spawned From Uncommon Parent Locatio | medium | 15 | 0 | T1059 | frack113, Tim Shelton (update fp) |
| Office Autorun Keys Modification | medium | 13 | 0 | T1547.001 | Victor Sergeev, Daniil Yugoslavskiy, Gle |
| PUA - Sysinternal Tool Execution - Registry | low | 13 | 0 | T1588.002 | Markus Neis |
| PUA - Sysinternals Tools Execution - Registry | medium | 13 | 0 | T1588.002 | Nasreddine Bencherchali (Nextron Systems |
| PSScriptPolicyTest Creation By Uncommon Process | medium | 12 | 0 | - | Nasreddine Bencherchali (Nextron Systems |
| Malicious PowerShell Commandlets - PoshModule | high | 11 | 0 | T1059.001, T1069, T1069.001 | Nasreddine Bencherchali (Nextron Systems |
| Malicious PowerShell Keywords | medium | 11 | 0 | T1059.001 | Sean Metcalf (source), Florian Roth (Nex |
| Suspicious PowerShell Invocations - Specific | high | 11 | 0 | T1059.001 | Florian Roth (Nextron Systems), Jonhnath |
| Potential Execution of Sysinternals Tools | low | 10 | 0 | T1588.002 | Markus Neis |
| PowerShell Module File Created | low | 10 | 0 | - | Nasreddine Bencherchali (Nextron Systems |
| Potential Defense Evasion Via Raw Disk Access By Uncommon  | low | 9 | 0 | T1006 | Teymur Kheirkhabarov, oscd.community |

## Rules that fired on the benign baseline

Every rule in the ruleset that matched ordinary Windows activity.

| Rule | Severity | Attack hits | Benign hits | Precision | Author |
|---|---|---|---|---|---|
| Modification of IE Registry Settings | low | 0 | 56 | 0.00 | frack113 |
| Suspicious High IntegrityLevel Conhost Legacy Option | informational | 10 | 2 | 0.83 | frack113 |
| Disable Windows Defender Functionalities Via Registry Keys | high | 2 | 2 | 0.50 | AlertIQ, Ján Trenčanský, frack113, Nasre |
| RunMRU Registry Key Deletion - Registry | high | 2 | 2 | 0.50 | Swachchhanda Shrawan Poudel (Nextron Sys |

## Limitations

1. **These are counts on one corpus, not rates.** The benign baseline is a
   single Windows Server 2022 host. A rule that is quiet here may be noisy on a
   workstation fleet, a developer machine, or a domain controller. Nothing here
   supports a claim about any rule's false-positive rate in general.
2. **Absence of a match is not evidence a rule is bad.** A rule that never fired
   may target behaviour this corpus never performed. Silence measures the
   corpus and the rule together, not the rule alone.
3. **The attack corpus is finite and specific.** It covers OTRF atomic captures
   plus the APT29 ATT&CK Evals scenarios. Coverage against those attacks says
   nothing about coverage against attacks not represented here.
4. **Event counts are not alert counts.** A rule matching 4,000 events would not
   produce 4,000 alerts in a real SIEM, which would aggregate them. Counts here
   measure match volume, not analyst workload.
5. **One ruleset, one engine.** Results are for Zircolite's packaged Windows
   ruleset. A different Sigma distribution or backend may convert rules
   differently.

## Provenance and licensing

- Detection rules: SigmaHQ, **Detection Rule License 1.1**, which requires
  per-rule author attribution. Authors are named in every table above.
- Execution engine: Zircolite (wagga40), LGPL.
- Attack telemetry: OTRF Security-Datasets, MIT.
- Benign telemetry: NextronSystems evtx-baseline, Apache-2.0.

Run is reproducible: `python3 scripts/run_scoring.py`.