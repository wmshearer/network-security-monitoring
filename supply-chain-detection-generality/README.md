# Does supply chain detection content generalize past the incident it was written for?

## The finding, up front

Of the 29 supply-chain-relevant detections in Splunk's `security_content`
repository (28 tagged with ATT&CK's Supply Chain Compromise technique T1195,
plus the SUNBURST detection, which is not tagged T1195 at all, see below),
**23 (79%) are behavioral: they key on the mechanics of the technique and
would fire on a future attack that uses the same technique with different
file names, different domains, and a different vendor. Only 6 (21%) are
incident-bound: they hardcode an indicator from one specific incident and
would not fire on a different attack using the same technique.**

This reverses the pessimistic hypothesis this project set out to test. Going
in, the visible examples (SUNBURST's hardcoded DLL name, Shai-Hulud's
hardcoded workflow file names) suggested most of this content might be
frozen to the incident it was written for. Reading all 29 detections'
actual search logic shows the opposite is true for the majority.

## What a supply chain attack, an IOC, and a behavioral detection are

- **Supply chain attack**: an attacker compromises something you trust, an
  update mechanism, a build tool, a widely used code library, so that the
  malicious code arrives through a channel you already trusted and did not
  expect to inspect. SolarWinds shipping a trojanized Orion update to its own
  customers is the canonical example.
- **IOC (indicator of compromise)**: a specific, concrete fact about one
  attack, a file name, a file hash, a domain name, a registry key value. IOCs
  are cheap to write detections against and cheap for the next attacker to
  avoid, because they only describe what one campaign happened to do.
- **Detection rule**: a saved search (in Splunk, an SPL query) that a
  security team runs against its logs to surface a specific kind of
  suspicious activity.
- **Behavioral detection**: a detection rule that matches a technique's
  mechanics (a Python process phoning home during a package build, a file
  created under `.github/workflows/`) rather than one incident's IOCs. It
  survives the next attacker changing every literal detail of their attack,
  as long as the underlying mechanism stays the same.
- **ATT&CK technique**: a named, cataloged method of attack in MITRE's
  ATT&CK framework (for example T1195, Supply Chain Compromise). Detections
  are commonly tagged with the technique ID they are meant to catch.

## Why this project exists (and why it isn't "build new supply chain detections")

Splunk's `security_content` already ships production-status detections for
recent incidents (Shai-Hulud/npm, 3CX, malicious Python packages). Building
new detections for those incidents would be redundant with content that
already exists and is already good. The open question nobody publishes is
about the **shape** of that existing content: is it durable past the
incident that motivated it, or not? This project reads the YAML, classifies
every detection by hand against a published rubric, and reports the count.

## How the classification was done, and why not a regex

A first attempt used a one-line regex over the whole YAML file, looking for
`.dll`, `.exe`, domain-like strings, and hashes. It produced a false
positive: GitHub audit-log detections got flagged as incident-bound because
their API action names or reference URLs contain `.com`. That is exactly the
failure mode this project exists to catch, a coarse pattern match cannot
distinguish an attacker-chosen indicator from a platform's own vocabulary.

This project uses **hand classification against a published, two-question
rubric**, with every call justified by the exact `search:` fragment it rests
on. See `rubric/RUBRIC.md` for the rubric and `rubric/calls.csv` for every
one of the 29 per-detection calls. Disagree with a call by reading the cited
search fragment against the file in `security_content` yourself; that is the
point of publishing it this way instead of a single opaque score.

## What was verified directly, and how

- **Splunk `security_content` LICENSE**: read directly, Apache License 2.0.
- **Splunk `attack_data` LICENSE**: read directly, Apache License 2.0.
- **CVE-2024-3094 (XZ Utils)**: confirmed against the NVD REST API
  (`services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094`), which
  describes malicious code in xz upstream tarballs starting at version
  5.6.0. **security_content has zero detections referencing it**, confirmed
  by direct grep across `detections/` and `stories/`.
- **CVE-2023-29059 (3CX)**: confirmed against the same NVD API, which
  describes embedded malicious code in 3CX DesktopApp through 18.12.416,
  exploited in the wild in March 2023. This CVE is cited directly inside
  three detections in `security_content`
  (`hunting_3cxdesktopapp_software.yml`, `windows_vulnerable_3cx_software.yml`,
  `3cx_supply_chain_attack_network_indicators.yml`).
- **Codecov**: zero detections in `security_content`, confirmed by direct
  grep.
- **ATT&CK technique IDs** T1195, T1195.001, T1195.002, T1195.003, T1554,
  T1072, and (for the SUNBURST anomaly below) T1203: all confirmed by
  fetching the live page title at `attack.mitre.org/techniques/<id>/`.

## A data-quality finding along the way

The SUNBURST detection
(`detections/endpoint/sunburst_correlation_dll_and_network_event.yml`) is
the only detection in the repository built specifically around the SUNBURST
campaign, and it is `status: experimental`. It is tagged `mitre_attack_id:
T1203` (Exploitation for Client Execution), not any T1195 sub-technique. A
search for T1195-tagged content alone would miss it entirely, and it does
not appear in the 28-file T1195 population this project started from. It
was added to this project's population manually, verified by direct read,
because it is unambiguously a supply chain detection by name, description,
and its `NOBELIUM Group` analytic story. This looks like a tagging gap in
the source repository worth reporting upstream, not a finding about
detection generality.

## GUI evidence: what happened, plainly

The task prioritized showing a detection running in Splunk Web against real
telemetry. That was attempted: the local Splunk instance was up and its CLI
session was authenticated, and two real Sysmon datasets from `attack_data`
(Shai-Hulud/npm and 3CX) were ingested into a lab index. Getting the raw XML
Sysmon logs to parse into one event per line required a `props.conf` change,
which required a `splunk restart`, which invalidated the only authenticated
session available to this task. The admin password is intentionally not
stored anywhere retrievable (see the director's own memory on why: an old
password was found hardcoded in five files across three repos and was
deliberately removed rather than re-stored). Re-authentication was not
possible without a human supplying it.

Per this project's own instructions, that is disclosed plainly rather than
worked around with a fabricated screenshot. See `evidence/gui/README.md` for
the full sequence. The fallback delivered instead:
`scripts/04_replay_detections_against_telemetry.py` re-implements two
incident-bound detections' exact match conditions in Python and runs them
directly against the same raw Sysmon logs Splunk would have searched,
showing each detection fires on its own incident's data and produces zero
matches against a different incident's data. That run, and the
classification tally, are captured as real terminal screenshots (not
Splunk Web) using `termcap.sh`, a tool that photographs an actual terminal
window rather than rendering a fake one.

## Layout

- `README.md` — this file.
- `FINDINGS.md` — every number traced to a named evidence file.
- `rubric/RUBRIC.md`, `rubric/calls.csv` — the classification method and
  every per-detection call.
- `scripts/` — numbered, idempotent, read-only scripts against `_corpora`.
- `evidence/` — raw script output, never hand-edited.
- `evidence/gui/` — the real terminal captures and the Splunk-evidence
  postmortem.
- `charts/` — the classification breakdown chart and the script that made it.
- `tests/` — pytest, skips (does not fail) when a corpus is absent.

## Caveats

- Every classification call is a judgment made by one reviewer reading the
  YAML on 2026-08-28. See `rubric/RUBRIC.md` for exactly how, and disagree
  per row if you read a `search:` field differently.
- "Behavioral" is not a claim that a detection catches every future attack
  using that technique, only that it is not arithmetically tied to one
  incident's literal indicators. A behavioral detection can still miss an
  attacker who avoids the specific pattern it keys on (a different file
  path, a different registry key, a different API action).
- The core population (29) is deliberately narrower than every detection
  that mentions "supply chain" anywhere in its `analytic_story` tags. A
  looser search (any detection tagged with a story whose name contains
  "Supply Chain," or matching general credential/OAuth/persistence
  detections that list a supply-chain story among several) pulls in
  dozens of general-purpose detections (Azure AD, O365, PowerShell) that
  are not specific to supply chain compromise. That looser population was
  not classified; scoping to the 28 T1195-tagged detections plus SUNBURST
  was a deliberate choice to keep every classified row's supply-chain
  relevance unambiguous. See `FINDINGS.md` for the file list that was
  considered and excluded.
