# Classification rubric: incident-bound vs. behavioral

## Why hand classification, not a regex

A first attempt used a one-line regex looking for `.dll`, `.exe`, domain-like strings,
and hashes in the `search` field. It produced a false positive: it flagged GitHub
audit-log detections as incident-bound because their SPL references API action names
like `repository_vulnerability_alerts.disable`, and one contains the literal
`3cx[.]com` inside `known_false_positives` prose, not in the search logic. A regex
over the whole YAML cannot tell the difference between an attacker-chosen indicator
and a platform's own vocabulary.

Splunk's own detection content is heterogeneous in structure: `tstats` over CIM data
models, raw `sysmon` macro searches, and API-audit-log searches all express "what to
match" differently. There is no single syntactic pattern across all three that
distinguishes an attacker artifact from a legitimate field.

This rubric is a **hand classification with a documented question per detection**.
Every call in `rubric/calls.csv` is a judgment made by reading the `search:` field
of the YAML directly (not the description, not the title) and asking the two
questions below. A reader who disagrees with a specific call can look up that
detection's `search:` field in `security_content` and re-derive their own answer;
the rubric is falsifiable per row, which a black-box automated score would not be.

## The two questions, asked of the `search:` field only

**Q1. Does the search hardcode a value that only exists because of one specific
incident** (a malicious file's exact name, a C2 domain that one campaign registered,
a vulnerable software's process name, a lookup table of IOCs built for that
incident)?

**Q2. Would the search still fire if a different threat actor used the same ATT&CK
technique against a different product, with different file names, different
domains, and different code?**

| Answer to Q1 | Answer to Q2 | Class |
|---|---|---|
| Yes | No | **incident-bound** |
| No | Yes | **behavioral** |
| Yes, but the value is platform vocabulary, not attacker-chosen (see below) | Yes | **behavioral** |

## The platform-vocabulary exception (why GitHub audit-log detections are not incident-bound)

A search like `action=repository_vulnerability_alerts.disable` looks like a hardcoded
string, the same shape as `ImageLoaded=*SolarWinds.Orion.Core.BusinessLayer.dll`. The
rubric treats them differently because of who controls the string:

- `SolarWinds.Orion.Core.BusinessLayer.dll` is a name **the attacker chose** when they
  trojanized that specific DLL. A different attacker trojanizing a different DLL in a
  different product produces a different string. The search cannot follow.
- `repository_vulnerability_alerts.disable` is a name **GitHub defined** for its audit
  log, before any attack happened, and it names an administrative action (disabling
  Dependabot) that any attacker who wants to suppress vulnerability alerts must invoke
  through GitHub's own API, regardless of which package, which repo, or which supply
  chain incident this is. The detection generalizes to the next attacker who disables
  Dependabot for the same underlying reason.

The dividing line is **who authored the string that appears in the search**: the
attacker (incident-bound) or the platform/vendor whose product is being abused
(behavioral, because the platform's action vocabulary does not change per incident).

## Third category: mixed

A detection can combine an incident-specific string with a generic structural
pattern, or hardcode a value from one incident's public reporting as a "known
example" while the surrounding logic is generic. Marked **mixed** with a note on
which part is which.

## What this rubric does not claim

- It is not a measure of detection quality, false-positive rate, or how good the
  underlying logic is at catching the technique it targets.
- "Behavioral" does not mean "will catch every future supply chain attack." A
  behavioral detection can still miss an attacker who avoids the specific file path,
  registry key, or API action pattern it keys on. It only means the detection is not
  arithmetically tied to one incident's literal indicators.
- Every row is a judgment call by one reviewer reading the YAML on 2026-08-28. Another
  reviewer could reasonably classify a "mixed" case differently. Disagree by reading
  the cited `search:` field yourself.

See `rubric/calls.csv` for the per-detection table (file, class, the exact search
fragment the call rests on, and a one-line reason).
