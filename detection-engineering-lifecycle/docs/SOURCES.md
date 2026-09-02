# Sources

Every framework cited in `docs/LIFECYCLE.md`, with publisher, exact title, URL, and a
verification marking carried over from the research brief this project used
(`.research/incoming/wave4-program-frameworks.md`, AREA 2). The marking scheme:

- **PRIMARY**: the source document was fetched and read directly, and quoted text is
  verbatim from that fetch.
- **SECONDARY**: the source was not fetched directly; the claim comes from a search
  summary or a reputable third party describing the source. Treated as likely accurate
  but not independently confirmed.
- **GAP**: could not verify at all. Reported as an open question, not asserted.

## Detection engineering lifecycle framing

1. **Sigma Rules Specification** (status field). Publisher: SigmaHQ. File:
   `specification/sigma-rules-specification.md`.
   URL: https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md
   **PRIMARY.** The five status values and their definitional text quoted in
   `docs/LIFECYCLE.md` are verbatim from this spec.

2. **Palantir Alerting and Detection Strategy (ADS) Framework.** Publisher: Palantir.
   File: `ADS-Framework.md`.
   URL: https://github.com/palantir/alerting-detection-strategy-framework/blob/master/ADS-Framework.md
   Companion post: https://blog.palantir.com/alerting-and-detection-strategy-framework-52dc33722df2
   **PRIMARY.** The 10 section names and order are taken directly from this document.
   No formal publication date is visible in the fetched content; the repo has been
   referenced in practitioner writing since roughly 2016-2017.

3. **TaHiTI (Targeted Hunting integrating Threat Intelligence).** Publisher:
   Betaalvereniging Nederland (Dutch Payments Association) / NVB. Title: "TaHiTI: A
   Threat Hunting Methodology" whitepaper.
   URL: https://www.nvb.nl/media/rygbrwew/def-tahiti-threat-hunting-methodology.pdf
   **PRIMARY.** The three phase names (Initiate, Hunt, Finalize), the Hunt sub-steps
   (Define/Refine, Execute), and the three hypothesis-validation outcomes (proven,
   disproven, inconclusive) are confirmed by direct extraction of the PDF text.

4. **Splunk PEAK Threat Hunting Framework.** Publisher: Splunk (SURGe team). Title:
   "Introducing the PEAK Threat Hunting Framework."
   URL: https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html
   **SECONDARY.** Read via a search-engine summary of Splunk's own post, not
   independently re-fetched. The summary is internally consistent and directly quotes
   Splunk's own framing, so it is treated as likely accurate, but the phase
   descriptions in this document should not be read as verbatim quotation from Splunk.

5. **MITRE ATT&CK / ATT&CK Navigator.** Publisher: MITRE.
   Framework: https://attack.mitre.org
   Navigator: https://github.com/mitre-attack/attack-navigator
   **GAP for structural claims.** Neither attack.mitre.org nor the Navigator repo was
   fetched directly in the research pass this document relies on. The criticism that
   coverage counts are not the same as defensive effectiveness is reported here as
   widely-held practitioner opinion (consistent across AttackIQ, CardinalOps, and
   independent practitioner writing found in that research pass), not as a claim
   sourced to one paper or to MITRE itself.

6. **"Detection as Code."** Term and practice, origin contested.
   - Anton Chuvakin, "Can We Have 'Detection as Code'?", Medium, September 2020.
     URL: https://medium.com/anton-on-security/can-we-have-detection-as-code-96f869cfdc79
     **GAP.** The page returned HTTP 403 on direct fetch attempt; its content is known
     only via a search snippet ("a more systematic, flexible and comprehensive approach
     to threat detection inspired by software development"). The article's full text
     was not read.
   - Patrick Bareiss and Jose Hernandez (Splunk), "Detection as Code: Detection
     Development Using CI/CD," RSA Conference APJ 2020.
     URL: https://www.rsaconference.com/apj/agenda/detection-as-code-detection-development-using-cicd
     **SECONDARY.** Found via search, not fetched directly; talk content beyond the
     title was not verified.
   - No single first use could be established. Both sources date to 2020 and neither
     can be shown to precede the other with the material gathered. This document
     reports the origin as contested and does not assign priority to either one.

## SRE / error-budget framing (borrowed, not a named security practice)

7. **Google SRE Book, Chapter 4, "Service Level Objectives."** Publisher: Google /
   O'Reilly, freely hosted.
   URL: https://sre.google/sre-book/service-level-objectives/
   **PRIMARY.** SLI, SLO, SLA, and error-budget definitions in `docs/LIFECYCLE.md` are
   quoted or closely paraphrased from this chapter. This chapter is about production
   service reliability, not security. The application of "error budget" to false
   positives in a detection program is this document's own analogy, stated as such
   where it appears, and is not something Google's book itself proposes.

## Explicitly not found: a named false-positive-budget / alert-quality-SLO practice

The research pass behind this document looked for a formally named, published
practice specifically covering "false positive budgets" or "alert quality SLOs" in a
security-operations context (as opposed to ad hoc vendor blog usage) and did not find
one. This is a **GAP**, not a finding. `docs/LIFECYCLE.md` is explicit that its
false-positive-budget section is an adaptation of the SRE error-budget idea above,
not a citation of an established named security practice.

## Portfolio projects cited as the worked example and supporting evidence

These are not external frameworks. They are this portfolio's own prior work, cited
for their measured numbers, which were re-checked against each project's own README
and docs before use here:

- `llm-abuse-detection`: 7-rule detector: precision 99.7%, recall 71.8%, F1 83.5% on
  1,405 malicious + 1,405 benign prompts (2,810 total). See
  `../llm-abuse-detection/README.md` and `../llm-abuse-detection/src/rules.py`.
- `sql-vs-python-detection`: same 7 rules re-implemented in SQL and Python, scored on
  the same 2,810 prompts, zero per-prompt disagreements between the two
  implementations. `leak-extraction` fires zero times in either implementation. See
  `../sql-vs-python-detection/docs/FINDING.md`.
- `sql-threat-hunting`: beaconing-by-jitter query ranks a benign Philips Hue bridge
  (jitter 0.0000) above the Torii botnet (jitter 0.028-0.071); precision 50% at the
  obvious threshold, 0% once tightened. See `../sql-threat-hunting/docs/FINDING.md`.
- `cib-detection`: co-timing signal scores AUC 0.592 against other malicious
  operations, collapsing to AUC 0.534 against a benign control (Caverlee 2011
  honeypot dataset), because it was measuring shared time zone rather than
  coordination. See `../cib-detection/docs/FINDING.md`.
- `atlas-coverage-map`: 7 of 101 MITRE ATLAS techniques covered (6.9%), 9 of 16
  tactics touched, computed by walking source text through a keyword mapping rather
  than hand-asserted. See `../atlas-coverage-map/README.md`.
- `detection-rule-lab`: 2,691 Sigma rules run against labeled Windows telemetry;
  135 (5.0%) fired at all, 2,556 (95.0%) never fired once, and 94.6% of the ruleset
  targets event types the corpus actually contains, ruling out corpus-coverage as the
  explanation for the silence. See `../detection-rule-lab/README.md`.
