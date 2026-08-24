# stix-feed-overlap

A measurement, not a tool demo: how much do this portfolio's own captured
intrusion indicators actually overlap with a real public threat-intel
feed? Both sides are normalized onto STIX 2.1 first, so the comparison is
apples-to-apples in a real interchange format, not a private ad hoc shape.

## Terms, defined once, up front

- **Threat intelligence (CTI)**: information about attackers and their
  tools/infrastructure, collected so defenders can recognize an intrusion
  earlier or understand one that already happened.
- **Indicator of Compromise (IOC)**: a concrete, checkable value tied to
  an intrusion, an IP address, a file hash, a domain name, that a defender
  can search their own logs for.
- **STIX** (Structured Threat Information eXpression): a JSON-based data
  format, standardized by OASIS, for describing threat intelligence
  (indicators, malware, threat actors, and the relationships between
  them) in a machine-readable, shareable structure. Current version:
  STIX 2.1 (published 2021).
- **TAXII** (Trusted Automated eXchange of Intelligence Information): a
  transport protocol, also an OASIS standard, for pulling or pushing STIX
  data between servers over HTTPS. STIX is the format; TAXII is one way
  to move it around, not the only way.
- **MISP** (Malware Information Sharing Platform): an open-source
  software platform, a web app plus database, for storing and sharing
  threat intelligence as "events" made of "attributes." MISP has its own
  native JSON format and can also import/export STIX. This project
  consumes MISP-format data as one input; it does not install or run the
  MISP application itself (see "Why not install MISP" below).
- **Feed overlap**: what fraction of the indicators in one threat-intel
  source also appear in another. Low overlap between independent feeds is
  a well-documented finding in published research (cited below); this
  project measures it directly against this portfolio's own data instead
  of only citing someone else's number.

## Why not install MISP

Three projects in this portfolio already consume MISP-format JSON exports
(`threat-intel-datamart`, `ioc-investigation-tool`, `signal-stitching`),
just without naming MISP/STIX/TAXII as such. Standing up the MISP
*platform* on top of that would mean running someone else's finished
software (a web app, a database, a feed importer) and screenshotting that
it works, which proves Docker Compose works, not that anything new was
measured. The full reasoning is recorded at
`../wshearer-site/research/misp-stix-taxii.md`. What is new here: a
measurement (real overlap between this portfolio's captured intrusion and
a real public feed) that no other project in the portfolio has run.

## What was built

1. `src/extract_lockbit.py` — pulls IPv4 addresses, SHA256 hashes, and DNS
   query names out of a real captured intrusion's Sysmon log by regex.
2. `src/filter_lockbit_iocs.py` — separates lab background noise (private
   IPs, the lab's own Active Directory domain, AWS management endpoints,
   background web browsing) from indicators that could plausibly be
   attacker-related, and reports the split honestly.
3. `src/emit_stix.py` — turns the surviving indicators into real STIX 2.1
   `indicator` objects using the `stix2` Python library, and re-parses the
   output to independently confirm it is valid STIX 2.1.
4. `src/fetch_circl.py` — downloads the CIRCL OSINT feed (MISP JSON
   format, no signup, no API key), capped at 4 GB, with every request
   logged.
5. `src/normalize_circl.py` — pulls the same three indicator types
   (IP/SHA256/DNS) out of the CIRCL feed's MISP JSON.
6. `src/compare_to_feeds.py` — THE MEASUREMENT: exact-match comparison
   between the intrusion's surviving indicators and the CIRCL feed's
   indicators, reported as a count and a percentage per indicator type.
7. `src/compare_to_attack.py` — a separate, explicitly weaker fallback
   comparison against the on-disk MITRE ATT&CK STIX 2.1 bundle, included
   because the task required a fallback path be ready if no keyless feed
   were reachable. CIRCL was reachable, so this is reported for context
   only, not as the headline measurement.

## Indicators extracted from the intrusion

Source: `_corpora/attack_data/datasets/apt_simulations/
ActiveMQ_exploit_Lockbit_Ransomware/windows-sysmon.log`, a Sysmon log
captured from a lab reproduction of the ActiveMQ RCE (CVE-2023-46604) to
LockBit 3.0 ransomware chain (documented in the sibling project
`ir-activemq-lockbit`).

Raw counts (before filtering):

| Type | Raw regex matches | After octet/format validation |
|---|---|---|
| IPv4 | 316 | 315 (one match, `11.491.2.10`, has an octet of 491, not a real IP) |
| SHA256 | 602 | 602 |
| DNS names | 238 | 238 |

Noise-filtering rules, applied and reported (see
`src/filter_lockbit_iocs.py` for the exact logic):

- IPs dropped: RFC1918 private ranges, loopback, link-local (includes the
  169.254.169.x AWS instance metadata range), and the `0.0.0.0`
  placeholder.
- DNS names dropped: anything under the lab's own Active Directory domain
  `attackrange.local`, the lab's own EC2 hostname pattern (`EC2AMAZ-*`),
  AWS Systems Manager endpoints, Windows AD service-location (SRV)
  records, DNS root servers, and `www.google.com` by name (called out
  explicitly in scope because it is the clearest example of background
  browsing that must not be silently counted as an IOC).
- SHA256 hashes are never filtered: a file hash has no "lab background"
  concept the way an IP or hostname does.

| Type | Raw | Kept after filtering | Dropped |
|---|---|---|---|
| IPv4 | 315 | 301 | 14 |
| DNS | 238 | 168 | 70 |
| SHA256 | 602 | 602 | 0 |

Honest limitation, stated directly: IP filtering can only remove addresses
that are non-routable by definition. It cannot distinguish a legitimate
CDN/DNS-resolver IP (for example Cloudflare's public DNS `1.0.0.1`, which
survives filtering here) from genuine attacker infrastructure, because
both are ordinary public IPs and there is no lab-domain string to match
an IP against the way there is for a hostname. The DNS-name survivor
count is the more trustworthy of the two after filtering.

## The STIX 2.1 output, and how it was validated

1071 STIX 2.1 `indicator` objects were built (301 IP + 168 DNS + 602
SHA256), plus one `identity` object, written to
`data/lockbit_stix_bundle.json`. Each indicator uses real STIX 2.1
patterning syntax:

- `[ipv4-addr:value = '<ip>']`
- `[domain-name:value = '<name>']`
- `[file:hashes.'SHA-256' = '<hex>']`

Validation was done two ways, not by inspection:

1. Every object was built through the `stix2` Python library's own
   constructors (`stix2.Indicator(...)`), which parses and validates the
   pattern grammar at construction time and raises on a malformed
   pattern. `tests/test_emit_stix.py::test_malformed_pattern_is_rejected_by_stix2_library`
   proves this by feeding the library a pattern with a missing closing
   bracket and confirming it raises.
2. The serialized bundle was independently re-parsed with `stix2.parse()`
   (a separate code path from construction), confirming `spec_version`
   `2.1` on every object and the expected object-type counts.

## Which public feeds were actually reachable

Per the prior research (`../wshearer-site/research/misp-stix-taxii.md`),
live-checked again at the start of this build:

| Feed | Reachable without a key? | Action taken |
|---|---|---|
| CIRCL OSINT feed (MISP JSON, TLP:CLEAR) | Yes, HTTP 200 confirmed live | Used as the primary public feed |
| abuse.ch URLhaus / ThreatFox / MalwareBazaar | No, HTTP 401, Auth-Key mandatory as of 2025 | Skipped: no key obtained, per task constraint |
| AlienVault OTX | No, HTTP 403, signup required | Skipped: no signup performed, per task constraint |
| cti-taxii.mitre.org, freetaxii.com:8080 | No, connection failed on both | No live public TAXII 2.1 server found; not used |

Because CIRCL was reachable, the fallback comparison against the on-disk
MITRE ATT&CK STIX bundle (`compare_to_attack.py`) was run for context but
is not the headline measurement. That bundle contains zero STIX
`indicator` objects (confirmed by direct inspection, 26,086 objects total,
0 of type `indicator`), so no IOC-level comparison is even possible
against it; only a technique/software-name text search, which is a
different and much weaker kind of check (most name matches turned out to
be short, generic strings like `at`, `cmd`, `ftp`, `Ping` that trivially
appear in any Windows log for unrelated reasons, not evidence of the
named ATT&CK software actually being present).

## THE MEASUREMENT

<!-- FILLED IN AFTER THE CIRCL DOWNLOAD COMPLETES: see data/overlap_measurement.json -->

## What this number does and does not mean

<!-- FILLED IN ALONGSIDE THE MEASUREMENT ABOVE -->

## Tests

26+ tests across 6 files in `tests/`, run with `.venv/bin/python -m
pytest tests/`. Every test file was deliberately broken (a wrong regex
length, a removed filter rule, a swapped STIX property name, an
intersection changed to a union, a `.upper()` call removed, a hardcoded
count) and confirmed to fail before being restored and confirmed to pass
again. See the implementer's verification log for the exact break/restore
commands run.

## What this cannot claim

- Cannot claim MISP platform operational experience (installation,
  administration, sync, correlation tuning): the MISP platform itself was
  never installed, by design, per the duplication-gate research.
- Cannot claim TAXII protocol interoperability: no live public TAXII 2.1
  server was reachable this session.
- Cannot claim comprehensive feed coverage: only one feed (CIRCL) was
  usable without a signup or key. abuse.ch's three feeds and AlienVault
  OTX all require registration now and were skipped, not queried.
- Cannot claim the ATT&CK fallback comparison is an IOC-level check: the
  ATT&CK bundle has no indicator objects, so that comparison is limited to
  a text-based software-name search, reported separately and clearly
  labeled as weaker.

## Screenshot check

<!-- FILLED IN AFTER EVIDENCE IS CAPTURED -->

## Anything that contradicted the research

<!-- FILLED IN AFTER THE FINAL RUN -->

## Licensing note on the CIRCL data

CIRCL's OSINT feed is marked TLP:CLEAR by CIRCL itself (per
`https://www.circl.lu/doc/misp/feed-osint/`), meaning it is intended for
open redistribution. This project reports counts, overlap statistics, and
the specific matched values only where a match against this portfolio's
own captured intrusion occurred (which is itself LockBit intrusion data,
not CIRCL's content, being disclosed). No bulk republication of CIRCL's
raw event data is included in this repository; the downloaded cache lives
in `data/circl_cache/`, which is gitignored.
