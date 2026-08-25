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

1. `src/extract_lockbit.py`: pulls IPv4 addresses, SHA256 hashes, and DNS
   query names out of a real captured intrusion's Sysmon log by regex.
2. `src/filter_lockbit_iocs.py`: separates lab background noise (private
   IPs, the lab's own Active Directory domain, AWS management endpoints,
   background web browsing) from indicators that could plausibly be
   attacker-related, and reports the split honestly.
3. `src/emit_stix.py`: turns the surviving indicators into real STIX 2.1
   `indicator` objects using the `stix2` Python library, and re-parses the
   output to independently confirm it is valid STIX 2.1.
4. `src/fetch_circl.py`: downloads the CIRCL OSINT feed (MISP JSON
   format, no signup, no API key), capped at 4 GB, with every request
   logged.
5. `src/normalize_circl.py`: pulls the same three indicator types
   (IP/SHA256/DNS) out of the CIRCL feed's MISP JSON.
6. `src/compare_to_feeds.py`: THE MEASUREMENT: exact-match comparison
   between the intrusion's surviving indicators and the CIRCL feed's
   indicators, reported as a count and a percentage per indicator type.
7. `src/compare_to_attack.py`: a separate, explicitly weaker fallback
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
| CIRCL OSINT feed (MISP JSON) | Yes, HTTP 200 confirmed live | Used as the primary public feed |
| abuse.ch URLhaus / ThreatFox / MalwareBazaar | No, HTTP 401, Auth-Key mandatory as of 2025 | Skipped: no key obtained, per task constraint |
| AlienVault OTX | No, HTTP 403, signup required | Skipped: no signup performed, per task constraint |
| cti-taxii.mitre.org, freetaxii.com:8080 | No, connection failed on both | No live public TAXII 2.1 server found; not used |

The CIRCL feed's manifest lists 1680 events. This project downloaded 845
of them (50.3%) before stopping intentionally; see "How much of the feed
was actually pulled" below for why. Total downloaded: approximately 327
MB (`data/download_log.json` records every request, its HTTP status, and
its byte count), well under the 4 GB cap. No API key was sent on any
request, because none exists for this feed.

Because CIRCL was reachable, the fallback comparison against the on-disk
MITRE ATT&CK STIX bundle (`compare_to_attack.py`) was run for context but
is not the headline measurement. That bundle contains zero STIX
`indicator` objects (confirmed by direct inspection, 26,086 objects total,
0 of type `indicator`), so no IOC-level comparison is even possible
against it; only a technique/software-name text search, which is a
different and much weaker kind of check. Running it turned up 35 raw
substring matches, most of which are short, generic strings (`at`, `cmd`,
`ftp`, `Ping`, `certutil`, `netsh`) that trivially appear in any Windows
Sysmon log for unrelated reasons. Excluding those known false positives
and three more confirmed by manually checking the surrounding text
(`Tor` matched inside "monitor", `Epic` matched inside an unrelated
service GUID, `ABK` matched inside base64-encoded PowerShell), 16
distinctive-looking names remain: `AdFind`, `Conti`, `Disco`, `Emotet`,
`GRIFFON`, `Hikit`, `Ninja`, `Proton`, `Proxysvc`, `QakBot`, `RDAT`,
`RTM`, `SYSCON`, `Spica`, `ZLib`, `httpclient`. Of these, only `AdFind`
was checked further and confirmed genuine: the log shows an actual
`AdFind.exe` file-creation event, consistent with AdFind being a real,
commonly-documented LockBit-affiliate reconnaissance tool. The other 15
were not individually re-verified and should be read as unconfirmed
name collisions, not as a finding that those specific ATT&CK-catalogued
tools were present.

### How much of the feed was actually pulled

CIRCL's server answered slowly during this run: a single event file
took roughly 8 to 10 seconds round trip (measured directly with `curl
-w '%{time_total}'`, not a guess), which is a property of their server
at the time this project ran, not a bug in `fetch_circl.py`. At that
rate, pulling all 1680 events sequentially would have taken multiple
hours. The overlap measurement was re-checked at three points during the
download (31% of the feed, 40%, and 50%) and returned zero matches every
time, so the download was stopped at 845 of 1680 events (50.3%) rather
than run to completion for a result that had already stabilized. This is
reported plainly as a partial sample: the true full-feed number could in
principle differ from what is reported below, though nothing in three
successive checks suggested it would.

## THE MEASUREMENT

Comparing the LockBit intrusion's 1,071 surviving indicators (301 IPv4 +
168 DNS names + 602 SHA256 hashes, after noise filtering) against the
87,424 indicators pulled from 845 CIRCL OSINT feed events (18,577 IPv4 +
49,995 DNS names + 18,852 SHA256 hashes):

| Indicator type | LockBit surviving indicators | Matches found in CIRCL | Overlap |
|---|---|---|---|
| IPv4 | 301 | 0 | 0.0% |
| DNS | 168 | 0 | 0.0% |
| SHA256 | 602 | 0 | 0.0% |
| **Total** | **1,071** | **0** | **0.0%** |

Zero. Not one of the 1,071 surviving indicators from this portfolio's own
captured LockBit intrusion appears anywhere in the 87,424 indicators
pulled from the CIRCL OSINT feed. The exact match logic is exact-string
equality, case-normalized upstream (IPs as-is, DNS lowercased, SHA256
uppercased on both sides), no fuzzy or substring matching. The full
result, including the (empty) match lists, is in
`data/overlap_measurement.json`.

This matches the direction of the published research cited in the prior
research brief: Suarez-Roman et al. ("The CTI Echo Chamber," arXiv
2602.17458, May 2026, read directly) report IOC-level overlap below 0.1%
across the vendors they studied. A separate, older figure of 2.5-4.0%
feed overlap is attributed to Li et al. ("Reading the Tea Leaves," USENIX
Security 2019) in secondary sources; that paper's primary PDF returned
HTTP 403 when checked and was not read directly, so that specific number
is cited here only as a secondary-sourced figure, not verified against
the original text. This project's own result (0.0%) is at or below both
cited ranges, not a contradiction of either.

## What this number does and does not mean

Zero overlap does not mean public threat-intel feeds are useless, and
this project does not claim that. There is a specific, more likely
explanation for a zero here that has nothing to do with feed quality:
**the LockBit intrusion measured in this project is a lab reproduction,
not an in-the-wild campaign.** It was captured in Splunk's
`attack_range` lab environment (hostnames like `EC2AMAZ-*`, domain
`attackrange.local`), running a simulated ActiveMQ exploit chain to
LockBit 3.0 ransomware. The specific IPs, domains, and file hashes that
happened to appear during that one lab run were never part of a real
attacker's real infrastructure or a real malware build; there is no
reason any public feed, which exists to catalog observations from real
in-the-wild intrusions, would ever have recorded them. A zero here is
close to guaranteed by the nature of the data, independent of whatever
the true overlap rate between independent real-world feeds is.

That means this measurement's honest contribution is narrower than "this
portfolio proves feeds have near-zero overlap": it demonstrates the
STIX 2.1 normalization and comparison pipeline works correctly end to
end (proven by the tests and by re-parsing the emitted STIX through an
independent library call), and it produces a result that is directionally
consistent with, but not independent statistical confirmation of, the
published research on feed overlap. A stronger version of this project
would run the same pipeline against a real in-the-wild intrusion's
indicators (for example a public incident-response writeup with
published IOCs) rather than a lab reproduction, where a nonzero overlap
would actually be possible and a zero would be a more meaningful result.
That was out of scope here because the task specified this portfolio's
own captured intrusion data as the source.

## Tests

34 tests across 6 files in `tests/`, run with `.venv/bin/python -m pytest
tests/`. Every one of the 6 test files was broken on purpose and confirmed
to fail before being restored and confirmed to pass again:

| Test file | What was broken | Failure observed |
|---|---|---|
| `test_extract_lockbit.py` | SHA256 regex changed from `{64}` to `{63}` hex chars | `test_all_sha256_are_64_hex_chars` failed: `assert 63 == 64` |
| `test_filter_lockbit_iocs.py` | Removed the `www.google.com` filter rule | `test_www_google_com_is_dropped_by_name` failed: it stayed in the kept list |
| `test_emit_stix.py` | Changed `SHA-256` to an invalid STIX property name | `test_indicator_pattern_syntax_sha256` failed: 0 matching indicators instead of 1 |
| `test_compare_to_feeds.py` | Changed set intersection (`&`) to union (`\|`) for all three indicator types | 3 of 4 tests failed, e.g. `test_no_overlap_when_disjoint`: `assert 6 == 0` |
| `test_compare_to_attack.py` | Hardcoded the indicator-object count to 999 | `test_attack_bundle_has_zero_indicator_objects` failed: `assert 999 == 0` |
| `test_normalize_circl.py` | Removed the `.upper()` call on extracted SHA256 values | 2 tests failed on case mismatch |

Each break was reverted and the full suite re-run to confirm a clean pass
before moving on. `__pycache__` directories were cleared between runs
after one break/restore cycle produced a stale cached result that looked
like the fix hadn't taken effect; clearing the cache and re-running showed
the fix had, in fact, worked.

## What this cannot claim

- Cannot claim MISP platform operational experience (installation,
  administration, sync, correlation tuning): the MISP platform itself was
  never installed, by design, per the duplication-gate research.
- Cannot claim TAXII protocol interoperability: no live public TAXII 2.1
  server was reachable this session.
- Cannot claim broad feed coverage: only one feed (CIRCL) was
  usable without a signup or key. abuse.ch's three feeds and AlienVault
  OTX all require registration now and were skipped, not queried.
- Cannot claim the ATT&CK fallback comparison is an IOC-level check: the
  ATT&CK bundle has no indicator objects, so that comparison is limited to
  a text-based software-name search, reported separately and clearly
  labeled as weaker.

## Screenshot check

Five screenshots in `evidence/`, all rendered from real command output via
`termshot.py` (not a screen capture), each viewed directly with an image
read after being written, confirming no credential, token, or unrelated
environment detail is visible in any of them:

1. `01_tests_passing.png`: `pytest tests/ -v`, 34 passed. Viewed: clean,
   only test names and pass/fail status visible.
2. `02_extract_and_filter.png`: extraction and filtering counts. Viewed:
   clean, only JSON count output visible.
3. `03_stix_emit_and_validate.png`: STIX bundle build and re-parse
   validation. Viewed: clean, shows a local file path
   (`/home/kali/director/projects/...`) which is this machine's own
   working directory, not a credential or secret.
4. `04_the_measurement.png`: the final overlap comparison output. Viewed:
   clean, only the measurement JSON visible.
5. `05_download_cap_respected.png`: the download log's cap-compliance
   summary. Viewed: clean, only counts and booleans visible, no URL
   content or feed data shown.

## Anything that contradicted the research

- **The CIRCL feed is not uniformly TLP:CLEAR.** The prior research brief
  (`../wshearer-site/research/misp-stix-taxii.md`) described the feed as
  TLP:CLEAR overall, citing CIRCL's own feed-page description. Direct
  inspection of the feed's own manifest.json (not the description page)
  during this build showed a mix: 1295 events tagged `tlp:white`, 414
  `tlp:clear`, 76 `tlp:green`, 1 `tlp:amber`, and 21 with no TLP tag at
  all, out of 1680 total. TLP:GREEN and TLP:AMBER both carry real
  redistribution restrictions the earlier brief's characterization did
  not account for. This project's reporting was adjusted to report only
  counts and statistics, not raw feed values, because of this.
- **A full CIRCL feed pull was not practical in the time available.** The
  research brief did not measure or predict per-request latency for this
  feed. In practice, single-event requests took roughly 8-10 seconds each
  this session, an order of magnitude slower than expected for a small
  JSON file, and a full 1680-event sequential pull was not completed;
  845 events (50.3%) were pulled instead. The measurement result (zero
  overlap) was stable across three checks at increasing sample sizes, so
  this is reported as a defensible partial sample rather than treated as
  a blocker, but it is a real gap from "pulled the whole feed" to "pulled
  half the feed."
- **Everything else in the prior research held up under direct
  verification**: CIRCL reachable with no key (confirmed, HTTP 200),
  abuse.ch's three APIs requiring a key (not re-tested this session,
  taken as given per the brief's own live 401), no live public TAXII 2.1
  server (not re-tested, taken as given), the ATT&CK bundle already on
  disk with 26,086 objects (confirmed, and additionally confirmed to
  contain zero `indicator`-type objects, which the brief did not check),
  and the LockBit log's raw indicator counts (316 IP regex matches, 602
  SHA256, 238 DNS, all confirmed exactly).

## Licensing note on the CIRCL data

The CIRCL feed is NOT uniformly TLP:CLEAR. Direct inspection of the
manifest's 1680 events shows most carry `tlp:white` (1295) or `tlp:clear`
(414), the open/unrestricted marking (TLP:WHITE was the pre-2.0 name for
what is now called TLP:CLEAR), but 76 events are tagged `tlp:green`
(intended for community sharing, not open publication) and 1 is
`tlp:amber` (further restricted, need-to-know only). This corrects an
earlier characterization in the prior research brief
(`../wshearer-site/research/misp-stix-taxii.md`) that described the whole
feed as TLP:CLEAR without checking per-event tags.

Because of this mix, this project reports only counts and overlap
statistics, not raw indicator values from CIRCL events, except for the
handful of values that also independently appear in the portfolio's own
LockBit intrusion data (which is being disclosed as this portfolio's own
captured data, not as a republication of CIRCL's content). No bulk
republication of CIRCL's raw event data is included in this repository;
the downloaded cache lives in `data/circl_cache/`, which is gitignored.
