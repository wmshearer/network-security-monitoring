# Where the data came from

## The captures

Active Countermeasures, "Malware of the Day: Understanding C2 Beacons," Part 1
and Part 2, August 2024, by Faan Rossouw.

- https://www.activecountermeasures.com/malware-of-the-day-understanding-c2-beacons-part-1-of-2/
- https://www.activecountermeasures.com/malware-of-the-day-understanding-c2-beacons-part-2-of-2/

Nine lab captures that hold the environment constant and vary two parameters:
callback delay (10s, 30s, 300s) and jitter (0%, 10%, 25%, 99%), plus two
redirector arrangements. Each ships as a 1-hour capture, a 24-hour capture, and
a zip of Zeek logs.

This study uses **only the Zeek log archives**, downloaded from
`https://acm-motd.s3.amazonaws.com/<name>_zeek_logs.zip`. Each archive contains
Zeek logs for **both** the 1-hour and the 24-hour run, so the full parameter grid
at both observation windows comes to about 44 MB. The packet captures themselves
total roughly 8.2 GB and were **not** downloaded: they exist to produce these
logs, and the publisher already did that.

Every archive was verified against the SHA256 checksum published alongside it.
The checksums are recorded in `data/zeek/SHA256SUMS.published`, and all nine
matched.

### Reuse terms

There is **no formal license** on this data. Three independent checks found no
Terms of Use page: the site footer links only to a privacy policy, the
`/terms-of-use/` path returns a soft 404 (HTTP 200 serving a "404" page), and the
Internet Archive holds no snapshot of that path in the domain's history.

Nothing found restricts downloading or reuse, and the posts actively invite it:
*"PCAPs, or it didn't happen... we encourage you to download the data provided
below and explore these attacks yourself."*

One loose end, stated rather than smoothed over: the privacy policy refers by
name to a "Terms and Conditions" document that does not resolve at any locatable
URL. Its contents are unknown, not confirmed harmless.

So: **vendor-published, reuse explicitly invited, no formal grant found.** That is
weaker than a citable open license. The CTU-13 data used as a cross-check in the
companion `network-beacon-analysis` project carries CC BY 2.0, which this does
not.

Note for anyone reproducing this: the site blocks non-browser user agents, so
requests need a normal browser `User-Agent` header.

## The detector

RITA (Real Intelligence Threat Analytics) v5.1.2, released 2026-05-07.
GPLv3. https://github.com/activecm/rita

Published by the same vendor that published the captures. That is worth stating
plainly: this measures a tool against data its own authors generated, under
conditions they chose. It is a fair test of the tool's stated thresholds, not an
independent benchmark.

RITA v5 runs as three containers (itself, ClickHouse, and syslog-ng) and ingests
directories of Zeek logs rather than reading packet captures. Its documented
platform support lists RHEL-family and Ubuntu only; it installed and ran on Kali
without modification, because the OS list is documentation and not an enforced
check in the installer.

### Version matters here

Scoring changed between major versions. RITA v4 (now `activecm/rita-legacy`,
MongoDB-backed) computed a dispersion score as `1 - MADM/30.0`, with a hardcoded
30-second constant. That formula is still widely repeated in write-ups. **It is
not what v5 computes.** v5 uses `(median - MAD) / median`, which is relative to
the beacon's own interval rather than absolute, and the constant 30 does not
appear in the scoring code at all.

The difference is not cosmetic: an absolute threshold treats a 30-second wobble
as fatal whether the beacon calls every 30 seconds or every 3 hours, while a
relative one does not. Any threshold curve built on the older formula describes a
version of the tool nobody is running.

## Local constraint

Zeek is not installable on the analysis host: Kali packages 5.1.1, which requires
libc6 < 2.38, against an installed glibc 2.42. This is why the study uses the
publisher's pre-generated Zeek logs rather than processing the captures directly,
and it is the same wall the companion `network-beacon-analysis` project hit.
