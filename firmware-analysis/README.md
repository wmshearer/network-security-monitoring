# Firmware static analysis

Extracting and analysing an official OpenWrt firmware image, with provenance
verified before anything is opened.

## The licence question came first

The obvious subject for firmware analysis is a consumer router image from a
vendor support page. Those are copyrighted software. Being able to download a
file is not permission to use it, and that same distinction already ruled out a
cloud dataset and a CloudTrail corpus elsewhere in this portfolio.

OpenWrt states its licence in its own `COPYING`:

```
SPDX-License-Identifier: GPL-2.0-only
```

GPL covers binaries built from GPL source, so an official image is clean to
analyse and write about. The image was downloaded from OpenWrt's own release
server and checked against their published SHA-256 before extraction.

## The result

```
OpenWrt 24.10.8, ath79/generic, mips_24kc
1,281 files in the root filesystem

[MEDIUM] root has an empty password field in /etc/shadow
[INFO  ] etc/ssl/certs/ca-certificates.crt contains certificates
[INFO  ] 23 services enabled at boot
```

No password hashes baked in. No private keys. No setuid binaries. No
world-writable files.

That is a boring result and it is the correct one. This is a maintained
distribution that does security work, not abandoned vendor firmware, and the
finding is that it looks like one.

The root account genuinely has no password, which is OpenWrt's documented design:
the device is unreachable over the network until you set one, and dropbear
refuses empty-password logins. Reporting it is right. Calling it a vulnerability
would not be, which is why it carries that caveat rather than a HIGH label.

## Both detectors were wrong on the first run

The same mistake twice, in different clothes: matching a marker instead of the
thing the marker describes.

**Four fake password hashes.** The check reported ntp, dnsmasq, logd and ubus as
having hashes baked into the image. All four fields are the single character
`x`, which is a placeholder meaning no password is set. There was no hash in the
file at all. Meanwhile the one interesting line, `root:::`, went unreported. It
now matches the crypt(3) format explicitly.

**A private key inside a crypto library.** The check reported
`libmbedcrypto.so.3.6.6` as containing a private key. It contains 23 PEM header
and footer strings because it *parses* key files. Every crypto library on earth
would have tripped that check. It now requires a base64 body after the header.

Both fixes are pinned by tests that run in both directions, because a detector
that finds nothing and a detector that cannot find anything produce identical
output.

## Running it

```
# verify before extracting
cd images && sha256sum -c <(grep carambola2 sha256sums | sed 's/\*//')

binwalk --extract --directory extracted images/*.bin
python3 src/analyse.py
python3 -m pytest tests/ -q
```

binwalk, unsquashfs and sasquatch were already installed on this system.

One thing worth noting from extraction: binwalk warned that a symlink in the
image pointed outside the extraction directory and redirected it to /dev/null.
That is a real hazard when unpacking untrusted archives, and it is the kind of
thing worth reading rather than scrolling past.

## Scope

OWASP's Firmware Security Testing Methodology has nine stages. This covers one
to five, which are reconnaissance through filesystem analysis. Stages six to
nine are emulation, dynamic analysis, runtime analysis and exploitation, and
this project does none of them.

It does not check bundled components against CVE lists. A stable distribution
backports fixes without changing version strings, so matching a version against
a CVE year produces false positives by design. That question belongs to the
vendor's security tracker.

One image, one target architecture. A different device profile ships a different
package set.
