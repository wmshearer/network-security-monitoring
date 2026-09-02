"""Static analysis of an extracted firmware root filesystem.

WHY OPENWRT AND NOT A VENDOR IMAGE

The obvious subject for firmware analysis is a consumer router image from a
vendor support page. Those are copyrighted software. Being able to download a
file is not permission to use it, and that distinction has already ruled two
datasets out of this portfolio.

OpenWrt states its licence in its own COPYING file:

    SPDX-License-Identifier: GPL-2.0-only

GPL covers binaries built from GPL source, so an official OpenWrt image is a
licence-clean artifact to analyse and write about. It is also a well-maintained
distribution rather than abandoned vendor firmware, which shapes what the
findings mean: this measures a project that does security work, not one that
does not.

WHAT THIS LOOKS FOR

The standard firmware findings, in the order they matter:

  - credentials in configuration or password files
  - private keys and certificates shipped in the image
  - world-writable files and setuid binaries
  - services enabled by default
  - the age of bundled components

The last one carries a caveat this file is careful about. Version numbers in a
firmware image tell you what shipped. They do not tell you whether a distribution
backported a fix without changing the version string, which is exactly what
stable distributions do. So a version match against a CVE year is a question to
ask, never a vulnerability to report.

SOURCES
  OWASP Firmware Security Testing Methodology, stages 1-5 only. Stages 6 to 9
  are emulation, dynamic and runtime analysis, which this project does not do.
  https://github.com/scriptingxss/owasp-fstm
"""

from __future__ import annotations

import os
import re
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def find_rootfs() -> Path | None:
    for candidate in (ROOT / "extracted").rglob("squashfs-root"):
        if (candidate / "etc").is_dir():
            return candidate
    return None


@dataclass
class Finding:
    category: str
    title: str
    detail: str
    path: str
    #: PROVES: the file literally contains or declares this.
    #: SUGGESTS: worth investigating, not established by the file alone.
    evidence: str
    severity: str
    cannot_establish: str


@dataclass
class Report:
    rootfs: str
    files: int = 0
    findings: list[Finding] = field(default_factory=list)
    release: dict[str, str] = field(default_factory=dict)


#: A password field of "x" means the hash lives in /etc/shadow. "*" or "!" means
#: login is disabled. An empty field means no password at all, which is the
#: finding worth having.
def check_passwd(rootfs: Path, report: Report) -> None:
    passwd = rootfs / "etc" / "passwd"
    if not passwd.exists():
        return
    for line in passwd.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        user, pwfield, _, _, _, _, shell = parts[:7]
        if pwfield == "":
            report.findings.append(Finding(
                category="credentials",
                title="Account with no password",
                detail=f"{user} has an empty password field and a shell of {shell}.",
                path="etc/passwd",
                evidence="PROVES",
                severity="high" if "sh" in shell else "medium",
                cannot_establish=(
                    "Whether the account is reachable. A shell account with no "
                    "password matters only if a login service accepts it."
                ),
            ))


#: A real crypt(3) hash starts with $ and an algorithm id, as in $1$, $5$, $6$,
#: $y$ or $2b$. Everything else in a password field is a marker.
CRYPT_HASH = re.compile(r"^\$[0-9a-z]{1,3}\$")

#: Password-field markers that are NOT hashes.
#:   ""      no password at all
#:   "*", "!", "!!"  login disabled
#:   "x"     placeholder meaning "no password set for this account"
NON_HASH_FIELDS = {"", "*", "!", "!!", "x"}


def check_shadow(rootfs: Path, report: Report) -> None:
    """Read /etc/shadow, distinguishing a real hash from a placeholder.

    The first version of this treated anything other than "", "*" or "!" as a
    hash and reported four HIGH findings against ntp, dnsmasq, logd and ubus.
    All four password fields are the single character "x", which is a
    placeholder meaning no password is set. There was no hash anywhere in the
    file.

    Worse, the finding it should have made was the one it missed: the root line
    reads `root:::`, an empty password field, which is the only genuinely
    interesting entry in the file.

    So the check now matches the crypt(3) format explicitly and reports empty
    fields separately.
    """
    shadow = rootfs / "etc" / "shadow"
    if not shadow.exists():
        return
    for line in shadow.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split(":")
        if len(parts) < 2:
            continue
        user, field = parts[0], parts[1]

        if CRYPT_HASH.match(field):
            report.findings.append(Finding(
                category="credentials",
                title="Password hash baked into the image",
                detail=(
                    f"{user} has a crypt hash in the firmware, so every device "
                    "running this image starts with the same credential."
                ),
                path="etc/shadow",
                evidence="PROVES",
                severity="high",
                cannot_establish=(
                    "Whether the hash is crackable, and whether first boot "
                    "forces a change."
                ),
            ))
        elif field == "":
            report.findings.append(Finding(
                category="credentials",
                title="Account with an empty password field",
                detail=(
                    f"{user} has no password set in /etc/shadow. Whether that "
                    "permits a login depends entirely on how each service is "
                    "configured to treat an empty password."
                ),
                path="etc/shadow",
                evidence="PROVES",
                severity="medium",
                cannot_establish=(
                    "Whether any service accepts it. OpenWrt ships root with no "
                    "password by design and relies on dropbear refusing empty "
                    "password logins, which is a configuration question this "
                    "filesystem scan cannot settle."
                ),
            ))


#: A PEM header followed by actual base64 body, not the header alone.
#:
#: The first version searched for the header string and reported a private key
#: inside libmbedcrypto.so. That library contains 23 PEM header and footer
#: strings because it PARSES key files: they are format labels in its own code,
#: with no key material anywhere near them. Every crypto library on earth would
#: have produced the same false finding.
#:
#: Requiring a base64 body immediately after the header is what separates a
#: shipped key from a library that knows how to read one.
KEY_PATTERNS = (
    (re.compile(
        rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----\s*\n"
        rb"[A-Za-z0-9+/=\s]{100,}"
    ), "private key"),
    (re.compile(
        rb"-----BEGIN CERTIFICATE-----\s*\n[A-Za-z0-9+/=\s]{100,}"
    ), "certificate"),
)


def check_keys(rootfs: Path, report: Report) -> None:
    for path in rootfs.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            if path.stat().st_size > 2_000_000:
                continue
            blob = path.read_bytes()
        except OSError:
            continue
        for pattern, label in KEY_PATTERNS:
            if pattern.search(blob):
                rel = str(path.relative_to(rootfs))
                report.findings.append(Finding(
                    category="keys",
                    title=f"Embedded {label}",
                    detail=(
                        f"{rel} contains a {label}. Anything shipped in the "
                        "image is identical across every device running it."
                    ),
                    path=rel,
                    evidence="PROVES",
                    severity="high" if label == "private key" else "info",
                    cannot_establish=(
                        "Whether it is used for anything security-relevant, or "
                        "regenerated on first boot."
                    ),
                ))
                break


def check_permissions(rootfs: Path, report: Report) -> None:
    for path in rootfs.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            mode = path.stat().st_mode
        except OSError:
            continue
        rel = str(path.relative_to(rootfs))
        if mode & stat.S_ISUID:
            report.findings.append(Finding(
                category="permissions",
                title="Setuid binary",
                detail=f"{rel} runs with the privileges of its owner, not its caller.",
                path=rel,
                evidence="PROVES",
                severity="medium",
                cannot_establish=(
                    "Whether it is exploitable. Setuid is a fact about the file; "
                    "whether it can be abused depends on the binary."
                ),
            ))
        if mode & stat.S_IWOTH:
            report.findings.append(Finding(
                category="permissions",
                title="World-writable file",
                detail=f"{rel} can be modified by any user on the device.",
                path=rel,
                evidence="PROVES",
                severity="medium",
                cannot_establish="Whether an unprivileged user exists to abuse it.",
            ))


#: Components worth noting the version of. Not a vulnerability check: a stable
#: distribution routinely backports fixes without changing a version string, so
#: matching a version against a CVE list produces false positives by design.
VERSION_FILES = (
    ("etc/openwrt_release", "OpenWrt release"),
    ("etc/os-release", "OS release"),
)


def check_versions(rootfs: Path, report: Report) -> None:
    for rel, label in VERSION_FILES:
        path = rootfs / rel
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                report.release[key.strip()] = value.strip().strip("'\"")


def check_services(rootfs: Path, report: Report) -> None:
    init_dir = rootfs / "etc" / "rc.d"
    if not init_dir.is_dir():
        return
    enabled = sorted(
        p.name for p in init_dir.iterdir() if p.name.startswith("S")
    )
    if enabled:
        report.findings.append(Finding(
            category="services",
            title=f"{len(enabled)} services enabled at boot",
            detail=", ".join(enabled[:10]) + ("..." if len(enabled) > 10 else ""),
            path="etc/rc.d",
            evidence="PROVES",
            severity="info",
            cannot_establish=(
                "Whether any of them listens on the network. That needs the "
                "service running, which is dynamic analysis."
            ),
        ))


def analyse(rootfs: Path) -> Report:
    report = Report(rootfs=str(rootfs))
    report.files = sum(1 for p in rootfs.rglob("*") if p.is_file())
    check_versions(rootfs, report)
    check_passwd(rootfs, report)
    check_shadow(rootfs, report)
    check_keys(rootfs, report)
    check_permissions(rootfs, report)
    check_services(rootfs, report)
    return report


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def main() -> None:
    rootfs = find_rootfs()
    if rootfs is None:
        print("no extracted root filesystem found under extracted/")
        return

    report = analyse(rootfs)

    print("Firmware static analysis")
    print(f"  {report.release.get('DISTRIB_ID', '?')} "
          f"{report.release.get('DISTRIB_RELEASE', '?')}, "
          f"{report.release.get('DISTRIB_TARGET', '?')}, "
          f"{report.release.get('DISTRIB_ARCH', '?')}")
    print(f"  {report.files:,} files in the root filesystem\n")

    by_category: dict[str, int] = {}
    for finding in report.findings:
        by_category[finding.category] = by_category.get(finding.category, 0) + 1

    ordered = sorted(report.findings, key=lambda f: SEVERITY_ORDER[f.severity])
    for finding in ordered:
        print(f"  [{finding.severity.upper():<6}] {finding.title}")
        print(f"           {finding.detail}")

    if not report.findings:
        print("  no findings")

    print("\n  by category:", ", ".join(
        f"{k} {v}" for k, v in sorted(by_category.items())
    ))

    print("\nWhat this does not check: whether any bundled component has a known")
    print("vulnerability. A stable distribution backports fixes without changing")
    print("version strings, so matching versions against CVE years produces")
    print("false positives by design. That is a question for the vendor's own")
    print("security tracker, not for a version string in a file.")


if __name__ == "__main__":
    main()
