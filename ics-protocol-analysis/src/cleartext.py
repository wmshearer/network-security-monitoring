"""Find credentials and sensitive material sent in the clear.

Some protocols transmit authentication with no encryption at all. This is not a
vulnerability in the sense of a bug to patch: FTP, Telnet and SNMPv1/v2c work
exactly as specified. The specification is the problem, and it dates from an era
when the network itself was assumed trustworthy.

Anyone positioned to see the traffic reads the credentials. On an industrial
network, where flat segments and legacy equipment are the norm rather than the
exception, "positioned to see the traffic" is a low bar.

WHAT THIS DOES NOT DO
    It does not crack, brute force, or decrypt anything. It reads fields that
    the protocols transmit in plaintext by design. Everything here is visible to
    any passive observer on the path.

REPORTING NOTE
    Passwords are redacted by default. The finding is "credentials for this
    account traversed this network unencrypted", which is fully established by
    the username, protocol and endpoints. Printing the password adds nothing to
    the finding and creates a secondary exposure in the report itself, which
    then lives in a repository and a case study.
"""

from __future__ import annotations

import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

# SNMP community strings that ship as defaults. Finding these is equivalent to
# finding a device with its factory password: `public` grants read access to the
# device's entire management tree, `private` typically grants write.
DEFAULT_COMMUNITIES = frozenset({
    "public", "private", "manager", "admin", "cisco", "community",
    "read", "write", "monitor", "secret", "snmp", "default",
})


@dataclass(frozen=True)
class Exposure:
    """One instance of credential material observed in plaintext."""

    protocol: str
    src: str
    dst: str
    field_name: str
    value: str
    severity: str = "medium"

    def redacted(self) -> str:
        """The value, safe to print.

        Usernames and community strings are shown because they identify WHICH
        account or device is exposed, which is the actionable part. Passwords
        are masked to their length: enough to show something was captured,
        nothing reusable.
        """
        if self.field_name in ("password", "secret"):
            return "<%d chars redacted>" % len(self.value)
        return self.value


@dataclass
class ProtocolFindings:
    protocol: str
    exposures: list[Exposure] = field(default_factory=list)
    hosts: set[str] = field(default_factory=set)

    @property
    def count(self) -> int:
        return len(self.exposures)

    def as_row(self) -> dict:
        by_field: Counter = Counter(e.field_name for e in self.exposures)
        return {
            "protocol": self.protocol,
            "exposures": self.count,
            "hosts_involved": len(self.hosts),
            "field_breakdown": dict(by_field),
            "samples": [
                {"src": e.src, "dst": e.dst, "field": e.field_name,
                 "value": e.redacted(), "severity": e.severity}
                for e in self.exposures[:10]
            ],
        }


def _tshark(pcap: Path, display_filter: str, fields: list[str],
            timeout: float = 3600.0) -> list[list[str]]:
    cmd = ["tshark", "-r", str(pcap), "-Y", display_filter, "-T", "fields",
           "-E", "separator=\t"]
    for f in fields:
        cmd += ["-e", f]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0 and not proc.stdout:
        return []
    return [line.split("\t") for line in proc.stdout.splitlines() if line.strip()]


def find_ftp_credentials(pcap: Path) -> ProtocolFindings:
    """FTP sends USER and PASS as plaintext commands (RFC 959)."""
    out = ProtocolFindings(protocol="FTP")
    rows = _tshark(
        pcap,
        'ftp.request.command == "USER" || ftp.request.command == "PASS"',
        ["ip.src", "ip.dst", "ftp.request.command", "ftp.request.arg"],
    )
    for r in rows:
        if len(r) < 4 or not r[3]:
            continue
        is_pass = r[2].upper() == "PASS"
        out.exposures.append(Exposure(
            protocol="FTP", src=r[0], dst=r[1],
            field_name="password" if is_pass else "username",
            value=r[3],
            # A password crossing the wire is the higher finding; a username
            # alone is disclosure but not directly usable.
            severity="high" if is_pass else "medium",
        ))
        out.hosts.update([r[0], r[1]])
    return out


def find_snmp_communities(pcap: Path) -> ProtocolFindings:
    """SNMPv1/v2c authenticate with a plaintext community string.

    A default community string is the finding. `public` normally grants read of
    the full management tree; `private` normally grants write, which on network
    or industrial equipment can mean reconfiguration.
    """
    out = ProtocolFindings(protocol="SNMP")
    rows = _tshark(pcap, "snmp.community", ["ip.src", "ip.dst", "snmp.community"])
    for r in rows:
        if len(r) < 3 or not r[2]:
            continue
        community = r[2].split(",")[0]
        is_default = community.lower() in DEFAULT_COMMUNITIES
        out.exposures.append(Exposure(
            protocol="SNMP", src=r[0], dst=r[1],
            field_name="community_string", value=community,
            severity="high" if is_default else "medium",
        ))
        out.hosts.update([r[0], r[1]])
    return out


def find_http_basic_auth(pcap: Path) -> ProtocolFindings:
    """HTTP Basic authentication is base64, which is encoding, not encryption."""
    out = ProtocolFindings(protocol="HTTP")
    rows = _tshark(pcap, "http.authorization", ["ip.src", "ip.dst", "http.authorization"])
    for r in rows:
        if len(r) < 3 or not r[2]:
            continue
        out.exposures.append(Exposure(
            protocol="HTTP", src=r[0], dst=r[1],
            field_name="authorization_header", value=r[2][:24],
            severity="high",
        ))
        out.hosts.update([r[0], r[1]])
    return out


def find_telnet_sessions(pcap: Path) -> ProtocolFindings:
    """Telnet carries the entire session, credentials included, in plaintext.

    Only session ENDPOINTS are recorded here, not reconstructed keystrokes.
    Telnet transmits character-by-character with server echo, so reassembling a
    typed password is possible but produces a report containing live credentials
    for equipment that, in this capture, belongs to someone else.
    """
    out = ProtocolFindings(protocol="Telnet")
    rows = _tshark(pcap, "telnet", ["ip.src", "ip.dst"])
    pairs: Counter = Counter()
    for r in rows:
        if len(r) < 2 or not r[0]:
            continue
        pairs[(r[0], r[1])] += 1
        out.hosts.update([r[0], r[1]])
    for (src, dst), n in pairs.most_common():
        out.exposures.append(Exposure(
            protocol="Telnet", src=src, dst=dst,
            field_name="session", value="%d packets" % n,
            severity="high",
        ))
    return out


def scan(pcap: Path) -> list[ProtocolFindings]:
    """Run every cleartext check that applies."""
    results = [
        find_ftp_credentials(pcap),
        find_telnet_sessions(pcap),
        find_snmp_communities(pcap),
        find_http_basic_auth(pcap),
    ]
    return [r for r in results if r.count]
