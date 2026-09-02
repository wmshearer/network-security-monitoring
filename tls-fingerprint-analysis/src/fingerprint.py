"""Identify TLS clients by how they negotiate, without decrypting anything.

Every TLS client announces itself in the ClientHello: which versions it supports,
which ciphers, in which order, which extensions. Those choices come from the TLS
library and its configuration, not from the user, and they differ between a
browser, a Python script, and a malware author's hand-rolled stack.

JA4 (FoxIO) hashes those choices into a comparable string. The payload stays
encrypted throughout. This is metadata analysis, which matters because payload
inspection is no longer available for most traffic.

Reading a JA4 fingerprint, e.g. t13d1516h2_8daaf6152771_b186095e22b6:

    t     TCP (q would be QUIC, d would be DTLS)
    13    TLS 1.3
    d     SNI present (i means NO server name was sent)
    15    15 cipher suites offered
    16    16 extensions
    h2    ALPN says HTTP/2
    then two truncated SHA-256 hashes: ciphers, and extensions+sigalgs

The `i`/`d` character earns its own attention. A browser fetching a website
always sends SNI, because the server needs to know which certificate to present.
A client connecting directly to an IP address has nothing to put there. Absent
SNI on port 443 is not proof of anything, but it is a question worth asking.

LICENSING
    Base JA4 (this file) is BSD-3-Clause. The extended JA4+ family (JA4S, JA4H,
    JA4X and the rest) is under FoxIO License 1.1, which is non-commercial only.
    Only base JA4 is used here, so the permissive licence applies.
"""

from __future__ import annotations

import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# tshark computes JA3 and JA4 natively as of 4.x, so the hashing is not
# reimplemented here. Reimplementing it would add a subtle-bug surface for
# nothing: the value of this project is the analysis, not the hash function.
FIELDS = (
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.dstport",
    "tls.handshake.ja4",
    "tls.handshake.ja3",
    "tls.handshake.extensions_server_name",
    "tls.handshake.version",
)


@dataclass(frozen=True)
class Hello:
    """One observed TLS ClientHello."""

    timestamp: float
    src: str
    dst: str
    dport: int
    ja4: str
    ja3: str
    sni: str

    @property
    def has_sni(self) -> bool:
        return bool(self.sni)

    @property
    def declares_sni(self) -> bool:
        """Whether the JA4 fingerprint itself claims SNI was sent.

        Read from position 3 of the fingerprint rather than from the SNI field,
        so a disagreement between the two is detectable rather than silently
        resolved. They should always agree; if they do not, something is wrong
        with the parse and that is worth knowing.
        """
        return len(self.ja4) > 3 and self.ja4[3] == "d"


@dataclass
class ClientProfile:
    """Everything observed for one JA4 fingerprint."""

    ja4: str
    count: int = 0
    sources: set[str] = field(default_factory=set)
    destinations: set[str] = field(default_factory=set)
    server_names: Counter = field(default_factory=Counter)
    ports: Counter = field(default_factory=Counter)

    @property
    def sends_sni(self) -> bool:
        return len(self.ja4) > 3 and self.ja4[3] == "d"

    @property
    def tls_version(self) -> str:
        """Human-readable TLS version from the fingerprint's own 2-char code."""
        code = self.ja4[1:3] if len(self.ja4) > 2 else ""
        return {
            "13": "TLS 1.3", "12": "TLS 1.2", "11": "TLS 1.1",
            "10": "TLS 1.0", "s3": "SSL 3.0", "s2": "SSL 2.0",
        }.get(code, code or "unknown")

    @property
    def fanout(self) -> int:
        """How many distinct destinations this client contacted.

        A browser fingerprint reaches many servers. A fingerprint that reaches
        exactly one address, repeatedly, is a client with one job.
        """
        return len(self.destinations)

    def as_row(self) -> dict:
        return {
            "ja4": self.ja4,
            "count": self.count,
            "tls_version": self.tls_version,
            "sends_sni": self.sends_sni,
            "distinct_sources": len(self.sources),
            "distinct_destinations": self.fanout,
            "top_server_names": self.server_names.most_common(5),
            "ports": dict(self.ports),
        }


def extract_hellos(pcap: Path, timeout: float = 3600.0) -> list[Hello]:
    """Pull every ClientHello out of a capture."""
    cmd = ["tshark", "-r", str(pcap), "-Y", "tls.handshake.type==1",
           "-T", "fields", "-E", "separator=\t"]
    for f in FIELDS:
        cmd += ["-e", f]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0 and not proc.stdout:
        raise RuntimeError("tshark failed: %s" % proc.stderr[-400:])

    hellos: list[Hello] = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < len(FIELDS):
            continue
        ts, src, dst, dport, ja4, ja3, sni, _ver = parts[:8]
        if not ja4:
            continue
        try:
            hellos.append(Hello(
                timestamp=float(ts or 0),
                src=src, dst=dst,
                dport=int(dport or 443),
                # A single frame can carry more than one value; tshark comma-joins
                # them. Take the first rather than letting a compound string
                # become its own bogus "fingerprint" in the counts.
                ja4=ja4.split(",")[0],
                ja3=(ja3.split(",")[0] if ja3 else ""),
                sni=(sni.split(",")[0] if sni else ""),
            ))
        except ValueError:
            continue
    return hellos


def profile_clients(hellos: list[Hello]) -> list[ClientProfile]:
    """Group ClientHellos by fingerprint.

    Sorted by how many times each fingerprint appeared. Frequency is the wrong
    signal for suspicion on its own, since the noisiest client is usually the
    browser, but it is the right way to see the shape of a capture at a glance.
    """
    by_ja4: dict[str, ClientProfile] = {}
    for h in hellos:
        p = by_ja4.setdefault(h.ja4, ClientProfile(ja4=h.ja4))
        p.count += 1
        p.sources.add(h.src)
        p.destinations.add(h.dst)
        p.ports[h.dport] += 1
        if h.sni:
            p.server_names[h.sni] += 1
    return sorted(by_ja4.values(), key=lambda p: -p.count)


def find_sni_mismatches(hellos: list[Hello]) -> list[Hello]:
    """ClientHellos whose fingerprint and SNI field disagree.

    The JA4 fingerprint encodes whether SNI was present. If that marker says
    absent while an SNI value exists (or the reverse), the parse is inconsistent
    and any conclusion drawn from either field is unsafe. This surfaces that
    rather than picking whichever field is convenient.
    """
    return [h for h in hellos if h.declares_sni != h.has_sni]


def group_by_destination(hellos: list[Hello]) -> dict[str, set[str]]:
    """Which fingerprints contacted each destination.

    A destination reached by several different clients looks like shared
    infrastructure. A destination reached by exactly one unusual fingerprint,
    and nothing else, is a narrower question.
    """
    out: dict[str, set[str]] = defaultdict(set)
    for h in hellos:
        out[h.dst].add(h.ja4)
    return dict(out)
