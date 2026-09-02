"""Detect network scanning and brute-force attempts from connection outcomes.

The signal is failure. A host doing ordinary work connects to things that exist:
it looks up a name, gets an address, and the address answers. A host scanning
does not know what exists, so most of what it contacts never replies.

That produces a measurable asymmetry. Connection attempts vastly outnumber
successful handshakes, and the target list is wide rather than repeated.

The TCP handshake makes this observable without any payload inspection:

    SYN            client asks to connect
    SYN-ACK        server agrees          <- only if something is listening
    ACK            client confirms

A SYN with no SYN-ACK back means nothing was there, or a firewall dropped it.
Counting both sides gives a response rate, and a low response rate across many
distinct destinations is what scanning looks like from the wire.

WHAT THIS DOES NOT SEPARATE
    Scanning for open ports and brute-forcing credentials on a service that IS
    open look different here: the first fails to connect, the second connects
    fine and fails at authentication, which happens inside the encrypted session
    on SSH. This measures reachability, not authentication. A high response rate
    with many attempts to ONE host is the brute-force shape and is flagged
    separately rather than folded into the same number.
"""

from __future__ import annotations

import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Attempt:
    """One outbound connection attempt."""

    timestamp: float
    src: str
    dst: str
    dport: int


@dataclass
class ScanProfile:
    """What one source host's connection behaviour looks like."""

    src: str
    attempts: int = 0
    targets: set[str] = field(default_factory=set)
    responded: set[str] = field(default_factory=set)
    ports: Counter = field(default_factory=Counter)
    first_seen: float = 0.0
    last_seen: float = 0.0

    @property
    def response_rate(self) -> float | None:
        """Share of contacted hosts that answered.

        None when nothing was contacted. Not zero: "reached nobody" and
        "reached many, none answered" are different states and collapsing them
        would hide the second, which is the interesting one.
        """
        if not self.targets:
            return None
        return len(self.responded) / len(self.targets)

    @property
    def duration_s(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def attempts_per_target(self) -> float:
        return self.attempts / len(self.targets) if self.targets else 0.0

    @property
    def distinct_subnets(self) -> int:
        """Distinct /24 blocks touched.

        Address spread separates scanning from ordinary work more reliably than
        raw target count. A busy web browser reaches many addresses, but they
        cluster in the networks of a few providers. A scanner sweeps ranges.
        """
        return len({".".join(t.split(".")[:3]) for t in self.targets if "." in t})

    def as_row(self) -> dict:
        return {
            "source": self.src,
            "attempts": self.attempts,
            "distinct_targets": len(self.targets),
            "hosts_that_answered": len(self.responded),
            "response_rate": (None if self.response_rate is None
                              else round(self.response_rate, 5)),
            "distinct_subnets": self.distinct_subnets,
            "attempts_per_target": round(self.attempts_per_target, 2),
            "duration_s": round(self.duration_s, 1),
            "top_ports": self.ports.most_common(5),
        }


# Both thresholds are stated here rather than buried in a conditional so they
# can be argued with. They are descriptive, not authoritative: a scan is a shape,
# and where the boundary sits depends on the network being watched.
SCAN_RESPONSE_CEILING = 0.10   # under 10% answering is not ordinary traffic
SCAN_MIN_TARGETS = 50          # below this, a low rate is just a few dead hosts


def classify(p: ScanProfile) -> str:
    """Describe a host's behaviour. A shape, not a verdict."""
    rate = p.response_rate
    if rate is None:
        return "no attempts"
    if len(p.targets) == 1 and p.attempts >= 20:
        # Many attempts at one host that IS answering is the brute-force shape:
        # reachability is fine, so whatever is failing fails after the connect.
        return "repeated attempts on a single host (brute-force shape)"
    if len(p.targets) >= SCAN_MIN_TARGETS and rate < SCAN_RESPONSE_CEILING:
        return "wide scanning (most targets never answered)"
    if len(p.targets) >= SCAN_MIN_TARGETS:
        return "many targets, most answering (normal wide activity)"
    return "ordinary connection behaviour"


def extract_attempts(pcap: Path, port: int | None = None,
                     timeout: float = 3600.0) -> tuple[list[Attempt], set[tuple[str, str]]]:
    """Return outbound SYNs, and the (src,dst) pairs that got a SYN-ACK back.

    Attempts and responses are pulled in one tshark pass rather than two. Two
    passes over a large capture is slow, and worse, a filter typo in the second
    would silently yield zero responses and turn every host into a scanner.
    """
    filt = "tcp.flags.syn==1"
    if port is not None:
        filt = "(%s) && tcp.port==%d" % (filt, port)

    cmd = ["tshark", "-r", str(pcap), "-Y", filt, "-T", "fields",
           "-E", "separator=\t",
           "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
           "-e", "tcp.dstport", "-e", "tcp.flags.ack"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0 and not proc.stdout:
        return [], set()

    attempts: list[Attempt] = []
    answered: set[tuple[str, str]] = set()
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 5 or not parts[1]:
            continue
        try:
            ts = float(parts[0])
            dport = int(parts[3] or 0)
        except ValueError:
            continue
        # A frame carrying tunnelled or encapsulated IP has more than one
        # ip.src, and tshark comma-joins them. The OUTERMOST header is first and
        # is the one that actually routed the packet. Without this split, a
        # tunnelled packet becomes its own bogus "host" like "1.2.3.4,5.6.7.8",
        # which fragments one scanner into thousands of phantom sources.
        src = parts[1].split(",")[0]
        dst = parts[2].split(",")[0]
        # A SYN with ACK set is the server's half of the handshake, so this
        # packet's SOURCE is the host that answered.
        is_synack = parts[4].strip() in ("1", "True", "true")
        if is_synack:
            answered.add((dst, src))
        else:
            attempts.append(Attempt(timestamp=ts, src=src, dst=dst, dport=dport))
    return attempts, answered


def profile(attempts: list[Attempt],
            answered: set[tuple[str, str]]) -> list[ScanProfile]:
    """Group attempts by source and mark which targets replied."""
    by_src: dict[str, ScanProfile] = {}
    for a in attempts:
        p = by_src.setdefault(a.src, ScanProfile(src=a.src,
                                                 first_seen=a.timestamp,
                                                 last_seen=a.timestamp))
        p.attempts += 1
        p.targets.add(a.dst)
        p.ports[a.dport] += 1
        p.first_seen = min(p.first_seen, a.timestamp)
        p.last_seen = max(p.last_seen, a.timestamp)
        if (a.src, a.dst) in answered:
            p.responded.add(a.dst)
    return sorted(by_src.values(), key=lambda p: -p.attempts)


def timeline(attempts: list[Attempt], src: str, buckets: int = 20) -> list[int]:
    """Attempts over time for one source, as fixed-width buckets.

    Rate shape distinguishes a burst from sustained low-and-slow activity. A
    scanner deliberately pacing itself under a rate threshold still produces a
    flat, machine-steady line that human activity does not.
    """
    ts = sorted(a.timestamp for a in attempts if a.src == src)
    if len(ts) < 2:
        return []
    span = ts[-1] - ts[0]
    if span <= 0:
        return [len(ts)]
    width = span / buckets
    out = [0] * buckets
    for t in ts:
        i = min(buckets - 1, int((t - ts[0]) / width))
        out[i] += 1
    return out
