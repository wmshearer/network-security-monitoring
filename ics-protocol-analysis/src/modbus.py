"""Analyse Modbus/TCP traffic for unauthorised control operations.

Modbus has no authentication. None. The protocol was designed in 1979 for serial
links inside a locked cabinet, and putting it on TCP did not add a security model.
Any host that can reach port 502 can command a PLC, and the PLC will comply,
because there is no mechanism in the protocol for it to refuse.

That inverts the detection problem. On an IT network you look for credentials being
misused. Here there are no credentials, so the question becomes: which hosts are
SUPPOSED to write, and is anything else writing?

The distinction that carries the analysis is read versus write. A read reports
state. A write CHANGES it, and in an industrial context that means a valve, a
breaker, a motor, or a setpoint. An unauthorised read is an information leak. An
unauthorised write is a physical event.

Function codes, per the Modbus Application Protocol Specification v1.1b3:
    1, 2, 3, 4       reads, no state change
    5, 6, 15, 16     writes, change device state
    23               read/write in one operation, treated as a WRITE here
    8                diagnostics, can force listen-only mode or restart comms
    43               encapsulated interface, device identification

Function 23 is counted as a write deliberately. It performs both, and treating it
as a read because the name starts with "Read" would let a state change through
the check that exists specifically to catch state changes.
"""

from __future__ import annotations

import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

FUNCTION_NAMES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    8: "Diagnostics",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    23: "Read/Write Multiple Registers",
    43: "Encapsulated Interface Transport",
}

# Codes that change device state. 23 is included: it writes as well as reads.
WRITE_CODES = frozenset({5, 6, 15, 16, 23})

# Diagnostics is neither a plain read nor a write, but sub-function 4 forces a
# device into listen-only mode and sub-function 1 restarts communications. Both
# are availability-affecting, so it is tracked separately rather than lumped in
# with reads where it would disappear.
DIAGNOSTIC_CODES = frozenset({8})


MODBUS_PORT = 502


@dataclass(frozen=True)
class ModbusOp:
    timestamp: float
    src: str
    dst: str
    func_code: int
    unit_id: int | None = None
    reference: int | None = None
    dport: int | None = None
    sport: int | None = None

    @property
    def is_request(self) -> bool:
        """True when this is a command TO a device, not a reply FROM one.

        Every Modbus exchange appears twice in a capture: the client's request
        and the server's echo of it. Counting both doubles every number and,
        worse, makes each PLC look like it issues writes when it is only
        answering them. Direction is decided by which side owns port 502.
        """
        if self.dport == MODBUS_PORT:
            return True
        if self.sport == MODBUS_PORT:
            return False
        # Neither side on 502 (non-standard port): cannot determine direction,
        # so count it rather than silently discard traffic that may matter.
        return True

    @property
    def is_write(self) -> bool:
        return self.func_code in WRITE_CODES

    @property
    def is_diagnostic(self) -> bool:
        return self.func_code in DIAGNOSTIC_CODES

    @property
    def name(self) -> str:
        return FUNCTION_NAMES.get(self.func_code, "Function %d" % self.func_code)


@dataclass
class HostProfile:
    """What one host does on the Modbus network."""

    host: str
    reads: int = 0
    writes: int = 0
    diagnostics: int = 0
    targets: set[str] = field(default_factory=set)
    functions: Counter = field(default_factory=Counter)

    @property
    def total(self) -> int:
        return self.reads + self.writes + self.diagnostics

    @property
    def write_ratio(self) -> float:
        return self.writes / self.total if self.total else 0.0

    @property
    def role(self) -> str:
        """Inferred role, from behaviour alone.

        This is a LABEL FOR THE ANALYST, not a verdict. A host that only reads
        looks like a monitoring or historian system; one that writes to many
        devices looks like an engineering workstation or HMI. Both descriptions
        are inferences from traffic, and a compromised host performing its
        normal role would carry the same label.
        """
        if self.total == 0:
            return "silent"
        if self.writes == 0:
            return "read-only (monitoring/historian)"
        if len(self.targets) > 2 and self.write_ratio > 0.2:
            return "writes widely (engineering workstation/HMI)"
        return "writes narrowly"

    def as_row(self) -> dict:
        return {
            "host": self.host,
            "total_ops": self.total,
            "reads": self.reads,
            "writes": self.writes,
            "diagnostics": self.diagnostics,
            "write_ratio": round(self.write_ratio, 4),
            "distinct_targets": len(self.targets),
            "role": self.role,
            "top_functions": [
                {"code": c, "name": FUNCTION_NAMES.get(c, str(c)), "count": n}
                for c, n in self.functions.most_common(6)
            ],
        }


def extract_ops(pcap: Path, timeout: float = 3600.0) -> list[ModbusOp]:
    """Pull Modbus operations out of a capture."""
    cmd = [
        "tshark", "-r", str(pcap), "-Y", "modbus", "-T", "fields",
        "-E", "separator=\t",
        "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
        "-e", "modbus.func_code", "-e", "mbtcp.unit_id",
        "-e", "modbus.reference_num",
        "-e", "tcp.dstport", "-e", "tcp.srcport",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0 and not proc.stdout:
        raise RuntimeError("tshark failed: %s" % proc.stderr[-400:])

    ops: list[ModbusOp] = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        ts, src, dst, fc = parts[0], parts[1], parts[2], parts[3]
        if not fc or not src:
            continue
        # One frame can carry several PDUs; tshark comma-joins them. Emit one
        # operation per code rather than discarding the extras, which would
        # undercount exactly the batched writes most worth seeing.
        def _int_at(idx: int) -> int | None:
            if len(parts) > idx and parts[idx]:
                try:
                    return int(parts[idx].split(",")[0])
                except ValueError:
                    return None
            return None

        for code in str(fc).split(","):
            try:
                ops.append(ModbusOp(
                    timestamp=float(ts or 0), src=src, dst=dst,
                    func_code=int(code),
                    unit_id=_int_at(4),
                    reference=_int_at(5),
                    dport=_int_at(6),
                    sport=_int_at(7),
                ))
            except ValueError:
                continue
    return ops


def profile_hosts(ops: list[ModbusOp], requests_only: bool = True) -> list[HostProfile]:
    """Group operations by the host that issued them.

    `requests_only` defaults True because a Modbus server echoes the function
    code when it replies. Counting replies makes every PLC appear to issue the
    writes it merely answered, which inverts the entire question of who is
    commanding whom.
    """
    by_host: dict[str, HostProfile] = {}
    for op in ops:
        if requests_only and not op.is_request:
            continue
        p = by_host.setdefault(op.src, HostProfile(host=op.src))
        p.targets.add(op.dst)
        p.functions[op.func_code] += 1
        if op.is_write:
            p.writes += 1
        elif op.is_diagnostic:
            p.diagnostics += 1
        else:
            p.reads += 1
    return sorted(by_host.values(), key=lambda p: -p.writes)


def unauthorised_writers(ops: list[ModbusOp], allowed: set[str]) -> list[HostProfile]:
    """Hosts issuing writes that are not on the allow-list.

    This is the detection an ICS operator actually deploys. It requires knowing
    which hosts are permitted to write, which is an operational fact rather than
    something derivable from traffic. Deriving the list from the traffic itself
    would be circular: it would define whatever happened as authorised, which is
    precisely the assumption an intruder benefits from.
    """
    return [p for p in profile_hosts(ops) if p.writes > 0 and p.host not in allowed]
