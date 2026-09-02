"""
Detect GREASE values in a captured ClientHello, independent of JA3/JA4.

GREASE (RFC 8701) is a set of reserved cipher suite / extension / group
/ version values that all follow the pattern 0x?A?A where both nibbles
are equal and one of {0x0, 0x1, ..., 0xF}: 0x0A0A, 0x1A1A, 0x2A2A, ...,
0xFAFA. A client sends one at random in various fields to force servers
to tolerate unknown values, instead of breaking when a genuinely new
cipher or extension shows up later.

JA3 and JA4 both strip GREASE out before hashing, so you can't see it
in the fingerprint at all. This script reads the raw extension/cipher
lists straight out of tshark to check whether GREASE was present on
the wire, which is a hypothesis this project tests rather than a
documented fact: does a real browser send GREASE and does a stock
scripted client not?
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

# 0x?A?A where both ?'s are the same nibble: 0x0A0A, 0x1A1A, ..., 0xFAFA
GREASE_VALUES = {(h << 12) | (0xA << 8) | (h << 4) | 0xA for h in range(16)}


def is_grease(value: int) -> bool:
    return value in GREASE_VALUES


def _run_tshark_fields(pcap: str, field: str) -> list[str]:
    out = subprocess.run(
        ["tshark", "-r", pcap, "-Y", "tls.handshake.type==1", "-T", "fields", "-e", field],
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in out.stdout.strip().split("\n") if line]


def check_pcap(pcap: str) -> dict:
    """Look at every ClientHello in the pcap for GREASE values in the
    cipher suite list, the extension type list, and the supported
    groups list. Returns counts per field."""
    result = {
        "cipher_grease": 0,
        "extension_grease": 0,
        "group_grease": 0,
        "clienthello_count": 0,
        "any_grease": False,
    }

    cipher_lines = _run_tshark_fields(pcap, "tls.handshake.ciphersuite")
    ext_lines = _run_tshark_fields(pcap, "tls.handshake.extension.type")
    group_lines = _run_tshark_fields(pcap, "tls.handshake.extensions_supported_group")

    result["clienthello_count"] = max(len(cipher_lines), len(ext_lines), 1) if (cipher_lines or ext_lines) else 0

    for line in cipher_lines:
        for tok in line.split(","):
            tok = tok.strip()
            if tok and is_grease(int(tok, 0) if tok.startswith("0x") else int(tok)):
                result["cipher_grease"] += 1

    for line in ext_lines:
        for tok in line.split(","):
            tok = tok.strip()
            if tok and is_grease(int(tok, 0) if tok.startswith("0x") else int(tok)):
                result["extension_grease"] += 1

    for line in group_lines:
        for tok in line.split(","):
            tok = tok.strip()
            if tok and is_grease(int(tok, 0) if tok.startswith("0x") else int(tok)):
                result["group_grease"] += 1

    result["any_grease"] = bool(
        result["cipher_grease"] or result["extension_grease"] or result["group_grease"]
    )
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pcap")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    result = check_pcap(args.pcap)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"ClientHellos seen: {result['clienthello_count']}")
        print(f"GREASE in cipher list: {result['cipher_grease']}")
        print(f"GREASE in extension list: {result['extension_grease']}")
        print(f"GREASE in supported groups: {result['group_grease']}")
        print(f"any GREASE present: {result['any_grease']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
