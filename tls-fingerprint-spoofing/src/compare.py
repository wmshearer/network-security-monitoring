"""
Compare two JA4_r (raw JA4) strings and say exactly which part is
different.

A plain JA4 hash comparison can only tell you two clients are different.
It can't tell you why, because a hash throws that information away.
JA4_r keeps the cipher list, extension list, and signature algorithm
list in the clear, so we can diff those lists directly.

JA4_r format (see FoxIO's JA4.md):
    t13d1516h2_002f,0035,...(ciphers)..._000a,000b,...(exts)..._0403,0503,...(sigalgs)

The first part before the first underscore is JA4_a: protocol, TLS
version, SNI flag, cipher count, extension count, ALPN.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field


@dataclass
class Ja4A:
    protocol: str
    tls_version: str
    sni_flag: str
    cipher_count: str
    ext_count: str
    alpn: str
    raw: str

    @classmethod
    def parse(cls, part: str) -> "Ja4A":
        # e.g. "t13i9012h2" -> t / 13 / i / 90 / 12 / h2
        raw = part
        protocol = part[0]
        rest = part[1:]
        tls_version = rest[0:2]
        rest = rest[2:]
        sni_flag = rest[0]
        rest = rest[1:]
        cipher_count = rest[0:2]
        ext_count = rest[2:4]
        alpn = rest[4:]
        return cls(protocol, tls_version, sni_flag, cipher_count, ext_count, alpn, raw)


@dataclass
class Ja4Raw:
    a: Ja4A
    ciphers: list = field(default_factory=list)
    extensions: list = field(default_factory=list)
    sigalgs: list = field(default_factory=list)
    raw: str = ""

    @classmethod
    def parse(cls, ja4_r: str) -> "Ja4Raw":
        parts = ja4_r.strip().split("_")
        if len(parts) < 2:
            raise ValueError(f"not a valid ja4_r string: {ja4_r!r}")
        a = Ja4A.parse(parts[0])
        ciphers = [c for c in parts[1].split(",") if c] if len(parts) > 1 else []
        # part 2 holds extensions and sigalgs joined by "_" inside the
        # same historical field in some emitters; tshark's ja4_r emits
        # them as separate underscore-delimited sections (parts[2], parts[3]).
        extensions = [e for e in parts[2].split(",") if e] if len(parts) > 2 else []
        sigalgs = [s for s in parts[3].split(",") if s] if len(parts) > 3 else []
        return cls(a=a, ciphers=ciphers, extensions=extensions, sigalgs=sigalgs, raw=ja4_r)


def diff(left: str, right: str) -> dict:
    """Return a dict describing every field that differs between two
    ja4_r strings. Empty dict means identical."""
    l = Ja4Raw.parse(left)
    r = Ja4Raw.parse(right)
    out = {}

    a_fields = ["protocol", "tls_version", "sni_flag", "cipher_count", "ext_count", "alpn"]
    for f in a_fields:
        lv, rv = getattr(l.a, f), getattr(r.a, f)
        if lv != rv:
            out[f] = {"left": lv, "right": rv}

    if l.ciphers != r.ciphers:
        left_set, right_set = set(l.ciphers), set(r.ciphers)
        if left_set == right_set:
            out["cipher_order"] = {
                "note": "same set, different wire order",
                "left": l.ciphers,
                "right": r.ciphers,
            }
        else:
            out["cipher_set"] = {
                "only_in_left": sorted(left_set - right_set),
                "only_in_right": sorted(right_set - left_set),
            }

    if l.extensions != r.extensions:
        left_set, right_set = set(l.extensions), set(r.extensions)
        if left_set == right_set:
            out["extension_order"] = {
                "note": "same set, different wire order",
                "left": l.extensions,
                "right": r.extensions,
            }
        else:
            out["extension_set"] = {
                "only_in_left": sorted(left_set - right_set),
                "only_in_right": sorted(right_set - left_set),
            }

    if l.sigalgs != r.sigalgs:
        # Sigalgs are NOT sorted in JA4_r, so any list difference here
        # includes order. We report both the set diff and whether the
        # order differs on an identical set.
        left_set, right_set = set(l.sigalgs), set(r.sigalgs)
        if left_set == right_set:
            out["sigalg_order"] = {
                "note": "same set, different order (order is significant for JA4_c)",
                "left": l.sigalgs,
                "right": r.sigalgs,
            }
        else:
            out["sigalg_set"] = {
                "only_in_left": sorted(left_set - right_set),
                "only_in_right": sorted(right_set - left_set),
            }

    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("left", help="first ja4_r string")
    ap.add_argument("right", help="second ja4_r string")
    ap.add_argument("--json", action="store_true", help="print raw JSON")
    args = ap.parse_args(argv)

    d = diff(args.left, args.right)

    if args.json:
        print(json.dumps(d, indent=2))
        return 0

    if not d:
        print("identical")
        return 0

    print(f"{len(d)} component(s) differ:")
    for key, val in d.items():
        print(f"  - {key}: {val}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
