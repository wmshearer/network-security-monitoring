#!/usr/bin/env python3
"""Run all four AD detections against the reference captures and print results.

Each capture in this project isolates one AD recon-or-theft technique, so
there is one small analysis per capture rather than one large one. This
script runs all four in sequence and writes one combined JSON report,
matching the numbers this project's findings.md cites.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.common import KNOWN_DCS, frame_count  # noqa: E402
from src.dcsync import classify as dcsync_classify  # noqa: E402
from src.dcsync import extract_calls as dcsync_calls  # noqa: E402
from src.dcsync import flag_non_dc_replication  # noqa: E402
from src.ldap_recon import describe as ldap_describe  # noqa: E402
from src.ldap_recon import extract_binds, extract_searches  # noqa: E402
from src.ldap_recon import is_subtree_dump  # noqa: E402
from src.samr_enum import describe as samr_describe  # noqa: E402
from src.samr_enum import extract_calls as samr_calls  # noqa: E402
from src.samr_enum import group_sequences  # noqa: E402
from src.spn_recon import describe as spn_describe  # noqa: E402
from src.spn_recon import extract_spn_searches  # noqa: E402

CAPTURES = ROOT / "data" / "captures"
report: dict = {}


def section(title: str) -> None:
    print()
    print("== %s ==" % title)


section("DCSync: dcsync.pcapng")
pcap = CAPTURES / "dcsync.pcapng"
calls = dcsync_calls(pcap)
flagged = flag_non_dc_replication(calls, known_dcs=KNOWN_DCS)
print("frames: %d | DRSUAPI calls: %d | flagged: %d" %
      (frame_count(pcap), len(calls), len(flagged)))
for f in flagged:
    print("  frame %d  %s -> %s  %s" %
          (f.frame, f.src, f.dst, dcsync_classify(f, KNOWN_DCS)))
report["dcsync"] = {
    "frames": frame_count(pcap), "drsuapi_calls": len(calls),
    "flagged": [{"frame": f.frame, "src": f.src, "dst": f.dst} for f in flagged],
}

section("SPN discovery: find_service_accounts.pcap")
pcap = CAPTURES / "find_service_accounts.pcap"
searches = extract_spn_searches(pcap)
print("frames: %d | searches: %d" % (frame_count(pcap), len(searches)))
print("  %s" % spn_describe(searches))
report["spn_recon"] = {
    "frames": frame_count(pcap),
    "searches": [{"frame": s.frame, "src": s.src, "dst": s.dst} for s in searches],
}

section("LDAP recon: tinkersec-ldapsearch.pcap")
pcap = CAPTURES / "tinkersec-ldapsearch.pcap"
searches = extract_searches(pcap)
binds = extract_binds(pcap)
print("frames: %d | searchRequests: %d | bindRequests: %d" %
      (frame_count(pcap), len(searches), len(binds)))
for s in searches:
    print("  frame %d  %s" % (s.frame, ldap_describe(s)))
for b in binds:
    print("  frame %d  bind as %r" % (b.frame, b.name or "(anonymous)"))
report["ldap_recon"] = {
    "frames": frame_count(pcap),
    "searches": [{"frame": s.frame, "scope": s.scope, "base": s.base_object,
                  "subtree_dump": is_subtree_dump(s)} for s in searches],
    "binds": [{"frame": b.frame, "name": b.name} for b in binds],
}

section("SAMR group enumeration: net_group_DAs.pcap")
pcap = CAPTURES / "net_group_DAs.pcap"
calls = samr_calls(pcap)
seqs = [s for s in group_sequences(calls) if s.matches_enumeration_chain]
print("frames: %d | SAMR calls: %d | matching sequences: %d" %
      (frame_count(pcap), len(calls), len(seqs)))
for s in seqs:
    print("  %s -> %s  %s" % (s.src, s.dst, samr_describe(s)))
report["samr_enum"] = {
    "frames": frame_count(pcap), "samr_calls": len(calls),
    "sequences": [{"src": s.src, "dst": s.dst, "group": s.group_name,
                   "opnums": list(s.opnums)} for s in seqs],
}

out = ROOT / "reports" / "analysis-results.json"
out.write_text(json.dumps(report, indent=2))
print()
print("wrote %s" % out)
print()
print("Every classify()/describe() above states shape, not intent. Whether the")
print("hosts and accounts involved were authorised to do this is a fact about")
print("the environment, not something derivable from the packets alone.")
