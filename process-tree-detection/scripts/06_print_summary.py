#!/usr/bin/env python3
"""Print the headline comparison numbers, read straight from evidence/comparison_table.json.

Nothing here computes anything: it only formats numbers that scripts 02-04
already wrote to disk, for a short terminal capture of the project's result.

Usage:
    python3 scripts/06_print_summary.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "evidence" / "comparison_table.json"


def main():
    if not PATH.exists():
        print(f"SKIP: {PATH} not found, run scripts 01-04 first", file=sys.stderr)
        return
    d = json.load(PATH.open())

    print("=== SINGLE-HOP BASELINE (2,691 Sigma rules, this project's re-execution) ===")
    sh = d["single_hop_baseline"]
    print(f"Rules fired at all:           {sh['rules_fired_at_all']} / {sh['rules_evaluated']}")
    print(f"Malicious events matched:     {sh['total_malicious_events_matched']}")
    print(f"Benign events matched (FP):   {sh['total_benign_events_matched']}")
    print()
    print("=== TREE DETECTOR 1: UAC_BYPASS_PROXY_CHAIN (T1548.002) ===")
    t1 = d["tree_detector_uac_bypass_proxy_chain"]
    print(f"Malicious hits: {t1['malicious_hits']}   Benign hits (FP): {t1['benign_hits']}   Precision: {t1['precision']}")
    print()
    print("=== TREE DETECTOR 2: DEEP_CHAIN_TO_LOLBIN (T1218) -- NEGATIVE RESULT ===")
    t2 = d["tree_detector_deep_chain_to_lolbin"]
    print(f"Malicious hits: {t2['malicious_hits']}   Benign hits (FP): {t2['benign_hits']}   Precision: {t2['precision']:.3f}")
    print()
    print("=== CASE STUDY: sdclt.exe UAC-bypass payload-launch events ===")
    cs = d["case_study_sdclt_uac_bypass"]
    print(f"Payload-launch events:                                       {cs['payload_launch_events']}")
    print(f"Caught by content-based single-hop rules (PowerShell text):  {len(cs['single_hop_rules_matching_payload_launch_events'])}")
    print("Caught by any LINEAGE-based single-hop rule:                 0")


if __name__ == "__main__":
    main()
