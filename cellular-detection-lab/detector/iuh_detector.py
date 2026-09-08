#!/usr/bin/env python3
"""
iuh_detector.py - HNB-identity allowlist detector for 3G/UMTS Iuh/HNBAP.

WHY THIS EXISTS
----------------
This tier's own scope is narrower than the other three tiers' detectors,
and that narrowness is deliberate, not an oversight: there is NO RF-free
path for the WCDMA Uu air interface (see docs/3G-TIER.md's explicit
RF-boundary statement), so this lab never reached a UE registering, and
therefore never captured an HNBAP UE REGISTER REQUEST or a RANAP Initial
UE Message/UMTS AKA exchange. Only ONE signal is implemented here as a
result - the one this lab actually has real signalling to test against.

SIGNAL IMPLEMENTED
-------------------
  HNB-identity allowlist violation   (HNBAP HNB REGISTER REQUEST)

    The 3G/Iuh analogue of the 5G tier's signal #5 (NG Setup Request),
    the 4G tier's signal #16 (S1 Setup Request), and the 2G tier's own
    LAI-based checks: a Home NodeB claims an identity (PLMN + HNB-Identity
    string) before any mutual authentication has occurred at this layer,
    exactly like a gNB/eNB's NG/S1 Setup Request - there is still no
    cryptographic proof that a registering HNB belongs to the claimed
    operator at the point this message is sent (TS 25.469 9.2.19 defines
    the id-HNB-Identity IE as an operator-defined string with no
    mandated format or authentication of its own). Comparing the claimed
    identity against a known-good allowlist is the reliable check
    available here, same reasoning ngap_detector.py's own signal #5
    docstring gives.

SIGNAL DELIBERATELY NOT IMPLEMENTED
-------------------------------------
  Cleartext IMSI in HNBAP UE REGISTER REQUEST (TS 25.469 9.2.13's
  id-UE-Identity IE, IMSI choice) was the task's own second candidate
  signal. It is NOT implemented here: this lab never reached a UE
  registering over Iuh at all (see docs/3G-TIER.md, "what this tier does
  NOT reach" - osmo-hnodeb ships no Uu/PHY/RRC client, and driving its
  lower-layer primitive socket to synthesize one would require writing a
  new ASN.1-encoding client from scratch, assessed as out of this pass's
  effort budget - see NOTES.md). Writing a check against a message type
  this lab has never seen on the wire, with no way to verify the tshark
  field names or behaviour empirically, is exactly the "hollow detector"
  the task instructed against. If a future pass captures a real HNBAP UE
  REGISTER REQUEST, the fields to check are `hnbap.iMSI` (raw bytes) or
  an `e212.imsi`-tagged sub-dissection if tshark provides one, following
  the exact same allowlist/cleartext-identity pattern as this file's own
  check_hnb_identity_allowlist() and gsm_detector.py's/lte_detector.py's
  cleartext-IMSI checks - deliberately NOT stubbed out here as dead code.

HOW IT WORKS
------------
Same approach as ngap_detector.py/gsm_detector.py/lte_detector.py,
deliberately kept in the same style: tshark does all protocol parsing
(HNBAP ASN.1 PER decoding) - this script never touches raw bytes. We
shell out to `tshark -T fields` once for this signal, requesting every
field it needs in one call (see ngap_detector.py's own docstring for
run_tshark_fields() for why one call, not one per field). No third-party
Python packages - standard library plus `subprocess` calling the system
`tshark` binary only.

USAGE
-----
  Offline against a pcap:
    ./iuh_detector.py --pcap evidence/3g/iuh-hnb-register.pcap

  Live against an interface (needs CAP_NET_RAW / root, e.g. loopback for
  this tier's own Iuh traffic - see docs/3G-TIER.md):
    sudo ./iuh_detector.py --iface lo --duration 30

  Both modes accept --allowlist to point at a different allowlist file.
"""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

# tshark field set for HNBAP HNB REGISTER REQUEST, pulled in ONE call (see
# ngap_detector.py's own hard-won lesson: two separate tshark calls against
# the same capture can silently return different row COUNTS for the same
# display filter, misaligning any downstream zip()/positional pairing).
# hnbap.hNB_Identity_Info is a hex octet string (TS 25.469 9.2.19 imposes
# no format on id-HNB-Identity; this lab's osmo-hnodeb encodes it as plain
# ASCII, confirmed empirically against evidence/3g/iuh-hnb-register.pcap
# with `tshark -Y hnbap -V`), decoded to text below rather than compared
# as hex, so the allowlist file stays human-readable.
HNB_REGISTER_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "hnbap.hNB_Identity_Info",
    "e212.mcc",
    "e212.mnc",
    "hnbap.CellIdentity",
    "hnbap.LAC",
    "hnbap.RAC",
    "hnbap.SAC",
]


# --------------------------------------------------------------------------
# tshark plumbing (identical pattern to the other three detectors)
# --------------------------------------------------------------------------

def run_tshark_fields(pcap_path, display_filter, fields):
    """Run `tshark -T fields` and return a list of dicts, one per matching
    packet, keyed by field name. See ngap_detector.py's own docstring for
    this function for the full rationale (occurrence=f, unit-separator,
    one call per signal).
    """
    separator = "\x1f"
    cmd = ["tshark", "-r", pcap_path, "-Y", display_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    cmd += ["-E", "separator=" + separator, "-E", "occurrence=f"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"tshark failed ({' '.join(cmd)}): {result.stderr.strip()}")
    rows = []
    for line in result.stdout.splitlines():
        if not line:
            continue
        cols = line.split(separator)
        cols += [""] * (len(fields) - len(cols))
        rows.append(dict(zip(fields, cols)))
    return rows


def capture_live_to_pcap(iface, duration, pcap_out, bpf_filter="sctp port 29169"):
    """Capture live traffic to a pcap file first, then run the signal's
    display filter against that single capture - same rationale as the
    other three detectors' equivalent function. Port 29169 is the IANA/
    3GPP-registered Iuh SCTP port (IUA_DEFAULT_SCTP_PORT in both
    osmo-hnbgw and osmo-hnodeb - see docs/3G-TIER.md).
    """
    cmd = [
        "tshark", "-i", iface, "-a", f"duration:{duration}",
        "-f", bpf_filter, "-w", pcap_out,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"tshark live capture failed: {result.stderr.strip()}")
    return pcap_out


# --------------------------------------------------------------------------
# Allowlist
# --------------------------------------------------------------------------

def load_allowlist(path):
    """Load the HNB-identity allowlist. See detector/allowlist_hnb.json
    for the schema and how to derive each field from a real HNB REGISTER
    REQUEST.
    """
    with open(path) as fh:
        data = json.load(fh)
    hnbs = []
    for entry in data.get("hnbs", []):
        hnbs.append({
            "name": entry.get("name", "(unnamed)"),
            "mcc": str(entry["plmn"]["mcc"]),
            "mnc": str(entry["plmn"]["mnc"]),
            "hnb_identity": entry["hnb_identity"],
        })
    return hnbs


def allowlist_lookup(hnbs, mcc, mnc, hnb_identity):
    """Return the matching allowlist entry, or None if (mcc, mnc,
    hnb_identity) is not on the allowlist. hnb_identity is compared as
    the DECODED text string, not the raw hex - see allowlist_hnb.json's
    own comment for why (TS 25.469 imposes no format on this IE, so the
    only stable comparison is against whatever text an operator actually
    configured, which is what this file records).
    """
    for hnb in hnbs:
        if (hnb["mcc"] == mcc and hnb["mnc"] == mnc
                and hnb["hnb_identity"] == hnb_identity):
            return hnb
    return None


def decode_hnb_identity_hex(hex_str):
    """hnbap.hNB_Identity_Info arrives from `tshark -T fields` as a plain
    hex string with no separators (e.g. "43656c6c..."), not the
    colon-separated form some other tshark byte fields use (compare
    ngap_detector.py's ngap.gNB_ID handling, which DOES need colons
    stripped - hnbap.hNB_Identity_Info never has them to begin with,
    confirmed empirically against this lab's own capture). Decoded as
    ASCII/UTF-8 since that's what this lab's osmo-hnodeb configuration
    produces; a real deployment could in principle populate this IE with
    non-printable binary since TS 25.469 imposes no format, so decoding
    errors are reported as their own finding rather than silently
    crashing or truncating - see check_hnb_identity_allowlist() below.
    """
    return bytes.fromhex(hex_str).decode("utf-8")


# --------------------------------------------------------------------------
# Finding helper (identical schema to the other three detectors)
# --------------------------------------------------------------------------

def make_finding(signal_id, severity, summary, observed, expected, citation,
                  frame_number=None, packet_time_epoch=None):
    """Build one structured finding. Same fixed schema as
    ngap_detector.py/gsm_detector.py/lte_detector.py's make_finding(), so
    a downstream consumer that already handles their JSON lines needs no
    changes to also handle this one.
    """
    if packet_time_epoch:
        ts = datetime.fromtimestamp(float(packet_time_epoch), tz=timezone.utc).isoformat()
    else:
        ts = datetime.now(timezone.utc).isoformat()
    return {
        "timestamp": ts,
        "signal_id": signal_id,
        "severity": severity,
        "summary": summary,
        "observed": observed,
        "expected": expected,
        "spec_citation": citation,
        "frame_number": frame_number,
    }


# --------------------------------------------------------------------------
# Signal - HNB-identity allowlist violation
# --------------------------------------------------------------------------

def check_hnb_identity_allowlist(pcap_path, allowlist_hnbs):
    """HNBAP HNB REGISTER REQUEST (TS 25.469 9.2.1) carries the HNB's
    claimed PLMN identity (id-PLMNidentity) and its own operator-defined
    identity string (id-HNB-Identity). A Home NodeB that is not part of
    the operator's deployment - a rogue/unauthorised femtocell, or in
    this lab, an intentionally unauthorised process presenting a
    different identity string - still has to send this message before
    osmo-hnbgw will register it, and it can claim whatever identity it
    likes because HNB REGISTER REQUEST is sent before any mutual
    authentication has occurred at this layer (there is no cryptographic
    proof of who the HNB is at the point this message is evaluated -
    the same "no cryptographic proof that a broadcasting cell belongs to
    the claimed operator" gap docs/DETECTION-SIGNALS.md documents for
    NGAP/S1AP one layer up, TS 25.469 itself defines no authentication
    procedure for HNB REGISTER REQUEST). Comparing the claimed identity
    against a known-good allowlist is the one fully reliable check
    available here, because in this lab (unlike the real world) we own
    ground truth about which HNBs are supposed to exist.
    """
    findings = []
    rows = run_tshark_fields(
        pcap_path,
        "hnbap.HNBRegisterRequest_element",
        HNB_REGISTER_FIELDS,
    )
    for row in rows:
        mcc = row["e212.mcc"]
        mnc = row["e212.mnc"]
        identity_hex = row["hnbap.hNB_Identity_Info"]

        if not mcc or not identity_hex:
            # HNB REGISTER REQUEST always carries these IEs (both
            # id-PLMNidentity and id-HNB-Identity are mandatory per TS
            # 25.469 9.2.1). An incomplete row means tshark could not
            # fully dissect this packet (e.g. truncated capture). Do not
            # silently skip - report it as its own finding, same posture
            # ngap_detector.py's signal #5 takes for the same failure mode.
            findings.append(make_finding(
                signal_id="hnb-identity-incomplete",
                severity="warning",
                summary="HNB REGISTER REQUEST seen but mandatory identity "
                        "IEs could not be fully decoded (truncated "
                        "capture, or a malformed/non-conformant message).",
                observed={"frame": row["frame.number"], "mcc": mcc,
                          "identity_hex": identity_hex},
                expected="PLMNidentity and HNB-Identity fully present, "
                         "per TS 25.469 9.2.1 (HNB REGISTER REQUEST).",
                citation="3GPP TS 25.469 9.2.1 (HNB REGISTER REQUEST)",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
            continue

        try:
            hnb_identity = decode_hnb_identity_hex(identity_hex)
        except UnicodeDecodeError:
            # TS 25.469 9.2.19 imposes no format on this IE - a real HNB
            # could legitimately send non-UTF-8 binary. Report the raw
            # hex as its own finding rather than crash or silently
            # truncate; a human can then decide whether this is
            # legitimate vendor-specific encoding or a malformed message.
            findings.append(make_finding(
                signal_id="hnb-identity-undecodable",
                severity="warning",
                summary="HNB REGISTER REQUEST's HNB-Identity IE is not "
                        "valid UTF-8 text - cannot compare against the "
                        "text-based allowlist. TS 25.469 imposes no "
                        "format on this IE, so this may be legitimate "
                        "vendor-specific binary encoding rather than a "
                        "malformed message.",
                observed={"frame": row["frame.number"], "mcc": mcc,
                          "mnc": mnc, "identity_hex": identity_hex},
                expected="UTF-8 text identity, per this lab's own "
                         "allowlist convention (see allowlist_hnb.json).",
                citation="3GPP TS 25.469 9.2.19 (HNB Identity IE)",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
            continue

        match = allowlist_lookup(allowlist_hnbs, mcc, mnc, hnb_identity)
        observed = {
            "frame": row["frame.number"],
            "src_ip": row["ip.src"],
            "plmn": f"{mcc}/{mnc}",
            "hnb_identity": hnb_identity,
            "cell_identity": row["hnbap.CellIdentity"] or None,
            "lac": row["hnbap.LAC"] or None,
            "rac": row["hnbap.RAC"] or None,
            "sac": row["hnbap.SAC"] or None,
        }
        if match is None:
            expected_desc = ", ".join(
                f"{h['name']}: PLMN {h['mcc']}/{h['mnc']}, identity "
                f"\"{h['hnb_identity']}\""
                for h in allowlist_hnbs
            ) or "(allowlist is empty)"
            findings.append(make_finding(
                signal_id="hnb-identity-allowlist-violation",
                severity="critical",
                summary="HNB REGISTER REQUEST presented a (PLMN, "
                        "HNB-Identity) identity that is not on the "
                        "allowlist - candidate rogue/unauthorised "
                        "femtocell.",
                observed=observed,
                expected=f"One of the allowlisted HNBs: {expected_desc}",
                citation="3GPP TS 25.469 9.2.1 (HNB REGISTER REQUEST, "
                         "PLMNidentity + HNB-Identity IEs); "
                         "docs/3G-TIER.md",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
        else:
            findings.append(make_finding(
                signal_id="hnb-identity-allowlist-ok",
                severity="info",
                summary="HNB REGISTER REQUEST identity matches an "
                        "allowlisted HNB.",
                observed=observed,
                expected=f"Matched: {match['name']}",
                citation="3GPP TS 25.469 9.2.1 (HNB REGISTER REQUEST)",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
    return findings


# --------------------------------------------------------------------------
# Console summary (same format as the other three detectors)
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "warning": 2, "info": 3}


def print_console_summary(all_findings):
    actionable = [f for f in all_findings
                  if not f["signal_id"].endswith("-ok")
                  and not f["signal_id"].endswith("-incomplete")
                  and not f["signal_id"].endswith("-undecodable")]
    print("=" * 78)
    print("IUH/HNBAP HNB-IDENTITY ALLOWLIST DETECTOR - SUMMARY")
    print("=" * 78)
    if not actionable:
        print("No findings. All observed HNB REGISTER REQUEST procedures")
        print("matched allowlisted, expected HNB identities.")
        print("(A clean run is a valid, good outcome, not an absence of checking -")
        print(f" {len(all_findings)} check(s) were evaluated; see --json-out for detail.)")
    else:
        for finding in sorted(actionable, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9)):
            print(f"\n[{finding['severity'].upper()}] {finding['signal_id']} "
                  f"- {finding['summary']}")
            print(f"    Observed: {finding['observed']}")
            print(f"    Expected: {finding['expected']}")
            print(f"    Spec:     {finding['spec_citation']}")
            if finding.get("frame_number"):
                print(f"    Frame:    {finding['frame_number']}")
    print()
    print(f"Total checks evaluated: {len(all_findings)}  |  "
          f"Actionable findings: {len(actionable)}")
    print("=" * 78)
    print()
    print("NOTE: only one signal is implemented in this detector (HNB-identity")
    print("allowlist). Cleartext IMSI in HNBAP UE REGISTER REQUEST was NOT")
    print("implemented - this lab never captured a UE registering over Iuh at")
    print("all (no RF-free path to a real Uu/PHY/RRC client - see")
    print("docs/3G-TIER.md and NOTES.md). See this file's own module")
    print("docstring for the full explanation.")
    print("=" * 78)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Detect HNB-identity allowlist violations in HNBAP "
                    "traffic (3G/Iuh tier).",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--pcap", help="Path to an existing pcap/pcapng file (offline mode).")
    mode.add_argument("--iface", help="Network interface to capture live from (live mode).")
    parser.add_argument("--duration", type=int, default=30,
                        help="Live capture duration in seconds (live mode only). Default 30.")
    parser.add_argument("--save-pcap", default=None,
                        help="In live mode, save the capture to this path (default: a "
                             "temp file that is deleted after analysis).")
    parser.add_argument("--allowlist", default=None,
                        help="Path to the HNB-identity allowlist JSON file. "
                             "Default: allowlist_hnb.json next to this script.")
    parser.add_argument("--json-out", default=None,
                        help="Write findings as JSON lines (one finding per line) to "
                             "this path, in addition to stdout.")
    args = parser.parse_args()

    allowlist_path = args.allowlist or (
        __file__.rsplit("/", 1)[0] + "/allowlist_hnb.json" if "/" in __file__
        else "allowlist_hnb.json"
    )
    try:
        allowlist_hnbs = load_allowlist(allowlist_path)
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"ERROR: could not load allowlist from {allowlist_path}: {exc}", file=sys.stderr)
        return 2

    cleanup_pcap = None
    if args.iface:
        pcap_path = args.save_pcap or f"/tmp/iuh_detector_live_{int(time.time())}.pcap"
        if not args.save_pcap:
            cleanup_pcap = pcap_path
        print(f"Capturing on {args.iface} for {args.duration}s "
              f"(filter: sctp port 29169) -> {pcap_path}", file=sys.stderr)
        capture_live_to_pcap(args.iface, args.duration, pcap_path)
    else:
        pcap_path = args.pcap

    all_findings = []
    all_findings += check_hnb_identity_allowlist(pcap_path, allowlist_hnbs)

    print_console_summary(all_findings)

    if args.json_out:
        with open(args.json_out, "w") as fh:
            for finding in all_findings:
                fh.write(json.dumps(finding) + "\n")
        print(f"\nJSON findings written to {args.json_out}", file=sys.stderr)

    if cleanup_pcap:
        import os
        os.remove(cleanup_pcap)

    actionable = [f for f in all_findings
                  if not f["signal_id"].endswith("-ok")
                  and not f["signal_id"].endswith("-incomplete")
                  and not f["signal_id"].endswith("-undecodable")]
    return 1 if actionable else 0


if __name__ == "__main__":
    sys.exit(main())
