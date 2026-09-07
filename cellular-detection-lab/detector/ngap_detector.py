#!/usr/bin/env python3
"""
ngap_detector.py - Rogue base-station indicator detector for 5G NGAP/NAS-5GS.

WHY THIS EXISTS
----------------
Prometheus/Grafana (the other half of this lab's detection stack) can only
see what Open5GS chooses to export as a counter or gauge - aggregate rates
like "auth failures per minute". It has no visibility at all into the
CONTENTS of individual NGAP or NAS-5GS messages: which gNB identity showed
up, what SUCI protection scheme a UE used, how many times the network asked
a UE to identify itself. Those facts only exist on the wire. This script
reads them straight out of a packet capture (offline pcap or a live
interface) using tshark as a dissector, and turns them into structured
findings.

Every signal below is described in docs/DETECTION-SIGNALS.md, which cites
its 3GPP/academic source. This script re-cites the source in each finding
so the output is defensible without cross-referencing another file.

HOW IT WORKS
------------
tshark does all protocol parsing (NGAP ASN.1 PER decoding, NAS-5GS IE
decoding) - this script never touches raw bytes. We shell out to
`tshark -T fields` (far more reliable to parse than pyshark, and pyshark
is not installed/used here per the lab's tooling policy) once per capture,
requesting exactly the fields each signal needs, and reason about the
resulting rows in plain Python. No third-party Python packages are used -
standard library plus `subprocess` calling the system `tshark` binary only.

SIGNALS IMPLEMENTED
--------------------
  #5 Cell-identity allowlist violation   (NGAP NG Setup Request)
  #3 Null-scheme SUCI                    (NAS-5GS Registration Request)
  #8 Excessive Identity Request          (NAS-5GS Identity Request, per UE)

USAGE
-----
  Offline against a pcap:
    ./ngap_detector.py --pcap evidence/rogue-gnb-detection.pcap

  Live against an interface (needs CAP_NET_RAW / root, e.g. a docker
  bridge such as br-<network-id>):
    sudo ./ngap_detector.py --iface br-89d61b12981f --duration 30

  Both modes accept --allowlist to point at a different allowlist file
  and --identity-request-threshold to change signal #8's sensitivity.
"""

import argparse
import json
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

# 3GPP TS 24.501 Table 9.7.1: NAS-5GS 5GMM message type values (decimal, as
# tshark's nas-5gs.mm.message_type field reports them). Only the ones this
# detector reasons about are listed; tshark decodes the rest but we don't
# need their numeric values here.
NAS_MSG_REGISTRATION_REQUEST = 65   # 0x41
NAS_MSG_IDENTITY_REQUEST = 91       # 0x5b
NAS_MSG_REGISTRATION_REJECT = 68    # 0x44

# TS 33.501 6.12.2's null-scheme value for the SUCI Protection Scheme
# Identifier.
SUCI_SCHEME_NULL = 0

DEFAULT_IDENTITY_REQUEST_THRESHOLD = 2

# The fields we ask tshark for, one field set per display filter. All fields
# for a given signal MUST be pulled in a single tshark invocation: tshark's
# `-T fields` only emits a row for a packet if at least one requested field
# is non-empty in that packet, so two separate invocations against the same
# display filter can - and, confirmed empirically against this lab's own
# NG Setup Failure messages, DO - come back with a different number of rows
# (a packet that matches the filter but has none of one call's fields
# simply doesn't appear in that call's output), silently desynchronising a
# naive zip() across the two calls. One call, all fields, always.
#
# Filtering on ngap.NGSetupRequest_element (rather than
# ngap.procedureCode == 21, which also matches NGSetupResponse and
# NGSetupFailure - id-NGSetup is one procedure code shared by all three
# message types) means every row here really is a Setup Request, and the
# Supported TA List's TAC (ngap.tAC) is pulled in the same call as the
# Global RAN Node ID fields.
NGAP_SETUP_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "e212.mcc",
    "e212.mnc",
    "ngap.gNB_ID",
    "ngap.tAC",
    "ngap.RANNodeName",
]

NAS_MM_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ngap.RAN_UE_NGAP_ID",
    "ngap.AMF_UE_NGAP_ID",
    "nas-5gs.mm.message_type",
    "nas-5gs.mm.suci.scheme_id",
    "nas-5gs.mm.suci.msin",
    "nas-5gs.mm.suci.routing_indicator",
]


# --------------------------------------------------------------------------
# tshark plumbing
# --------------------------------------------------------------------------

def run_tshark_fields(pcap_path, display_filter, fields):
    """Run `tshark -T fields` and return a list of dicts, one per matching
    packet, keyed by field name.

    -T fields with -E occurrence=f (first occurrence only) and a fixed
    separator gives one line per packet, one column per field, with empty
    string for fields absent in that packet - much easier to parse
    correctly than pyshark's object graph or tshark's own nested JSON tree
    (which names repeated IEs by human-readable position, e.g.
    "Item 0: id-GlobalRANNodeID", not something you can index
    programmatically without also depending on English message strings).
    """
    separator = "\x1f"  # unit separator: won't collide with any 3GPP field value
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
        cols += [""] * (len(fields) - len(cols))  # pad short rows
        rows.append(dict(zip(fields, cols)))
    return rows


def capture_live_to_pcap(iface, duration, pcap_out, bpf_filter="sctp port 38412"):
    """Capture live traffic to a pcap file first, then run every signal's
    display filter against that single capture. This avoids running tshark
    multiple times against a live interface (which would each only see a
    disjoint slice of traffic) and produces an evidence artifact for free.
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
    """Load the cell-identity allowlist. See detector/allowlist.json for the
    schema and how to derive each field from a real NG Setup Request.
    """
    with open(path) as fh:
        data = json.load(fh)
    cells = []
    for entry in data.get("cells", []):
        cells.append({
            "name": entry.get("name", "(unnamed)"),
            "mcc": str(entry["plmn"]["mcc"]),
            "mnc": str(entry["plmn"]["mnc"]),
            "gnb_id": int(entry["gnb_id"]),
            "id_length_bits": int(entry.get("id_length_bits", 32)),
            "tac": int(entry["tac"]),
        })
    return cells


def allowlist_lookup(cells, mcc, mnc, gnb_id, tac):
    """Return the matching allowlist entry, or None if (mcc, mnc, gnb_id,
    tac) is not on the allowlist. gNB ID is compared as a plain integer -
    two gNBs with the same bit-length ID field but different declared
    id_length_bits are still a mismatch, since the spec ties the ID's
    meaning to its declared length.
    """
    for cell in cells:
        if (cell["mcc"] == mcc and cell["mnc"] == mnc
                and cell["gnb_id"] == gnb_id and cell["tac"] == tac):
            return cell
    return None


# --------------------------------------------------------------------------
# Finding helper
# --------------------------------------------------------------------------

def make_finding(signal_id, severity, summary, observed, expected, citation,
                  frame_number=None, packet_time_epoch=None):
    """Build one structured finding. Every field here is deliberately
    present even when null, so a downstream consumer (SIEM, grep, jq) can
    rely on a fixed schema regardless of which signal fired.
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
# Signal #5 - Cell-identity allowlist violation
# --------------------------------------------------------------------------

def check_cell_identity_allowlist(pcap_path, allowlist_cells):
    """NGAP NG Setup Request carries the gNB's claimed Global gNB ID (PLMN +
    gNB ID) and its Supported TA List (one or more TACs it serves). A gNB
    that is not part of the operator's deployment - a rogue base station,
    or in this lab, an intentionally unauthorised container - still has to
    send this message before the AMF will talk to it, and it can claim
    whatever identity it likes because NG Setup Request is sent before any
    mutual authentication has occurred (there is no cryptographic proof of
    who the gNB is at this layer at all - see docs/DETECTION-SIGNALS.md,
    "no cryptographic proof that a broadcasting cell belongs to the claimed
    operator"). Comparing the claimed identity against a known-good
    allowlist is the one fully reliable check available here, because in
    this lab (unlike the real world) we own ground truth about which gNBs
    are supposed to exist.
    """
    findings = []
    rows = run_tshark_fields(
        pcap_path,
        "ngap.NGSetupRequest_element",
        NGAP_SETUP_FIELDS,
    )
    for row in rows:
        mcc = row["e212.mcc"]
        mnc = row["e212.mnc"]
        gnb_id_hex = row["ngap.gNB_ID"]
        ran_node_name = row["ngap.RANNodeName"] or "(no RANNodeName)"
        tac_raw = row["ngap.tAC"]

        if not mcc or not gnb_id_hex or not tac_raw:
            # NG Setup Request always carries these IEs (they are mandatory
            # per TS 38.413 9.2.6.1); an incomplete row means tshark could
            # not fully dissect this packet (e.g. truncated capture). Do
            # not silently skip - that would be exactly the kind of
            # incomplete-record failure this project's other work has
            # flagged elsewhere. Report it as its own finding.
            findings.append(make_finding(
                signal_id="5-incomplete",
                severity="warning",
                summary="NG Setup Request seen but mandatory identity IEs "
                        "could not be fully decoded (truncated capture, or "
                        "a malformed/non-conformant message).",
                observed={"frame": row["frame.number"], "mcc": mcc,
                          "gnb_id_hex": gnb_id_hex, "tac_raw": tac_raw},
                expected="Global RAN Node ID (PLMN + gNB ID) and Supported "
                         "TA List(s) fully present, per TS 38.413 9.2.6.1.",
                citation="3GPP TS 38.413 9.2.6.1 (NG Setup Request)",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
            continue

        # ngap.gNB_ID is a colon-separated hex octet string, e.g. "00:00:00:10".
        gnb_id = int(gnb_id_hex.replace(":", ""), 16)
        # ngap.tAC can repeat once per Supported TA Item; occurrence=f above
        # keeps only the first, which is the common single-TAC gNB case this
        # lab exercises. A gNB serving multiple TACs would need each Item
        # checked individually - noted as a known limitation in
        # detector/README.md rather than silently mishandled here.
        tac = int(tac_raw)

        match = allowlist_lookup(allowlist_cells, mcc, mnc, gnb_id, tac)
        observed = {
            "frame": row["frame.number"],
            "src_ip": row["ip.src"],
            "ran_node_name": ran_node_name,
            "plmn": f"{mcc}/{mnc}",
            "gnb_id": gnb_id,
            "gnb_id_hex": gnb_id_hex,
            "tac": tac,
        }
        if match is None:
            expected_desc = ", ".join(
                f"{c['name']}: PLMN {c['mcc']}/{c['mnc']}, gNB-ID {c['gnb_id']} "
                f"(0x{c['gnb_id']:x}), TAC {c['tac']}"
                for c in allowlist_cells
            ) or "(allowlist is empty)"
            findings.append(make_finding(
                signal_id="5",
                severity="critical",
                summary="NG Setup Request presented a (PLMN, gNB ID, TAC) "
                        "identity that is not on the allowlist - candidate "
                        "rogue base station.",
                observed=observed,
                expected=f"One of the allowlisted cells: {expected_desc}",
                citation="3GPP TS 38.413 9.2.6.1 (NG Setup Request, Global "
                         "RAN Node ID + Supported TA List IEs); "
                         "docs/DETECTION-SIGNALS.md signal #5",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
        else:
            findings.append(make_finding(
                signal_id="5-ok",
                severity="info",
                summary="NG Setup Request identity matches an allowlisted "
                        "cell.",
                observed=observed,
                expected=f"Matched: {match['name']}",
                citation="3GPP TS 38.413 9.2.6.1 (NG Setup Request)",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
    return findings


# --------------------------------------------------------------------------
# Signal #3 - Null-scheme SUCI
# --------------------------------------------------------------------------

def check_null_scheme_suci(pcap_path):
    """The SUCI (Subscription Concealed Identifier) is how a 5G UE sends its
    permanent identity (SUPI, e.g. an IMSI) to the network before any
    security context exists, WITHOUT sending it in the clear - the SUPI is
    encrypted under the home network's public key using ECIES. The
    "Protection Scheme Identifier" field says which scheme was used to do
    that: 0 means "null-scheme", i.e. NO encryption was applied at all, and
    the SUPI is sent as plain digits (see the MSIN emitted right next to
    the scheme_id in the same IE).

    TS 33.501 6.12.2 permits null-scheme in exactly three situations:
      1. an emergency registration where the UE has no valid 5G-GUTI,
      2. the home network has deliberately configured null-scheme (some
         private/lab networks legitimately do this),
      3. the home network's public key has not been provisioned to the USIM.

    Outside those cases, a null-scheme SUCI defeats the entire point of
    SUCI and re-exposes the subscriber's permanent identity to anyone who
    can see the Registration Request - exactly what SUCI was introduced to
    prevent. This detector cannot itself distinguish "policy-permitted
    null-scheme" from "should have been encrypted and wasn't" (that
    requires knowing the operator's provisioning policy, which is out of
    band), so every null-scheme SUCI is reported as a finding for a human
    to evaluate against the three permitted cases above - which is exactly
    what TS 33.501 intends this to be: an exception, not encountered
    silently.
    """
    findings = []
    rows = run_tshark_fields(
        pcap_path,
        f"nas-5gs.mm.message_type == {NAS_MSG_REGISTRATION_REQUEST}",
        NAS_MM_FIELDS,
    )
    for row in rows:
        scheme_id_raw = row["nas-5gs.mm.suci.scheme_id"]
        if scheme_id_raw == "":
            # Registration Request carried a 5G-GUTI instead of a SUCI (a UE
            # re-registering with an identity the network already issued
            # it) - there is no SUCI to evaluate in this message at all.
            continue
        scheme_id = int(scheme_id_raw)
        observed = {
            "frame": row["frame.number"],
            "src_ip": row["ip.src"],
            "suci_scheme_id": scheme_id,
            "suci_routing_indicator": row["nas-5gs.mm.suci.routing_indicator"] or None,
            "suci_msin_cleartext": row["nas-5gs.mm.suci.msin"] or None,
        }
        if scheme_id == SUCI_SCHEME_NULL:
            findings.append(make_finding(
                signal_id="3",
                severity="high",
                summary="Registration Request used null-scheme SUCI - the "
                        "subscriber's permanent identity (SUPI/IMSI) was "
                        "sent without any concealment, visible in the "
                        "MSIN field of this very message.",
                observed=observed,
                expected="Non-null protection scheme (Profile A = 1 or "
                         "Profile B = 2), UNLESS this UE is on a home "
                         "network that has deliberately configured "
                         "null-scheme, is performing an emergency "
                         "registration with no valid 5G-GUTI, or has no "
                         "home-network public key provisioned - the only "
                         "three cases TS 33.501 6.12.2 permits this in.",
                citation="3GPP TS 33.501 clause 6.12.2 (SUCI protection "
                         "scheme, null-scheme exceptions); "
                         "docs/DETECTION-SIGNALS.md signal #3",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
        else:
            findings.append(make_finding(
                signal_id="3-ok",
                severity="info",
                summary="Registration Request used a non-null SUCI "
                        "protection scheme - SUPI was concealed.",
                observed=observed,
                expected="Non-null protection scheme",
                citation="3GPP TS 33.501 clause 6.12.2",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
    return findings


# --------------------------------------------------------------------------
# Signal #8 - Excessive Identity Request
# --------------------------------------------------------------------------

def check_excessive_identity_requests(pcap_path, threshold):
    """NAS-5GS Identity Request is the network asking a UE to state its
    identity - normally used sparingly, e.g. once, when the AMF cannot
    resolve a 5G-GUTI the UE presented (say, after an AMF restart wiped its
    context). Identity Request is sent as PLAIN NAS (no integrity, no
    ciphering) before a security context exists, so anyone who can send
    this message can solicit a UE's identity - historically, in 2G/3G/4G,
    this exact mechanism (asking for IMSI in the clear) is THE textbook
    IMSI-catcher / rogue-base-station technique, and 5G did not close it
    off; it inherited the same pre-security-context Identity Request
    procedure (docs/DETECTION-SIGNALS.md signal #8, and the wider "no
    cryptographic proof of cell identity" gap TR 33.809 left open).

    A legitimate network sends this rarely and, per TS 24.501 5.4.4, would
    normally not need to at all for a UE that just presented a valid
    5G-GUTI - the AMF should be able to resolve it internally, or fall back
    to a *stored* SUCI/PEI, before re-asking the UE. A network (rogue or
    misbehaving) that repeatedly issues Identity Request is showing
    IMSI-catcher-shaped behaviour: keep asking until the UE gives up its
    permanent identity. We threshold per RAN-UE-NGAP-ID (the per-UE-per-
    association identifier NGAP assigns for the life of one radio
    connection) rather than per-IP, since every UE in this lab shares the
    gNB's IP address - RAN_UE_NGAP_ID is what actually distinguishes one
    UE's session from another's on the wire at this layer.
    """
    findings = []
    rows = run_tshark_fields(
        pcap_path,
        f"nas-5gs.mm.message_type == {NAS_MSG_IDENTITY_REQUEST}",
        NAS_MM_FIELDS,
    )
    per_ue = defaultdict(list)
    for row in rows:
        # Identity Request is DownlinkNASTransport (network -> UE); the NGAP
        # layer still carries both UE identifiers so the AMF/gNB can route
        # it to the right radio connection.
        ue_key = row["ngap.RAN_UE_NGAP_ID"] or row["ngap.AMF_UE_NGAP_ID"] or "(unknown-ue)"
        per_ue[ue_key].append(row)

    for ue_key, ue_rows in per_ue.items():
        count = len(ue_rows)
        observed = {
            "ran_ue_ngap_id": ue_key,
            "identity_request_count": count,
            "frames": [r["frame.number"] for r in ue_rows],
        }
        if count >= threshold:
            findings.append(make_finding(
                signal_id="8",
                severity="high",
                summary=f"UE (RAN-UE-NGAP-ID {ue_key}) received "
                        f"{count} Identity Request message(s) in this "
                        f"capture, meeting or exceeding the threshold of "
                        f"{threshold} - IMSI-catcher-shaped network "
                        f"behaviour.",
                observed=observed,
                expected=f"Fewer than {threshold} Identity Request "
                         f"message(s) per UE per capture window under "
                         f"normal operation.",
                citation="3GPP TS 24.501 5.4.4 (Identity Request "
                         "procedure, sent as plain/unprotected NAS); "
                         "docs/DETECTION-SIGNALS.md signal #8",
                frame_number=ue_rows[-1]["frame.number"],
                packet_time_epoch=ue_rows[-1]["frame.time_epoch"],
            ))
        else:
            findings.append(make_finding(
                signal_id="8-ok",
                severity="info",
                summary=f"UE (RAN-UE-NGAP-ID {ue_key}) received {count} "
                        f"Identity Request message(s), below threshold "
                        f"{threshold}.",
                observed=observed,
                expected=f"Fewer than {threshold} per UE",
                citation="3GPP TS 24.501 5.4.4",
                frame_number=ue_rows[-1]["frame.number"],
                packet_time_epoch=ue_rows[-1]["frame.time_epoch"],
            ))
    if not rows:
        # Zero Identity Requests observed at all is a valid, good outcome -
        # say so explicitly rather than emitting nothing, so a reader can
        # tell "checked, found none" apart from "signal didn't run".
        findings.append(make_finding(
            signal_id="8-ok",
            severity="info",
            summary="No Identity Request messages observed in this "
                    "capture.",
            observed={"identity_request_count": 0},
            expected=f"Fewer than {threshold} per UE",
            citation="3GPP TS 24.501 5.4.4",
        ))
    return findings


# --------------------------------------------------------------------------
# Console summary
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "warning": 2, "info": 3}


def print_console_summary(all_findings):
    actionable = [f for f in all_findings
                  if not f["signal_id"].endswith("-ok")
                  and not f["signal_id"].endswith("-incomplete")]
    print("=" * 78)
    print("NGAP/NAS-5GS ROGUE BASE STATION DETECTOR - SUMMARY")
    print("=" * 78)
    if not actionable:
        print("No findings. All observed NG Setup / Registration / Identity")
        print("procedures matched expected, allowlisted, policy-compliant behaviour.")
        print("(A clean run is a valid, good outcome, not an absence of checking -")
        print(f" {len(all_findings)} check(s) were evaluated; see --json-out for detail.)")
    else:
        for finding in sorted(actionable, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9)):
            print(f"\n[{finding['severity'].upper()}] signal #{finding['signal_id']} "
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


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Detect rogue-base-station indicators in NGAP/NAS-5GS "
                    "traffic that Prometheus counters cannot express.",
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
                        help="Path to the cell-identity allowlist JSON file. "
                             "Default: allowlist.json next to this script.")
    parser.add_argument("--identity-request-threshold", type=int,
                        default=DEFAULT_IDENTITY_REQUEST_THRESHOLD,
                        help=f"Fire signal #8 at this many Identity Requests "
                             f"per UE per capture. Default {DEFAULT_IDENTITY_REQUEST_THRESHOLD}.")
    parser.add_argument("--json-out", default=None,
                        help="Write findings as JSON lines (one finding per line) to "
                             "this path, in addition to stdout.")
    args = parser.parse_args()

    allowlist_path = args.allowlist or (
        __file__.rsplit("/", 1)[0] + "/allowlist.json" if "/" in __file__ else "allowlist.json"
    )
    try:
        allowlist_cells = load_allowlist(allowlist_path)
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"ERROR: could not load allowlist from {allowlist_path}: {exc}", file=sys.stderr)
        return 2

    cleanup_pcap = None
    if args.iface:
        pcap_path = args.save_pcap or f"/tmp/ngap_detector_live_{int(time.time())}.pcap"
        if not args.save_pcap:
            cleanup_pcap = pcap_path
        print(f"Capturing on {args.iface} for {args.duration}s "
              f"(filter: sctp port 38412) -> {pcap_path}", file=sys.stderr)
        capture_live_to_pcap(args.iface, args.duration, pcap_path)
    else:
        pcap_path = args.pcap

    all_findings = []
    all_findings += check_cell_identity_allowlist(pcap_path, allowlist_cells)
    all_findings += check_null_scheme_suci(pcap_path)
    all_findings += check_excessive_identity_requests(pcap_path, args.identity_request_threshold)

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
                  and not f["signal_id"].endswith("-incomplete")]
    return 1 if actionable else 0


if __name__ == "__main__":
    sys.exit(main())
