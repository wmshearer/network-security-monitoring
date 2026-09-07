#!/usr/bin/env python3
"""
gsm_detector.py - IMSI-catcher indicator detector for 2G/GSM (Um interface).

WHY THIS EXISTS
----------------
GSM has NO mutual authentication: the network authenticates the handset
(Authentication Request/Response), but the handset has no way to authenticate
the network in return. That single design gap, present since GSM's original
specification and never retrofitted, is the entire reason IMSI catchers work
against 2G. Two consequences of that gap are directly observable on the Um
(radio) interface and are exactly what this detector looks for:

  #11 the network can unilaterally select A5/0 (the null cipher) in the
      Cipher Mode Command, and the handset has no way to detect or refuse
      it - traffic then goes out completely unencrypted.
  #12 the network can send an Identity Request soliciting the IMSI in the
      clear at any time, including to a handset that already holds a valid
      TMSI (which should make re-asking unnecessary under normal operation).

Both are visible in PLAINTEXT here because this lab's GSMTAP export (the
Virtual Um transport - see ../docs/2G-TIER.md) happens pre-ciphering by
design: GSMTAP is Osmocom's own debug/analysis tap on the Um interface,
inserted at the point in the stack where frames are still plaintext L2/L3,
before whatever ciphering the Cipher Mode Command negotiated would apply to
a real over-the-air transmission. This is what makes it possible to
DEMONSTRATE the gap from the inside on our own network - see
../docs/DETECTION-SIGNALS.md, signals #11 and #12.

HOW IT WORKS
------------
Same approach as ../detector/ngap_detector.py, deliberately kept in the
same style: tshark does all protocol parsing (GSMTAP demux, LAPDm framing,
GSM A-I/F DTAP decoding) - this script never touches raw bytes. We shell
out to `tshark -T fields` once per capture per signal, requesting exactly
the fields that signal needs, and reason about the resulting rows in plain
Python. No third-party Python packages - standard library plus
`subprocess` calling the system `tshark` binary only.

SIGNALS IMPLEMENTED
--------------------
  #11 Cipher Mode Command selecting A5/0 (null cipher)   - severity high
  #12 Identity Request soliciting IMSI                   - severity high
  Bonus: LAC/ARFCN not on the cell-identity allowlist     - severity high
  Bonus: cleartext IMSI anywhere on the Um interface      - severity info
         (informational: a *normal* first-ever attach also does this - see
         signal #12's own docstring for why this is still worth surfacing)

USAGE
-----
  Offline against a pcap:
    ./gsm_detector.py --pcap evidence/2g/location-update-a50-null-cipher.pcap

  Live against an interface (Virtual Um traffic is loopback-only in this
  lab - see ../docs/2G-TIER.md):
    sudo ./gsm_detector.py --iface lo --duration 30

  Both modes accept --allowlist to point at a different cell-identity
  allowlist file.
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

# 3GPP TS 24.008 Table 10.2/3GPP TS 24.008: GSM RR / MM message type values
# (decimal, as tshark's gsm_a.dtap.msg_rr_type / msg_mm_type fields report
# them - confirmed via `tshark -G values` against this lab's own installed
# tshark, not assumed from a spec table, same discipline ngap_detector.py
# uses).
GSM_RR_MSG_CIPHERING_MODE_COMMAND = 0x35
GSM_MM_MSG_IDENTITY_REQUEST = 0x18

# TS 24.008 10.5.1.4: Type of identity IE values, as tshark's
# gsm_a.dtap.type_of_identity field reports them.
IDENTITY_TYPE_IMSI = 1

# TS 44.018 10.5.2.9 (Cipher Mode Setting): the "SC" (start ciphering) bit
# - 0 means no ciphering is applied (A5/0, the null cipher is the *only*
# thing left to select at that point), 1 means ciphering starts using
# whichever A5 algorithm the accompanying Algorithm Identifier names.
CIPHER_SC_NO_CIPHERING = "0"

# TS 24.008 10.5.1.3 (Location Area Identification): LAC 0xFFFE is a
# reserved placeholder value meaning "deleted"/"no valid LAI stored" - a
# handset with no prior LAI (e.g. its very first-ever attach, exactly
# like this lab's synthetic test subscriber) reports THIS value as its
# OLD LAI inside a Location Updating Request, not a real cell identity.
# It must be excluded from the cell-identity allowlist check, or every
# first-ever attach in this lab would falsely flag as a rogue cell.
LAC_DELETED_PLACEHOLDER = 0xFFFE

DEFAULT_IDENTITY_REQUEST_THRESHOLD = 1

# tshark field sets - pulled in ONE call per signal (see ngap_detector.py's
# own hard-won lesson, documented there in detail: two separate tshark
# calls against the same capture can silently return different row COUNTS
# for the same display filter, misaligning any downstream zip()/positional
# pairing). Every field a signal's logic needs is requested together.
CIPHER_MODE_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "gsm_a.rr.SC",
    "gsm_a.rr.algorithm_identifier",
]

IDENTITY_REQUEST_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "gsm_a.dtap.type_of_identity",
]

# Every Location Updating Request / Response pair in this lab is exchanged
# over LAPDm on a single SDCCH with no per-UE identifier at this layer
# comparable to NGAP's RAN-UE-NGAP-ID (this is a single-MS lab; a real BTS
# would key by channel/TDMA-frame or by IMSI once seen - noted as a
# limitation below, same spirit as ngap_detector.py's own limitations
# section for signal #8).
IMSI_CLEARTEXT_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "e212.imsi",
]

LAC_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "e212.lai.mcc",
    "e212.lai.mnc",
    "gsm_a.lac",
    "gsmtap.arfcn",
]


# --------------------------------------------------------------------------
# tshark plumbing (identical approach to ngap_detector.py, by design)
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


def capture_live_to_pcap(iface, duration, pcap_out,
                          bpf_filter="udp portrange 4729-4730"):
    """Capture live GSMTAP traffic (the Virtual Um transport - both the
    downlink 239.193.23.1 and uplink 239.193.23.2 multicast groups share
    the 4729/4730 port range) to a pcap file first, then run every
    signal's display filter against that single capture - same rationale
    as ngap_detector.py's equivalent function.
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
    """Load the GSM cell-identity allowlist. See
    detector/allowlist_gsm.json for the schema and how to derive each
    field from a real capture or this lab's own osmo-bsc-a5*.cfg.
    """
    with open(path) as fh:
        data = json.load(fh)
    cells = []
    for entry in data.get("cells", []):
        cells.append({
            "name": entry.get("name", "(unnamed)"),
            "mcc": str(entry["plmn"]["mcc"]),
            "mnc": str(entry["plmn"]["mnc"]),
            "lac": int(entry["lac"]),
            "arfcn": int(entry.get("arfcn", -1)),
        })
    return cells


def allowlist_lac_lookup(cells, mcc, mnc, lac):
    """Return the matching allowlist entry for (mcc, mnc, lac), or None."""
    for cell in cells:
        if cell["mcc"] == mcc and cell["mnc"] == mnc and cell["lac"] == lac:
            return cell
    return None


# --------------------------------------------------------------------------
# Finding helper (identical schema to ngap_detector.py, deliberately)
# --------------------------------------------------------------------------

def make_finding(signal_id, severity, summary, observed, expected, citation,
                  frame_number=None, packet_time_epoch=None):
    """Build one structured finding. Same fixed schema as
    ngap_detector.py's make_finding(), so a downstream consumer that
    already handles that detector's JSON lines needs no changes to also
    handle this one.
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
# Signal #11 - Cipher Mode Command selecting A5/0 (null cipher)
# --------------------------------------------------------------------------

def check_null_cipher(pcap_path):
    """GSM's Cipher Mode Command (sent by the network to the BTS/MS to
    start ciphering on the dedicated channel) carries a Cipher Mode
    Setting IE with a single "SC" (Start Ciphering) bit and, only when
    SC=1, an Algorithm Identifier naming which A5 variant to use. When
    SC=0, ciphering is explicitly NOT started at all - the traffic that
    follows on this channel is plaintext over the (virtual, in this lab;
    real, in the field) radio interface. This is the textbook IMSI-catcher
    technique: because GSM gives the handset no way to authenticate the
    network, a rogue or misconfigured BTS/BSC can select A5/0 and the
    handset has no cryptographic means to detect or refuse it - most
    phones do not even surface a visible "unencrypted call" indicator.

    This lab's own osmo-bsc-a50.cfg vs osmo-bsc-a51.cfg is the controlled
    demonstration of exactly this: identical network, one "encryption a5"
    config line changed, and the Cipher Mode Command goes from naming A5/1
    to carrying SC=0 with no algorithm at all (see
    ../docs/2G-TIER.md, "Signal #11").
    """
    findings = []
    rows = run_tshark_fields(
        pcap_path,
        f"gsm_a.dtap.msg_rr_type == {GSM_RR_MSG_CIPHERING_MODE_COMMAND}",
        CIPHER_MODE_FIELDS,
    )
    if not rows:
        findings.append(make_finding(
            signal_id="11-ok",
            severity="info",
            summary="No Ciphering Mode Command observed in this capture "
                    "(no dedicated-channel ciphering was negotiated at all - "
                    "e.g. the capture may only cover an unauthenticated "
                    "attempt, or authentication was not required).",
            observed={"ciphering_mode_command_count": 0},
            expected="A Ciphering Mode Command naming a non-null A5 "
                     "algorithm (SC=1) for a subscriber that authenticated.",
            citation="3GPP TS 44.018 clause 3.4.7 (Ciphering mode setting "
                     "procedure); docs/DETECTION-SIGNALS.md signal #11",
        ))
        return findings

    for row in rows:
        sc = row["gsm_a.rr.SC"]
        alg = row["gsm_a.rr.algorithm_identifier"]
        observed = {
            "start_ciphering_bit": sc,
            "algorithm_identifier_raw": alg or None,
        }
        if sc == CIPHER_SC_NO_CIPHERING:
            findings.append(make_finding(
                signal_id="11",
                severity="high",
                summary="Ciphering Mode Command has Start Ciphering (SC) = 0 "
                        "- the network explicitly instructed NO ciphering "
                        "on this channel. This is the A5/0 (null cipher) "
                        "IMSI-catcher signature: traffic on this dedicated "
                        "channel is plaintext over the air, and the "
                        "handset has no way to detect or refuse this "
                        "network-side choice.",
                observed=observed,
                expected="Start Ciphering (SC) = 1 with a non-null "
                         "Algorithm Identifier (A5/1 or stronger), unless "
                         "this network deliberately never ciphers by "
                         "policy (itself worth confirming, not assuming).",
                citation="3GPP TS 44.018 clause 3.4.7 and clause 10.5.2.9 "
                         "(Cipher Mode Setting IE, SC bit); "
                         "docs/DETECTION-SIGNALS.md signal #11",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
        else:
            alg_name = {
                "0": "A5/1", "1": "A5/2", "2": "A5/3",
                "3": "A5/4", "4": "A5/5", "5": "A5/6", "6": "A5/7",
            }.get(alg, f"unknown algorithm id {alg}")
            findings.append(make_finding(
                signal_id="11-ok",
                severity="info",
                summary=f"Ciphering Mode Command selected {alg_name} - "
                        f"ciphering was started (not the null cipher).",
                observed=observed,
                expected="Start Ciphering (SC) = 1 with a non-null "
                         "Algorithm Identifier",
                citation="3GPP TS 44.018 clause 10.5.2.9",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
    return findings


# --------------------------------------------------------------------------
# Signal #12 - Identity Request soliciting IMSI
# --------------------------------------------------------------------------

def check_identity_request(pcap_path, threshold):
    """GSM MM Identity Request is the network asking the handset "tell me
    who you are" - sent as plain, unprotected Layer 3 signalling, because
    it can be (and, in a normal network, sometimes legitimately is) sent
    before any security context exists (e.g. the VLR cannot resolve a
    presented TMSI, most often after a VLR restart or database loss).
    Exactly like NAS-5GS's Identity Request (see
    ../detector/ngap_detector.py signal #8, and
    ../docs/DETECTION-SIGNALS.md signal #12's own framing: "asking for
    IMSI in the clear... is THE textbook IMSI-catcher technique" -
    GSM is in fact the ORIGINAL case this pattern comes from, predating
    3G/4G/5G's own inherited version of the same gap), any device able to
    inject or trigger this message can solicit a handset's permanent
    identity in the clear.

    This is reported unconditionally as a finding whenever a Type of
    Identity = IMSI Identity Request is observed - the spec-compliant use
    case (VLR genuinely lost the subscriber's TMSI mapping) and the
    IMSI-catcher misuse case are wire-identical; only external context
    (does this VLR actually have a reason to have lost that mapping right
    now?) can distinguish them, which is exactly why the finding is
    reported for human judgement, the same posture ngap_detector.py takes
    for its own null-scheme SUCI check.
    """
    findings = []
    rows = run_tshark_fields(
        pcap_path,
        f"gsm_a.dtap.msg_mm_type == {GSM_MM_MSG_IDENTITY_REQUEST}",
        IDENTITY_REQUEST_FIELDS,
    )
    imsi_requests = [r for r in rows
                     if r["gsm_a.dtap.type_of_identity"] == str(IDENTITY_TYPE_IMSI)]

    if not imsi_requests:
        findings.append(make_finding(
            signal_id="12-ok",
            severity="info",
            summary=f"No Identity Request soliciting IMSI observed in this "
                    f"capture ({len(rows)} Identity Request(s) for other "
                    f"identity types, if any).",
            observed={"identity_request_imsi_count": 0,
                      "identity_request_total_count": len(rows)},
            expected=f"Fewer than {threshold} Identity Request(s) "
                     f"soliciting IMSI under normal operation.",
            citation="3GPP TS 24.008 clause 4.3.3 (Identity Request "
                     "procedure); docs/DETECTION-SIGNALS.md signal #12",
        ))
        return findings

    count = len(imsi_requests)
    observed = {
        "identity_request_imsi_count": count,
        "frames": [r["frame.number"] for r in imsi_requests],
    }
    severity = "high" if count >= threshold else "info"
    signal_id = "12" if count >= threshold else "12-ok"
    findings.append(make_finding(
        signal_id=signal_id,
        severity=severity,
        summary=f"{count} Identity Request(s) soliciting IMSI observed on "
                f"the Um interface - the network asked for the permanent "
                f"identity in the clear, unprotected Layer 3 signalling, "
                f"the textbook IMSI-catcher technique. Check whether the "
                f"subscriber already held a valid TMSI at the time (see "
                f"the paired Location Updating Request/Accept in the same "
                f"capture) - re-asking a subscriber who already has a "
                f"valid TMSI is the strongest version of this signature.",
        observed=observed,
        expected=f"Fewer than {threshold} Identity Request(s) soliciting "
                 f"IMSI per capture window under normal operation.",
        citation="3GPP TS 24.008 clause 4.3.3 (Identity Request procedure, "
                 "sent as plain/unprotected Layer 3 signalling); "
                 "docs/DETECTION-SIGNALS.md signal #12",
        frame_number=imsi_requests[-1]["frame.number"],
        packet_time_epoch=imsi_requests[-1]["frame.time_epoch"],
    ))
    return findings


# --------------------------------------------------------------------------
# Bonus - cleartext IMSI anywhere on the Um interface
# --------------------------------------------------------------------------

def check_cleartext_imsi(pcap_path):
    """The IMSI appears in the clear anywhere it is carried as a Mobile
    Identity IE before ciphering starts - most commonly in a Location
    Updating Request from a handset with no valid TMSI yet (its very
    first attach, or after an IMSI Detach) as well as in any Identity
    Response answering an Identity Request (signal #12). This check is
    informational rather than a hard finding on its own: a handset's
    first-ever attach legitimately has no TMSI to present and IMSI is the
    only option TS 24.008 gives it - the finding exists so a reader can
    see directly, in the same report, how many times and in which frames
    the permanent identity was actually visible on the wire, rather than
    only being told a message type fired.
    """
    findings = []
    rows = run_tshark_fields(pcap_path, "e212.imsi", IMSI_CLEARTEXT_FIELDS)
    if not rows:
        findings.append(make_finding(
            signal_id="imsi-clear-ok",
            severity="info",
            summary="No cleartext IMSI observed anywhere on the Um "
                    "interface in this capture.",
            observed={"cleartext_imsi_count": 0},
            expected="IMSI concealed (TMSI used) except on a legitimate "
                     "first-ever attach or a genuine Identity Request.",
            citation="3GPP TS 24.008 clause 4.3.3; "
                     "docs/DETECTION-SIGNALS.md signal #12",
        ))
        return findings

    imsis_seen = sorted(set(r["e212.imsi"] for r in rows if r["e212.imsi"]))
    findings.append(make_finding(
        signal_id="imsi-clear",
        severity="info",
        summary=f"IMSI appeared in the clear on the Um interface in "
                f"{len(rows)} frame(s) ({len(imsis_seen)} distinct "
                f"subscriber(s)). Pre-ciphering GSMTAP capture means this "
                f"is exactly what a passive Um-interface observer (a real "
                f"IMSI catcher, or this lab's own legitimate analysis "
                f"tooling) would also see.",
        observed={"cleartext_imsi_count": len(rows),
                  "imsis": imsis_seen,
                  "frames": [r["frame.number"] for r in rows]},
        expected="IMSI concealed (TMSI used) except on a legitimate "
                 "first-ever attach or a genuine Identity Request.",
        citation="3GPP TS 24.008 clause 4.3.3; "
                 "docs/DETECTION-SIGNALS.md signal #12",
        frame_number=rows[-1]["frame.number"],
        packet_time_epoch=rows[-1]["frame.time_epoch"],
    ))
    return findings


# --------------------------------------------------------------------------
# Bonus - LAC/ARFCN allowlist violation (2G analogue of signal #5)
# --------------------------------------------------------------------------

def check_lac_allowlist(pcap_path, allowlist_cells):
    """GSM has no NGAP-style explicit "setup request" identity check (see
    docs/DETECTION-SIGNALS.md signal #5) - a GSM handset instead learns
    its serving cell's PLMN/LAC/ARFCN from broadcast System Information
    and reflects the LAI back to the network in its own Location Updating
    Request. Comparing every LAI/ARFCN seen on the Um interface against a
    known-good allowlist (detector/allowlist_gsm.json) is the 2G analogue
    of the same idea signal #5 uses for 5G: this lab owns ground truth
    about which cells are legitimate, so any other LAI/ARFCN observed is
    a candidate rogue or misconfigured cell.
    """
    findings = []
    rows = run_tshark_fields(pcap_path, "gsm_a.lac", LAC_FIELDS)
    if not rows:
        findings.append(make_finding(
            signal_id="lac-ok",
            severity="info",
            summary="No LAI/LAC observed in this capture to check against "
                    "the cell-identity allowlist.",
            observed={"lac_count": 0},
            expected="At least one LAI observed and allowlisted, for a "
                     "capture spanning a Location Update.",
            citation="3GPP TS 24.008 clause 10.5.1.3 (Location Area "
                     "Identification); docs/DETECTION-SIGNALS.md signal #5 "
                     "(2G analogue)",
        ))
        return findings

    seen = set()
    for row in rows:
        mcc, mnc, lac_raw, arfcn = (row["e212.lai.mcc"], row["e212.lai.mnc"],
                                     row["gsm_a.lac"], row["gsmtap.arfcn"])
        if not mcc or not lac_raw:
            continue
        try:
            lac = int(lac_raw, 16) if lac_raw.startswith("0x") else int(lac_raw)
        except ValueError:
            continue
        key = (mcc, mnc, lac)
        if key in seen:
            continue
        seen.add(key)
        if lac == LAC_DELETED_PLACEHOLDER:
            findings.append(make_finding(
                signal_id="lac-ok",
                severity="info",
                summary=f"LAI {mcc}-{mnc}-{lac} is the reserved 'deleted/"
                        f"no valid LAI' placeholder (0xFFFE), not a real "
                        f"cell - expected on a subscriber's first-ever "
                        f"attach (its OLD LAI in the Location Updating "
                        f"Request). Not checked against the allowlist.",
                observed={"mcc": mcc, "mnc": mnc, "lac": lac, "arfcn": arfcn or None},
                expected="LAC 0xFFFE only ever appears as an OLD LAI, "
                         "never as a cell's own broadcast LAI",
                citation="3GPP TS 24.008 clause 10.5.1.3",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
            continue
        match = allowlist_lac_lookup(allowlist_cells, mcc, mnc, lac)
        observed = {"mcc": mcc, "mnc": mnc, "lac": lac, "arfcn": arfcn or None}
        if match:
            findings.append(make_finding(
                signal_id="lac-ok",
                severity="info",
                summary=f"LAI {mcc}-{mnc}-{lac} matches allowlisted cell "
                        f"'{match['name']}'.",
                observed=observed,
                expected="LAI present in detector/allowlist_gsm.json",
                citation="docs/DETECTION-SIGNALS.md signal #5 (2G analogue)",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
        else:
            findings.append(make_finding(
                signal_id="lac-violation",
                severity="high",
                summary=f"LAI {mcc}-{mnc}-{lac} is NOT on the cell-identity "
                        f"allowlist (detector/allowlist_gsm.json) - "
                        f"candidate rogue or misconfigured cell.",
                observed=observed,
                expected=f"One of: "
                         f"{[(c['mcc'], c['mnc'], c['lac']) for c in allowlist_cells]}",
                citation="docs/DETECTION-SIGNALS.md signal #5 (2G analogue "
                         "of the NGAP NG Setup Request allowlist check)",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
    return findings


# --------------------------------------------------------------------------
# Console summary (same format as ngap_detector.py)
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "warning": 2, "info": 3}


def print_console_summary(all_findings):
    actionable = [f for f in all_findings
                  if not f["signal_id"].endswith("-ok")
                  and not f["signal_id"].endswith("-incomplete")]
    print("=" * 78)
    print("GSM/2G UM-INTERFACE IMSI-CATCHER DETECTOR - SUMMARY")
    print("=" * 78)
    if not actionable:
        print("No findings. Ciphering, identity handling, and cell identity all")
        print("matched expected, policy-compliant behaviour.")
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
        description="Detect IMSI-catcher indicators in 2G/GSM Um-interface "
                    "traffic (via GSMTAP/Virtual Um).",
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
                        help="Path to the GSM cell-identity allowlist JSON file. "
                             "Default: allowlist_gsm.json next to this script.")
    parser.add_argument("--identity-request-threshold", type=int,
                        default=DEFAULT_IDENTITY_REQUEST_THRESHOLD,
                        help=f"Fire signal #12 at this many IMSI Identity Requests "
                             f"per capture. Default {DEFAULT_IDENTITY_REQUEST_THRESHOLD}.")
    parser.add_argument("--json-out", default=None,
                        help="Write findings as JSON lines (one finding per line) to "
                             "this path, in addition to stdout.")
    args = parser.parse_args()

    allowlist_path = args.allowlist or (
        __file__.rsplit("/", 1)[0] + "/allowlist_gsm.json" if "/" in __file__
        else "allowlist_gsm.json"
    )
    try:
        allowlist_cells = load_allowlist(allowlist_path)
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"ERROR: could not load allowlist from {allowlist_path}: {exc}", file=sys.stderr)
        return 2

    cleanup_pcap = None
    if args.iface:
        pcap_path = args.save_pcap or f"/tmp/gsm_detector_live_{int(time.time())}.pcap"
        if not args.save_pcap:
            cleanup_pcap = pcap_path
        print(f"Capturing on {args.iface} for {args.duration}s "
              f"(filter: udp portrange 4729-4730) -> {pcap_path}", file=sys.stderr)
        capture_live_to_pcap(args.iface, args.duration, pcap_path)
    else:
        pcap_path = args.pcap

    all_findings = []
    all_findings += check_null_cipher(pcap_path)
    all_findings += check_identity_request(pcap_path, args.identity_request_threshold)
    all_findings += check_cleartext_imsi(pcap_path)
    all_findings += check_lac_allowlist(pcap_path, allowlist_cells)

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
