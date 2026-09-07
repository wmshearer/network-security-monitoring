#!/usr/bin/env python3
"""
lte_detector.py - Identity-exposure and security-posture detector for
4G/LTE S1AP/NAS-EPS.

WHY THIS EXISTS
----------------
This lab's 2G and 5G tiers both show the same failure at opposite ends of
cellular history: GSM has no mutual authentication at all (the network
authenticates the handset, never the reverse), and 5G's SUCI conceals the
permanent identity but ships no key by default, so the SUPI goes out in
the clear anyway. LTE sits in between and is where the 2G weakness was
ACTUALLY fixed: EPS-AKA gives the UE a real way to authenticate the
network too (via AUTN), not just the reverse. But LTE still transmits the
IMSI in the clear in the initial Attach Request whenever the UE has no
valid GUTI - exactly the gap SUCI was later built to close. This script
answers, from real captured packets, whether LTE actually fixed identity
exposure or only the network-impersonation half of the problem.

Every signal below is described in docs/4G-TIER.md and
docs/DETECTION-SIGNALS.md, which cite their 3GPP sources. This script
re-cites the source in each finding so the output is defensible without
cross-referencing another file.

HOW IT WORKS
------------
Same approach as ../detector/ngap_detector.py and ../detector/
gsm_detector.py, deliberately kept in the same style: tshark does all
protocol parsing (S1AP ASN.1 PER decoding, NAS-EPS IE decoding) - this
script never touches raw bytes. We shell out to `tshark -T fields` once
per capture per signal, requesting exactly the fields that signal needs,
and reason about the resulting rows in plain Python. No third-party
Python packages - standard library plus `subprocess` calling the system
`tshark` binary only.

SIGNALS IMPLEMENTED
--------------------
  Cleartext IMSI in Attach Request      (NAS-EPS Attach Request)
  Identity Request soliciting IMSI      (NAS-EPS Identity Request)
  Null-integrity or null-ciphering      (NAS-EPS Security Mode Command)
  eNodeB identity allowlist violation   (S1AP S1 Setup Request)

USAGE
-----
  Offline against a pcap:
    ./lte_detector.py --pcap evidence/4g/lte-attach-full.pcap

  Live against an interface (needs CAP_NET_RAW / root, e.g. the lab's
  Docker bridge such as br-<network-id>):
    sudo ./lte_detector.py --iface br-89d61b12981f --duration 30

  Both modes accept --allowlist to point at a different allowlist file
  and --identity-request-threshold to change the Identity Request
  signal's sensitivity.
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

# 3GPP TS 24.301 Table 9.8.1: NAS-EPS EMM message type values (decimal, as
# tshark's nas_eps.nas_msg_emm_type field reports them). Confirmed against
# this lab's own installed tshark by decoding a real captured Attach
# procedure end to end (evidence/4g/lte-attach-full.pcap), not assumed
# from the spec table alone - same discipline ngap_detector.py and
# gsm_detector.py use.
NAS_MSG_ATTACH_REQUEST = 0x41
NAS_MSG_ATTACH_ACCEPT = 0x42
NAS_MSG_ATTACH_COMPLETE = 0x43
NAS_MSG_IDENTITY_REQUEST = 0x55
NAS_MSG_IDENTITY_RESPONSE = 0x56
NAS_MSG_AUTHENTICATION_REQUEST = 0x52
NAS_MSG_SECURITY_MODE_COMMAND = 0x5d

# TS 24.301 9.9.3.4 (EPS mobile identity): Type of identity IE values, as
# tshark's nas-eps.emm.type_of_id field reports them.
EPS_IDENTITY_TYPE_IMSI = 1
EPS_IDENTITY_TYPE_GUTI = 6

# TS 24.301 9.9.3.23/9.9.3.32 (Type of ciphering/integrity protection
# algorithm), as tshark's nas-eps.emm.toc / nas-eps.emm.toi fields report
# them. 0 is EEA0/EIA0 - the NULL algorithm in both cases - in both IEs.
EEA_EIA_NULL = 0

DEFAULT_IDENTITY_REQUEST_THRESHOLD = 1

# tshark field sets - pulled in ONE call per signal (see ngap_detector.py's
# own hard-won lesson, documented there in detail: two separate tshark
# calls against the same capture can silently return different row COUNTS
# for the same display filter, misaligning any downstream zip()/positional
# pairing). Every field a signal's logic needs is requested together.
S1_SETUP_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "e212.mcc",
    "e212.mnc",
    "s1ap.macroENB_ID",
    "s1ap.tAC",
    "s1ap.ENBname",
]

ATTACH_REQUEST_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "nas-eps.emm.type_of_id",
    "e212.imsi",
    "e212.assoc.imsi",
]

IDENTITY_REQUEST_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
]

SECURITY_MODE_COMMAND_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "nas-eps.emm.toc",
    "nas-eps.emm.toi",
]


# --------------------------------------------------------------------------
# tshark plumbing (identical approach to ngap_detector.py/gsm_detector.py)
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
                          bpf_filter="sctp port 36412 or (udp portrange 2152-2153) or (udp port 2123)"):
    """Capture live traffic to a pcap file first, then run every signal's
    display filter against that single capture - same rationale as
    ngap_detector.py's equivalent function. The BPF filter matches
    S1AP (SCTP 36412), GTPv2-C (UDP 2123), and GTP-U (UDP 2152/2153),
    covering every interface this tier's EPC exposes on the Docker
    bridge.
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
    """Load the eNodeB cell-identity allowlist. See
    detector/allowlist_lte.json for the schema and how to derive each
    field from a real S1 Setup Request.
    """
    with open(path) as fh:
        data = json.load(fh)
    cells = []
    for entry in data.get("cells", []):
        cells.append({
            "name": entry.get("name", "(unnamed)"),
            "mcc": str(entry["plmn"]["mcc"]),
            "mnc": str(entry["plmn"]["mnc"]),
            "enb_id_hex": entry["enb_id_hex"].lower(),
            "tac": int(entry["tac"]),
        })
    return cells


def allowlist_lookup(cells, mcc, mnc, enb_id_hex, tac):
    """Return the matching allowlist entry, or None if (mcc, mnc,
    enb_id_hex, tac) is not on the allowlist. eNB ID is compared as the
    raw on-wire hex byte string (not reinterpreted as an integer of a
    particular bit-width), matching how allowlist_lte.json documents
    deriving it - macro/home/short-macro/long-macro eNB IDs all have
    different bit-lengths per TS 36.413 9.2.1.37, so comparing the raw
    hex avoids conflating two different ID types that happen to share a
    numeric value.
    """
    for cell in cells:
        if (cell["mcc"] == mcc and cell["mnc"] == mnc
                and cell["enb_id_hex"] == enb_id_hex and cell["tac"] == tac):
            return cell
    return None


# --------------------------------------------------------------------------
# Finding helper (identical schema to ngap_detector.py/gsm_detector.py)
# --------------------------------------------------------------------------

def make_finding(signal_id, severity, summary, observed, expected, citation,
                  frame_number=None, packet_time_epoch=None):
    """Build one structured finding. Same fixed schema as the other two
    detectors' make_finding(), so a downstream consumer that already
    handles their JSON lines needs no changes to also handle this one.
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
# Signal - Cleartext IMSI in Attach Request
# --------------------------------------------------------------------------

def check_cleartext_imsi_attach(pcap_path):
    """The direct 4G analogue of the 2G tier's signal #12 and the 5G
    tier's null-scheme SUCI finding, and the actual point of this whole
    tier: LTE's Attach Request carries an EPS Mobile Identity IE that can
    be either a GUTI (if the UE has one stored from a previous
    registration) or the permanent identity, IMSI, sent completely in the
    clear - there is no encryption mechanism for this IE at all in LTE
    (SUCI's ECIES concealment did not exist yet; it was introduced in 5G
    specifically to close this exact gap). TS 24.301 5.5.1.2.2 specifies
    the UE MUST use IMSI, unconcealed, whenever it has no valid GUTI
    (e.g. its very first-ever attach, or after the network has
    invalidated its stored GUTI) - this is not a misconfiguration or an
    attacker forcing it, it is the NORMAL, SPEC-MANDATED fallback path,
    which is exactly why it matters: any passive observer on the S1
    interface (or the radio interface, in a real deployment) sees the
    subscriber's permanent identity on totally ordinary occasions, not
    just during an attack.

    This detector reports every IMSI-type Attach Request as a finding -
    it is not something the detector can second-guess as "should have
    used a GUTI instead" (that depends on whether the UE actually had a
    valid GUTI, which is out of band), the same posture ngap_detector.py
    takes for null-scheme SUCI and gsm_detector.py takes for cleartext
    IMSI on Um.
    """
    findings = []
    rows = run_tshark_fields(
        pcap_path,
        f"nas_eps.nas_msg_emm_type == {NAS_MSG_ATTACH_REQUEST}",
        ATTACH_REQUEST_FIELDS,
    )
    if not rows:
        findings.append(make_finding(
            signal_id="lte-imsi-clear-ok",
            severity="info",
            summary="No Attach Request observed in this capture.",
            observed={"attach_request_count": 0},
            expected="At least one Attach Request, for a capture spanning "
                     "an LTE Attach procedure.",
            citation="3GPP TS 24.301 clause 5.5.1.2 (Attach procedure)",
        ))
        return findings

    for row in rows:
        type_of_id_raw = row["nas-eps.emm.type_of_id"]
        if type_of_id_raw == "":
            continue
        type_of_id = int(type_of_id_raw)
        imsi = row["e212.imsi"] or row["e212.assoc.imsi"] or None
        observed = {
            "frame": row["frame.number"],
            "src_ip": row["ip.src"],
            "type_of_identity": type_of_id,
            "imsi_cleartext": imsi,
        }
        if type_of_id == EPS_IDENTITY_TYPE_IMSI:
            findings.append(make_finding(
                signal_id="lte-imsi-clear",
                severity="high",
                summary="Attach Request used EPS Mobile Identity type "
                        "IMSI (not GUTI) - the subscriber's permanent "
                        "identity was sent in the clear, unencrypted, in "
                        "this NAS-EPS message. This is the direct LTE "
                        "analogue of the 2G tier's cleartext-IMSI finding "
                        "and the 5G tier's null-scheme SUCI finding: LTE "
                        "has no identity-concealment mechanism at all for "
                        "this IE (SUCI's ECIES concealment was introduced "
                        "later, in 5G, specifically to close this gap).",
                observed=observed,
                expected="EPS Mobile Identity type GUTI, used whenever "
                         "the UE holds a valid one from a prior "
                         "registration - IMSI is the spec-mandated "
                         "fallback (TS 24.301 5.5.1.2.2) only when no "
                         "valid GUTI exists, which is itself a normal, "
                         "unavoidable occurrence (first-ever attach, "
                         "GUTI invalidated by the network, etc.), not "
                         "solely an attack indicator.",
                citation="3GPP TS 24.301 clause 5.5.1.2.2 and clause "
                         "9.9.3.4 (EPS mobile identity IE); "
                         "docs/4G-TIER.md",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
        else:
            id_name = "GUTI" if type_of_id == EPS_IDENTITY_TYPE_GUTI else f"type {type_of_id}"
            findings.append(make_finding(
                signal_id="lte-imsi-clear-ok",
                severity="info",
                summary=f"Attach Request used EPS Mobile Identity "
                        f"{id_name} - permanent identity (IMSI) was not "
                        f"exposed in this message.",
                observed=observed,
                expected="EPS Mobile Identity type GUTI",
                citation="3GPP TS 24.301 clause 9.9.3.4",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
    return findings


# --------------------------------------------------------------------------
# Signal - Identity Request soliciting IMSI
# --------------------------------------------------------------------------

def check_identity_request(pcap_path, threshold):
    """NAS-EPS Identity Request is the network asking the UE "tell me who
    you are" - sent as plain NAS signalling before a security context is
    established (it can legitimately be needed the very first time the
    MME sees a UE, before EPS-AKA has run at all). This is the exact same
    mechanism, and the exact same underlying weakness, as 2G's Identity
    Request (gsm_detector.py signal #12) and 5G's NAS-5GS Identity
    Request (ngap_detector.py signal #8): any device able to inject or
    trigger this message can solicit a UE's permanent identity, and LTE
    inherited the same pre-security-context procedure without closing
    the gap.

    Reported unconditionally whenever observed, same posture as the other
    two detectors' equivalent checks - the spec-compliant use case (MME
    genuinely cannot resolve a GUTI) and IMSI-catcher misuse are wire-
    identical; only external context can distinguish them.
    """
    findings = []
    rows = run_tshark_fields(
        pcap_path,
        f"nas_eps.nas_msg_emm_type == {NAS_MSG_IDENTITY_REQUEST}",
        IDENTITY_REQUEST_FIELDS,
    )
    if not rows:
        findings.append(make_finding(
            signal_id="lte-identity-request-ok",
            severity="info",
            summary="No Identity Request observed in this capture.",
            observed={"identity_request_count": 0},
            expected=f"Fewer than {threshold} Identity Request(s) under "
                     f"normal operation.",
            citation="3GPP TS 24.301 clause 5.4.4 (Identity Request "
                     "procedure); docs/DETECTION-SIGNALS.md signal #12 "
                     "(2G/4G/5G share this mechanism)",
        ))
        return findings

    count = len(rows)
    observed = {
        "identity_request_count": count,
        "frames": [r["frame.number"] for r in rows],
    }
    signal_id = "lte-identity-request" if count >= threshold else "lte-identity-request-ok"
    severity = "high" if count >= threshold else "info"
    findings.append(make_finding(
        signal_id=signal_id,
        severity=severity,
        summary=f"{count} Identity Request(s) observed on the S1AP/"
                f"NAS-EPS interface - the network asked for the "
                f"subscriber's identity via plain, pre-security-context "
                f"NAS signalling, the same textbook IMSI-catcher "
                f"technique GSM and 5G both inherited.",
        observed=observed,
        expected=f"Fewer than {threshold} Identity Request(s) per "
                 f"capture window under normal operation.",
        citation="3GPP TS 24.301 clause 5.4.4 (Identity Request "
                 "procedure, sent as plain/unprotected NAS)",
        frame_number=rows[-1]["frame.number"],
        packet_time_epoch=rows[-1]["frame.time_epoch"],
    ))
    return findings


# --------------------------------------------------------------------------
# Signal - Null-integrity or null-ciphering in Security Mode Command
# --------------------------------------------------------------------------

def check_null_security_algorithms(pcap_path):
    """The NAS Security Mode Command is where the MME tells the UE which
    integrity and ciphering algorithms to use from that point on, chosen
    from whichever the UE advertised support for, in the MME's own
    configured preference order (config/open5gs-4g/mme.yaml's
    integrity_order / ciphering_order). EIA0/EEA0 (the null algorithms)
    exist ONLY for one legitimate case per TS 33.401 5.1.4.5/6.3.1.1:
    unauthenticated emergency calls, where the network must let the call
    through even though it cannot verify the caller's identity or protect
    the signalling. Selecting EIA0/EEA0 for a normal, fully-authenticated
    subscriber defeats the purpose of running EPS-AKA at all - integrity
    protection and/or confidentiality is simply absent from that point
    forward, and the UE has no way to refuse this network-side choice
    (same "network decides, handset cannot object" structural gap
    signal #11 - GSM's Cipher Mode Command - and the wider "no
    cryptographic proof of cell identity" issue TR 33.809 studied and
    left open, both describe).

    This detector distinguishes integrity (nas-eps.emm.toi) from
    ciphering (nas-eps.emm.toc) explicitly, since selecting null
    ciphering with real integrity protection (a real, observed
    configuration in this lab - see docs/4G-TIER.md) is a materially
    different, and lesser, exposure than null integrity: with null
    ciphering only, NAS signalling contents (including the IMSI carried
    in later messages, and user-plane traffic once bearers are up) travel
    unencrypted, but the network can still detect any tampering; with
    null integrity, NAS messages themselves can be forged or replayed
    undetected, which is the more severe failure.
    """
    findings = []
    rows = run_tshark_fields(
        pcap_path,
        f"nas_eps.nas_msg_emm_type == {NAS_MSG_SECURITY_MODE_COMMAND}",
        SECURITY_MODE_COMMAND_FIELDS,
    )
    if not rows:
        findings.append(make_finding(
            signal_id="lte-null-security-ok",
            severity="info",
            summary="No Security Mode Command observed in this capture "
                    "(EPS-AKA/NAS security setup was not completed, or "
                    "the capture does not span it).",
            observed={"security_mode_command_count": 0},
            expected="A Security Mode Command selecting non-null "
                     "integrity and ciphering algorithms for a normal, "
                     "authenticated subscriber.",
            citation="3GPP TS 33.401 clause 6.3.1 (NAS security mode "
                     "control procedure); docs/4G-TIER.md",
        ))
        return findings

    for row in rows:
        toc_raw = row["nas-eps.emm.toc"]
        toi_raw = row["nas-eps.emm.toi"]
        if toc_raw == "" or toi_raw == "":
            findings.append(make_finding(
                signal_id="lte-null-security-incomplete",
                severity="warning",
                summary="Security Mode Command seen but ciphering/"
                        "integrity algorithm IEs could not be fully "
                        "decoded (truncated capture, or a malformed/"
                        "non-conformant message).",
                observed={"frame": row["frame.number"], "toc_raw": toc_raw,
                          "toi_raw": toi_raw},
                expected="Both Type of ciphering algorithm and Type of "
                         "integrity protection algorithm IEs present, "
                         "per TS 24.301 9.9.3.23/9.9.3.32.",
                citation="3GPP TS 24.301 clauses 9.9.3.23, 9.9.3.32",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
            continue

        toc = int(toc_raw)
        toi = int(toi_raw)
        observed = {
            "frame": row["frame.number"],
            "type_of_ciphering_algorithm": toc,
            "type_of_integrity_algorithm": toi,
        }

        if toi == EEA_EIA_NULL:
            findings.append(make_finding(
                signal_id="lte-null-integrity",
                severity="critical",
                summary="Security Mode Command selected EIA0 (null "
                        "integrity algorithm) - NAS signalling from this "
                        "point on has NO integrity protection at all and "
                        "can be forged or replayed undetected. EIA0 is "
                        "meant only for unauthenticated emergency calls; "
                        "its presence here is a serious finding.",
                observed=observed,
                expected="A non-null integrity algorithm (EIA1 or EIA2) "
                         "for any normal, authenticated subscriber.",
                citation="3GPP TS 33.401 clause 5.1.4.5 and clause "
                         "6.3.1.1 (EIA0 restricted to unauthenticated "
                         "emergency calls); docs/4G-TIER.md",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
        else:
            findings.append(make_finding(
                signal_id="lte-null-integrity-ok",
                severity="info",
                summary=f"Security Mode Command selected a non-null "
                        f"integrity algorithm (EIA{toi}).",
                observed=observed,
                expected="A non-null integrity algorithm",
                citation="3GPP TS 33.401 clause 6.3.1.1",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))

        if toc == EEA_EIA_NULL:
            findings.append(make_finding(
                signal_id="lte-null-ciphering",
                severity="high",
                summary="Security Mode Command selected EEA0 (null "
                        "ciphering algorithm) - NAS signalling and, once "
                        "bearers are established, user-plane traffic "
                        "travel WITHOUT confidentiality protection. EEA0 "
                        "is meant only for unauthenticated emergency "
                        "calls; selecting it for a normal authenticated "
                        "subscriber defeats the confidentiality purpose "
                        "of running EPS-AKA at all, even though "
                        "integrity may still be intact (checked "
                        "separately above).",
                observed=observed,
                expected="A non-null ciphering algorithm (EEA1, EEA2, or "
                         "EEA3) for any normal, authenticated subscriber.",
                citation="3GPP TS 33.401 clause 5.1.4.5 and clause "
                         "6.3.1.1 (EEA0 restricted to unauthenticated "
                         "emergency calls); docs/4G-TIER.md",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
        else:
            findings.append(make_finding(
                signal_id="lte-null-ciphering-ok",
                severity="info",
                summary=f"Security Mode Command selected a non-null "
                        f"ciphering algorithm (EEA{toc}).",
                observed=observed,
                expected="A non-null ciphering algorithm",
                citation="3GPP TS 33.401 clause 6.3.1.1",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
    return findings


# --------------------------------------------------------------------------
# Signal - eNodeB identity allowlist violation (S1 Setup Request)
# --------------------------------------------------------------------------

def check_enb_identity_allowlist(pcap_path, allowlist_cells):
    """The 4G analogue of ngap_detector.py's signal #5 (NGAP NG Setup
    Request) and gsm_detector.py's LAC/ARFCN allowlist check: every
    eNodeB announces itself to the MME with an S1 Setup Request the
    moment it connects, before any authentication of the eNodeB itself
    happens - S1AP has no cryptographic proof anywhere that an eNodeB's
    claimed identity is genuine, the exact same "no cryptographic proof
    of cell identity" gap TR 33.809 studied for 5G and left open (this
    lab's own docs/DETECTION-SIGNALS.md, "Orientation") is equally true,
    if not more so (LTE predates that entire study), for LTE's S1
    interface. The S1 Setup Request carries the eNodeB's Global eNB ID
    (PLMN + eNB ID) and its Supported TAs List - an eNodeB can claim
    whatever it wants in these fields.

    Same logic as the other two detectors' allowlist checks: this lab
    owns ground truth about which eNodeBs are supposed to exist
    (detector/allowlist_lte.json), so any S1 Setup Request presenting an
    identity that isn't listed is a candidate rogue base station.
    """
    findings = []
    rows = run_tshark_fields(
        pcap_path,
        "s1ap.procedureCode == 17",  # id-S1Setup - matches Request/
                                     # Response/Failure alike; filtered to
                                     # Request specifically below via the
                                     # presence of macroENB_ID, which only
                                     # appears in the Request direction.
        S1_SETUP_FIELDS,
    )
    for row in rows:
        enb_id_hex = row["s1ap.macroENB_ID"]
        if not enb_id_hex:
            # This is an S1SetupResponse/Failure (MME -> eNB direction),
            # which shares procedureCode 17 but carries no eNB identity
            # IEs at all - not an error, just not a Request. Skip
            # silently rather than emitting a misleading "incomplete"
            # finding for a message type that was never supposed to have
            # these fields.
            continue

        mcc = row["e212.mcc"]
        mnc = row["e212.mnc"]
        tac_raw = row["s1ap.tAC"]
        enb_name = row["s1ap.ENBname"] or "(no eNBname)"

        if not mcc or not tac_raw:
            findings.append(make_finding(
                signal_id="lte-enb-allowlist-incomplete",
                severity="warning",
                summary="S1 Setup Request seen but mandatory identity IEs "
                        "could not be fully decoded (truncated capture, "
                        "or a malformed/non-conformant message).",
                observed={"frame": row["frame.number"], "mcc": mcc,
                          "enb_id_hex": enb_id_hex, "tac_raw": tac_raw},
                expected="Global eNB ID (PLMN + eNB ID) and Supported "
                         "TAs List fully present, per TS 36.413 9.1.8.4.",
                citation="3GPP TS 36.413 9.1.8.4 (S1 SETUP REQUEST)",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
            continue

        tac = int(tac_raw)
        enb_id_hex = enb_id_hex.lower()
        match = allowlist_lookup(allowlist_cells, mcc, mnc, enb_id_hex, tac)
        observed = {
            "frame": row["frame.number"],
            "src_ip": row["ip.src"],
            "enb_name": enb_name,
            "plmn": f"{mcc}/{mnc}",
            "enb_id_hex": enb_id_hex,
            "tac": tac,
        }
        if match is None:
            expected_desc = ", ".join(
                f"{c['name']}: PLMN {c['mcc']}/{c['mnc']}, eNB-ID "
                f"0x{c['enb_id_hex']}, TAC {c['tac']}"
                for c in allowlist_cells
            ) or "(allowlist is empty)"
            findings.append(make_finding(
                signal_id="lte-enb-allowlist-violation",
                severity="critical",
                summary="S1 Setup Request presented a (PLMN, eNB ID, "
                        "TAC) identity that is not on the allowlist - "
                        "candidate rogue eNodeB.",
                observed=observed,
                expected=f"One of the allowlisted cells: {expected_desc}",
                citation="3GPP TS 36.413 9.1.8.4 (S1 SETUP REQUEST, "
                         "Global eNB ID + Supported TAs List IEs); "
                         "docs/DETECTION-SIGNALS.md signal #5 (4G "
                         "analogue)",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
        else:
            findings.append(make_finding(
                signal_id="lte-enb-allowlist-ok",
                severity="info",
                summary="S1 Setup Request identity matches an "
                        "allowlisted eNodeB.",
                observed=observed,
                expected=f"Matched: {match['name']}",
                citation="3GPP TS 36.413 9.1.8.4 (S1 SETUP REQUEST)",
                frame_number=row["frame.number"],
                packet_time_epoch=row["frame.time_epoch"],
            ))
    if not rows:
        findings.append(make_finding(
            signal_id="lte-enb-allowlist-ok",
            severity="info",
            summary="No S1 Setup procedure observed in this capture.",
            observed={"s1_setup_count": 0},
            expected="At least one S1 Setup Request, for a capture "
                     "spanning eNodeB connection to the MME.",
            citation="3GPP TS 36.413 9.1.8.4",
        ))
    return findings


# --------------------------------------------------------------------------
# Console summary (same format as ngap_detector.py/gsm_detector.py)
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "warning": 2, "info": 3}


def print_console_summary(all_findings):
    actionable = [f for f in all_findings
                  if not f["signal_id"].endswith("-ok")
                  and not f["signal_id"].endswith("-incomplete")]
    print("=" * 78)
    print("LTE S1AP/NAS-EPS IDENTITY-EXPOSURE / SECURITY-POSTURE DETECTOR - SUMMARY")
    print("=" * 78)
    if not actionable:
        print("No findings. All observed S1 Setup / Attach / Identity / Security Mode")
        print("procedures matched expected, allowlisted, policy-compliant behaviour.")
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


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Detect LTE identity-exposure and security-posture "
                    "indicators in S1AP/NAS-EPS traffic.",
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
                        help="Path to the eNodeB cell-identity allowlist JSON file. "
                             "Default: allowlist_lte.json next to this script.")
    parser.add_argument("--identity-request-threshold", type=int,
                        default=DEFAULT_IDENTITY_REQUEST_THRESHOLD,
                        help=f"Fire the Identity Request signal at this many Identity "
                             f"Requests per capture. Default {DEFAULT_IDENTITY_REQUEST_THRESHOLD}.")
    parser.add_argument("--json-out", default=None,
                        help="Write findings as JSON lines (one finding per line) to "
                             "this path, in addition to stdout.")
    args = parser.parse_args()

    allowlist_path = args.allowlist or (
        __file__.rsplit("/", 1)[0] + "/allowlist_lte.json" if "/" in __file__
        else "allowlist_lte.json"
    )
    try:
        allowlist_cells = load_allowlist(allowlist_path)
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"ERROR: could not load allowlist from {allowlist_path}: {exc}", file=sys.stderr)
        return 2

    cleanup_pcap = None
    if args.iface:
        pcap_path = args.save_pcap or f"/tmp/lte_detector_live_{int(time.time())}.pcap"
        if not args.save_pcap:
            cleanup_pcap = pcap_path
        print(f"Capturing on {args.iface} for {args.duration}s "
              f"(filter: sctp port 36412 or udp portrange 2152-2153 or udp port 2123) "
              f"-> {pcap_path}", file=sys.stderr)
        capture_live_to_pcap(args.iface, args.duration, pcap_path)
    else:
        pcap_path = args.pcap

    all_findings = []
    all_findings += check_enb_identity_allowlist(pcap_path, allowlist_cells)
    all_findings += check_cleartext_imsi_attach(pcap_path)
    all_findings += check_identity_request(pcap_path, args.identity_request_threshold)
    all_findings += check_null_security_algorithms(pcap_path)

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
