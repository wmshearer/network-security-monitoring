# Detection Signal Catalogue

Research basis for this lab's detection rules. Every signal traces to a 3GPP
spec, a peer-reviewed paper, or the Open5GS source itself. Researched 2026-09-06.

## Orientation: rogue-BTS detection is NOT solved

3GPP studied this directly in **TR 33.809** (Study on 5G security enhancements
against False Base Stations, 2019-2023) and closed **all seven Key Issues as
"not concluded"**. No normative requirements resulted. The only artefact in a
normative spec is the *informative* Annex E of TS 33.501, which predates the
study and was never made mandatory.

What 5G actually shipped is SUCI (mandatory SUPI concealment, TS 33.501 6.12).
What it left open:
- the **null-scheme** escape hatch (SUCI with no protection)
- pre-authentication NAS and RRC messages, still unauthenticated and unencrypted
- bidding-down to a weaker generation
- **no cryptographic proof that a broadcasting cell belongs to the claimed
  operator** — signed system information never shipped in any release

Recent work (FBSDetector USENIX Security '25, Marlin NDSS 2025, Devilray 2026)
explicitly frames 5G as not immune.

## The core-side advantage

Most published detectors are UE-side: an app on a phone looking outward. This
lab observes from the **core**, which is a different and more operationally
realistic vantage point. It also means the buildable signals are mostly
statistical and behavioural (failure rates, message rates) rather than
cryptographic cell-authenticity checks, which remain unimplemented anywhere.

The lab's unique advantage: it owns ground truth. It runs the legitimate gNBs
AND can spin up a rogue one with an arbitrary PLMN/TAC/Cell ID. A real-world
detector never gets that.

## Priority signals (implement in this order)

| # | Signal | Where observed | Logic |
|---|--------|----------------|-------|
| 1 | 5G-AKA **MAC failure** rate | NAS Auth Failure cause 20; `fivegs_amffunction_amf_authfail{cause=20}` | Spike from one SUCI/gNB = forged challenge or replay |
| 2 | 5G-AKA **sync failure** storm | NAS Auth Failure cause 21; Open5GS tracks `auth_synch_fail_count`, rejects after >=2 | Repeated resync = SQN desync, consistent with replay |
| 3 | **Null-scheme SUCI** outside permitted cases | Registration Request SUCI IE, `protection_scheme_id == 0` | TS 33.501 6.12.2 permits null-scheme in only 3 cases. Anything else re-exposes SUPI in cleartext. Smoking gun. |
| 4 | Registration request flood | `fivegs_amffunction_rm_reginitreq` vs `..._succ`/`..._fail` | Rate spike or success-ratio collapse |
| 5 | **Cell-identity allowlist violation** | NGAP NG Setup Request, PLMN+TAC+Cell ID | Not on the operator allowlist = candidate rogue cell. 100% reliable here. |
| 6 | Auth reject / ngKSI-already-in-use | `fivegs_amffunction_amf_authreject`, cause 22 | Threshold per subscriber/cell |
| 7 | PDU session creation failure/flood | `fivegs_smffunction_sm_pdusessioncreationreq/succ/fail` | Session churn from one subscriber |
| 8 | N4/PFCP session establishment failures | `fivegs_smffunction_sm_n4sessionestabreq/fail` | Correlates with rogue RAN or UPF injection |
| 9 | RAN UE vs AMF session divergence | `ran_ue` vs `amf_session` gauges | Divergence suggests MITM/relay or NAS desync |
| 10 | Paging request/success divergence | `fivegs_amffunction_mm_paging5greq/succ` | Excessive paging for one subscriber |
| 11 | **2G: Cipher Mode Command selecting A5/0** | Um via GSMTAP (pre-cipher by design), OsmoMSC log | The textbook IMSI-catcher signature. 2G has no network authentication. |
| 12 | **2G: Identity Request before ciphering** | Um GSMTAP capture | Asking IMSI in clear from a UE that already has a valid TMSI |
| 13 | **4G: Cleartext IMSI in Attach Request** | S1AP InitialUEMessage, NAS-EPS EPS mobile identity IE, `type_of_id == 1` | TS 24.301 5.5.1.2.2 mandates IMSI (unconcealed) whenever the UE has no valid GUTI - LTE never got a SUCI-equivalent concealment mechanism. Direct 4G analogue of signal #12/#3. |
| 14 | **4G: Identity Request soliciting IMSI** | NAS-EPS Identity Request, plain/unprotected NAS | Same pre-security-context "ask for identity" mechanism as 2G/5G; inherited unchanged into LTE. |
| 15 | **4G: Null-integrity or null-ciphering selected** | NAS-EPS Security Mode Command, `type_of_ciph_alg`/`type_of_int_alg == 0` (EEA0/EIA0) | TS 33.401 5.1.4.5/6.3.1.1 restrict EEA0/EIA0 to unauthenticated emergency calls. Selecting either for a normal subscriber defeats EPS-AKA's confidentiality/integrity purpose. |
| 16 | **4G: eNodeB identity allowlist violation** | S1AP S1 Setup Request, PLMN+eNB ID+TAC | Same "no cryptographic proof of cell identity" gap as signal #5, one generation earlier. Not on the operator allowlist = candidate rogue eNodeB. |
| 17 | **3G: HNB-identity allowlist violation** | HNBAP HNB REGISTER REQUEST, PLMN+HNB-Identity string | TS 25.469 9.2.1/9.2.19 - id-HNB-Identity is an operator-defined string with no mandated format or authentication of its own, sent before any mutual auth at this layer. Same "no cryptographic proof of identity" gap as signals #5/#16, two generations earlier. Implemented and proven in `detector/iuh_detector.py`. |
| — | **3G: cleartext IMSI in HNBAP UE REGISTER REQUEST** | HNBAP UE REGISTER REQUEST, id-UE-Identity IE (TS 25.469 9.2.13) | NOT implemented - this lab never captured a real HNBAP UE REGISTER REQUEST (no RF-free path to a Uu/PHY/RRC client reachable within the 3G tier's effort budget; see `docs/3G-TIER.md`). Listed here as the candidate signal, deliberately left unimplemented rather than written as a hollow/unverified check. |

## Verified Open5GS telemetry (read from source, HEAD 2026-09-03)

Confirmed by reading `src/{amf,smf,upf,pcf,mme}/metrics.c` directly, not docs.

**AMF** — gauges `ran_ue`, `amf_session`, `gnb`; counters
`fivegs_amffunction_rm_reginitreq/succ`, `rm_regmobreq/succ`,
`rm_regperiodreq/succ`, `rm_regemergreq/succ`, `mm_paging5greq/succ`,
`amf_authreq`, `amf_authreject`, `mm_confupdate/succ`; by-cause counters
`rm_reginitfail`, `rm_regmobfail`, `rm_regperiodfail`, `amf_authfail`;
histogram `rm_regtime`; by-slice gauge `rm_registeredsubnbr`.

**SMF** — `gn_rx_parse_failed`, `s5c_rx_parse_failed`, N4 session counters,
PDU session counters by slice, QoS-flow gauge by 5QI, gauges `ues_active`,
`bearers_active`, `pfcp_sessions_active`.

**UPF and PCF also have metrics.c**, which the official tutorial does not
document. Direct-source finding.

Metrics enabled per-NF via `metrics: server: [{address, port}]`, default 9090,
scraped by Prometheus.

**Wireshark** dissects NGAP, NAS-5GS, S1AP, GTPv1-U/GTPv2-C and PFCP, so all
core signalling here is decodable before touching Prometheus.

## Folklore, flagged (do NOT repeat these)

- **"Enriched measurement reports with MIB/SIB hashing"** — TR 33.809 Solution
  #4, a *proposal that was never adopted*. Blogs describe it as operational.
- **"UE-positioning-based FBS detection"** — Solution #22, same status.
- **"Digitally signed broadcast SI is part of 5G"** — false. Solution #20
  (Digital Signing Network Function), never deployed anywhere.
- **"5G solves IMSI catchers via SUCI"** — oversimplification, contradicted by
  the null-scheme exception and by 2024-2026 academic work.
- **"Empty paging" as a detection signature** — could NOT be traced to any
  primary source. Repeated in blogs. Treat as unverified.
- **"FBS-Radar" / "white-stingray"** — could not be verified as real findable
  projects. Do not cite.

## Detector projects (verified via GitHub API 2026-09-06)

| Project | Detects | Side | Maintained | Licence |
|---------|---------|------|-----------|---------|
| SnoopSnitch (SRLabs) | 2G/3G/4G catchers, SS7, silent SMS | UE | **Stale** (2022-05-17) | GPL-3.0 |
| AIMSICD (CellularPrivacy) | 2G/3G heuristics | UE | Active (2026-09-04) but completeness long debated | GPL-3.0 |
| Crocodile Hunter (EFF) | LTE cell-site simulators via SDR | SDR | **Archived** (2023-02-16) | GPL-3.0 |
| SeaGlass (UW) | City-scale catcher detection | Sensor | **Abandoned** (2017-06-22) | Unclear |
| FBSDetector | Fake BS via NAS/RRC sequence modelling | UE | Academic, USENIX Sec '25 | Unverified |
| Marlin | 53 identity-exposing messages, statistical | UE | Academic, NDSS 2025 | Unverified |

## Open questions

**RESOLVED 2026-09-06 (live lab):** `fivegs_amffunction_amf_authfail` carries the
**literal 5GMM cause number** as its label, not a coarser bucket. Observed
`fivegs_amffunction_amf_authfail{cause="21"}` on the running lab, corroborated by
the AMF log line `Authentication failure(Synch failure[count=0])` at
`gmm-sm.c:2182`. Cause 21 is Synch failure per the NAS spec, so signals #1 (MAC
failure, cause 20) and #2 (sync failure, cause 21) are separable in Grafana with
no extra instrumentation. `rm_reginitfail` labels its cause the same way
(observed `cause="7"`, Illegal UE, from a pre-provisioning registration attempt).
Evidence: `evidence/metrics-authfail-cause-label.txt`.

This was resolved by accident: a UE booting before its subscriber existed
produced a real, unforced authentication failure, which is exactly the class of
event signal #2 is meant to catch.

Still open:
- TR 33.809 Annex B (taxonomy of radio-interface attacks) seen in the TOC but
  not extracted; worth cross-referencing.

## Sources

- 3GPP TR 33.809 v1.0.0 (SP-230570), Study on 5G security enhancements against
  False Base Stations
- 3GPP TS 33.501, Security architecture and procedures for 5G, esp. 6.12 (SUCI)
  and informative Annex E
- Open5GS source, HEAD 2026-09-03
- FBSDetector (arXiv 2401.04958, USENIX Security '25); Marlin (NDSS 2025);
  Devilray (arXiv 2605.19232)
