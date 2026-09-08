# Screenshot evidence index

Real Wireshark GUI captures (Xvfb + `wireshark` + `scrot`, no headless-tshark
substitution) and two Grafana dashboard renders, one line each so a reader
knows what's in an image without opening it. Frame numbers refer to
`evidence/rogue-gnb-detection.pcap` (5G) and `evidence/2g/*.pcap` (2G) and
were independently verified with `tshark -V` before each screenshot was taken.

## 5G tier (NGAP / NAS-5GS, `evidence/rogue-gnb-detection.pcap`)

- `5g-rogue-ng-setup-detail.png` — Frame 42, the rogue gNB's NG Setup
  Request with the detail pane expanded down to Global RAN Node ID; shows
  `gNB-ID: 00baddad` and `tAC: 666 (0x00029a)` in the Supported TA List,
  the exact fields signal #5 (cell-identity allowlist) fires on.
- `5g-legitimate-ng-setup-detail.png` — Frame 14, the legitimate gNB's NG
  Setup Request with the same fields expanded, showing `gNB-ID: 00000010`
  and `tAC: 1 (0x000001)` — the contrast pair for the rogue capture above,
  same message type, same pcap.
- `5g-null-scheme-suci-detail.png` — Frame 22, the UE's Registration
  Request (InitialUEMessage) with the NAS-5GS 5GS Mobile Identity expanded,
  showing `Type of identity: SUCI (1)`, `Protection scheme Id: NULL scheme
  (0)`, and `MSIN: 0000000001` sent in the clear — the null-scheme SUCI
  finding (signal #3).
- `5g-ngap-packet-list.png` — Packet list filtered on `ngap || nas-5gs`
  (15 of 70 packets), giving the full NGAP/NAS conversation for context:
  legitimate NG Setup, InitialUEMessage/Registration, Authentication,
  Security Mode, InitialContextSetup, PDU Session Setup, then the rogue
  gNB's NG Setup Request/Failure at the end.

## 4G tier (S1AP / NAS-EPS, `evidence/4g/lte-attach-full.pcap`)

- `lte-s1ap-nas-packet-list.png` — Packet list filtered on
  `s1ap or nas_eps` (13 of 59 packets), the complete procedure: S1 Setup
  Request/Response, then the full LTE Attach (InitialUEMessage/Attach
  request, Authentication request/response, Security mode command/
  complete, ESM information request/response, InitialContextSetupRequest/
  Attach accept, InitialContextSetupResponse/Attach complete, EMM
  information).
- `lte-attach-request-imsi-detail.png` — Frame 17, the Attach Request
  (InitialUEMessage) with the embedded NAS-EPS PDU expanded down to EPS
  mobile identity, showing `Type of identity: IMSI (1)` and
  `IMSI: 999700000000099` in the clear — the tier's own headline finding:
  LTE has no identity-concealment mechanism, so the permanent identity is
  exposed on this ordinary, spec-mandated first attach.
- `lte-security-mode-command-detail.png` — Frame 24, the Security Mode
  Command with NAS security algorithms expanded, showing
  `Type of ciphering algorithm: EPS encryption algorithm EEA0 (null
  ciphering algorithm)` alongside `Type of integrity protection algorithm:
  EPS integrity algorithm 1...` (EIA2, real) — confirms integrity is
  protected but confidentiality is not, traced to Open5GS's own
  unmodified stock `ciphering_order` default.
- `lte-s1-setup-request-enb-id-detail.png` — Frame 5, the legitimate
  eNodeB's S1 Setup Request expanded to Global-ENB-ID, showing
  `pLMNidentity: 99f907` (MCC 999/MNC 70) and `macroENB-ID: 0019b0` — the
  fields `detector/lte_detector.py`'s eNodeB identity allowlist check
  matches against `detector/allowlist_lte.json`.

## 2G tier (GSM A-I/F DTAP, `evidence/2g/*.pcap`)

- `gsm-location-update-packet-list.png` — `gsm_a.dtap`-filtered packet
  list of a complete Location Update, from Location Updating Request
  through Channel Release, including Authentication and Ciphering Mode
  Command/Complete.
- `gsm-cipher-mode-a50-detail.png` — Ciphering Mode Command from the A5/0
  (null-cipher) capture, expanded, showing `Cipher Mode Setting: SC: No
  ciphering (0)` — signal #11.
- `gsm-cipher-mode-a51-detail-contrast.png` — The same message type from
  the A5/1 capture, expanded, showing `SC: Start ciphering (1)` and
  `Algorithm identifier: Cipher with algorithm A5/1` — the contrast pair
  for signal #11.
- `gsm-identity-response-imsi-detail.png` — Identity Response from a
  TMSI-holding subscriber that got asked for its permanent identity anyway
  (VLR restart scenario), expanded to show `Mobile Identity - IMSI
  (001010000000001)` decoded in the clear — signal #12.

## 3G tier (Iuh HNBAP, `evidence/3g/iuh-hnb-register.pcap`)

This tier is core-network-plus-Iuh-signalling only (no Uu air interface,
no real handset — see `docs/3G-TIER.md`'s explicit RF-boundary
statement), so these screenshots show HNBAP (HNB-to-HNBGW registration
signalling), not a UE/RRC exchange.

- `umts-iuh-packet-list.png` — Full packet list of the Iuh SCTP
  association: SCTP INIT/INIT_ACK/COOKIE_ECHO/COOKIE_ACK handshake,
  then `HNBAP HNB_REGISTER_REQUEST` (frame 5) and
  `HNBAP HNB_REGISTER_ACCEPT` (frame 7) with their SACKs — the complete,
  real HNB-to-HNBGW registration exchange, zero radio.
- `umts-hnb-register-identity-detail.png` — Frame 5 (HNB_REGISTER_REQUEST)
  with `Item 0: id-HNB-Identity` expanded down to `HNB-Identity-Info`;
  the corresponding hex bytes are highlighted in the byte pane and decode
  to the ASCII string `CellDetectLab-hNodeB-01`, this lab's own
  configured HNB identity (`config/osmocom/osmo-hnodeb.cfg`) — the exact
  field this tier's HNB-identity allowlist check (see `docs/3G-TIER.md`)
  would evaluate.
- `umts-hnb-register-accept-detail.png` — Frame 7 (HNB_REGISTER_ACCEPT)
  fully expanded: `successfulOutcome`, `procedureCode: id-HNBRegister
  (1)`, `HNBRegisterAccept`, `id-RNC-ID`, `RNC-ID: 23` — osmo-hnbgw's own
  RNC-ID assignment back to the HNB, confirming the registration
  completed successfully.

Note on these three: the packet tree for the HNB_REGISTER_REQUEST message
(frame 5) is deep enough (HNBAP-PDU > initiatingMessage > value >
HNBRegisterRequest > protocolIEs > Item N > ProtocolIE-Field > id/
criticality/value) that Wireshark's fixed-size window under bare Xvfb
(same GTK layout limitation documented in `NOTES.md` for the 2G tier —
no window manager under Xvfb, so the panes will not resize) could not
show the PLMNidentity item's own decoded value (MCC 001/MNC 01) on
screen at once alongside the necessary parent-node context; that decode
is confirmed instead in `evidence/3g/iuh-hnb-register-hnbap-detail.txt`
(`tshark -V` text output, not a screenshot) rather than fabricating or
cropping a misleading image.

## Detection dashboards (Grafana, live data from the running 5G lab)

- `5g-core-health.png` — "5G Core Health" dashboard: AMF/SMF/UPF/PCF
  Prometheus metrics (registration/auth counters, PFCP sessions, etc.).
- `cellular-threat-detection.png` — "Cellular Threat Detection" dashboard:
  panels built on the same Prometheus metrics for anomaly/attack-signal
  visibility (auth failures by cause, registration attempt rates, etc.).
