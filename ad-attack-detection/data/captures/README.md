# Captures used by this project

The raw pcaps are not committed to this repository. They belong to a
third-party lab dump, not to this project, and are not ours to redistribute.
This file lists what belongs in this directory and where to get it.

## Source

`github.com/elcabezzonn/Pcaps` (a personal AD lab dump; the repository carries
no LICENSE file, so treat the captures as available for analysis, not for
redistribution).

Lab environment: domain `picklesworth.local`, domain controller
`snicklefritz.picklesworth.local` at `192.168.1.195`, client/test host at
`192.168.1.46`.

## Files this analysis expects here

| File | Packets | Used by |
|---|---|---|
| `dcsync.pcapng` | 23 | `src/dcsync.py` |
| `find_service_accounts.pcap` | 81 | `src/spn_recon.py` |
| `tinkersec-ldapsearch.pcap` | 252 | `src/ldap_recon.py` |
| `net_group_DAs.pcap` | 86 | `src/samr_enum.py` |

Download these four files from the source repository above and place them
directly in this directory before running `scripts/run_analysis.py` or the
test suite's integration checks.

## Files intentionally NOT used

- `rubeus-kerberoast-cmdline-parameter.pcap` was pulled from the same source
  and discarded after verification: it contains LDAP traffic only, zero
  Kerberos frames, and its filename overclaims what it holds. It is not
  cited anywhere in this project's findings. This is a reminder that a
  filename is a claim, not a fact, and verifying capture contents against
  their names caught a mislabeled file before it could taint a finding.
- `mta-catbomber/` (Trickbot "Catbomber", malware-traffic-analysis.net,
  2020-05-28) is a parked capture for a possible future addition (it reaches
  a domain controller over SMB), not part of the current four detections.
  Its archive is password-protected; the password is not yet available.

See `../../VERIFIED-CAPTURES.md` for how each usable capture's contents were
confirmed against the packets themselves, not inferred from filenames.
