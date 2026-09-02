# AD attack captures — verified ground truth (2026-08-19)

Source: `github.com/elcabezzonn/Pcaps` (personal lab dump, no LICENSE file).
Lab domain `picklesworth.local`, DC `snicklefritz.picklesworth.local` = 192.168.1.195,
client/attacker = 192.168.1.46. USE FOR ANALYSIS ONLY, credit source, do NOT redistribute
the raw pcaps — link to the repo instead.

All facts below were confirmed by reading the packets with tshark, NOT from filenames.
One file (`rubeus-kerberoast-cmdline-parameter.pcap`) was DISCARDED: it is LDAP-only,
zero Kerberos frames, filename overclaims. Do not cite it.

## 1. DCSync — dcsync.pcapng (23 packets) — USABLE
DRSUAPI over DCERPC. Full chain: DsBind(0) → DsGetDomainControllerInfo(16) →
DsCrackNames(12) → DsBind(0) → **DsGetNCChanges(opnum 3)** → DsUnbind(1).
The artifact: opnum 3 (DsGetNCChanges) at frames 17/20, from 192.168.1.46 → DC.
DETECTION: 192.168.1.46 is a CLIENT, not a DC. Only domain controllers should ever
issue DsGetNCChanges (directory replication). A non-DC replicating = credential theft
of the whole domain. tshark: `drsuapi.opnum==3` and check src is not a known DC.

## 2. SPN enumeration — find_service_accounts.pcap (81 packets) — USABLE for RECON
LDAP filter `(servicePrincipalName=*/*)` present = real SPN-discovery recon
(setspn / PowerView / GetUserSPNs enumeration step).
HONEST NUANCE: the only Kerberos here is AS/TGS for the DC's OWN `ldap` SPN
(SnickleFritz.picklesworth.local), etype **18 (AES256)** — that's the normal SASL bind,
NOT a roast. So this is SPN *discovery*, correctly NOT kerberoasting. Do not label it as
a roast. tshark: `ldap.filter contains "servicePrincipalName"`.

## 3. Manual LDAP recon — tinkersec-ldapsearch.pcap (252 packets) — USABLE
Two searchRequests, both `(objectclass=*)`: one baseObject probe, one authenticated
(chewbacca@picklesworth, simple bind) `wholeSubtree` full-directory dump over
DC=picklesworth,DC=local. No SPN/UAC/samAccountType filters → manual `ldapsearch -x`,
NOT BloodHound/SharpHound. Label as manual recon, not BloodHound.
tshark: `ldap.protocolOp==3` + scope==wholeSubtree(2) + `(objectclass=*)`.

## 4. SAMR Domain Admins enum — net_group_DAs.pcap (86 packets) — USABLE
SAMR over \PIPE\samr. Opnum chain matching `net group "Domain Admins" /domain`:
Connect5(64) → EnumDomains(6) → LookupDomain(5) → OpenDomain(7) → LookupNames(17) →
OpenGroup(19) → QueryGroupMember(20) → GetMembersInGroup(18) → Close(1).
tshark: `samr` and the opnum sequence.

## NOT AVAILABLE (spec-only, no public capture found)
- Kerberoasting proper (RC4/etype-23 TGS-REP for a service account SPN) — none of these
  have it; generating it trips the cyber safeguard. See [[cyber-safeguard-flags-offensive-tooling]].
- AS-REP roasting, LLMNR/NBT-NS poisoning, NTLM relay — no public captures.

## PARKED
- Trickbot "Catbomber" (MTA 2020-05-28) — downloaded to data/captures/mta-catbomber/,
  zip password is an IMAGE on malware-traffic-analysis.net/about.html, needs Will to read it.
  Higher fidelity (real campaign, reaches DC over SMB) — fold in when password provided.
