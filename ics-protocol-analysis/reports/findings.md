# Industrial control system traffic: what 15 hours of a live ICS network shows

Capture: 4SICS Geek Lounge ICS lab, 2015. 2,274,000 packets over 15 hours of a
working industrial network with real PLCs from multiple vendors. Credit CS3Sthlm
for capturing and sharing it.

Two questions, because ICS networks fail differently from IT networks: who is
commanding the physical equipment, and what is being sent in the clear.

## Part 1: Who commands the PLCs

99,528 Modbus packets. **42.2% of operations are writes**, meaning they change
device state rather than report it.

That distinction is the whole analysis. A read reports a value. A write changes a
coil, a register, a setpoint, and on the other end of that register is a valve, a
breaker, or a motor. An unauthorised read is an information leak. An unauthorised
write is a physical event.

| Function | Count | Share | Type |
|---|---|---|---|
| Read Coils | 51,346 | 51.7% | read |
| Read/Write Multiple Registers | 20,594 | 20.7% | **write** |
| Write Multiple Coils | 20,592 | 20.7% | **write** |
| Read Input Registers | 2,287 | 2.3% | read |
| Read Discrete Inputs | 1,887 | 1.9% | read |
| Read Holding Registers | 1,884 | 1.9% | read |
| Write Single Coil | 388 | 0.4% | **write** |
| Write Single Register | 386 | 0.4% | **write** |

**Function 23 is classified as a write.** Its name is "Read/Write Multiple
Registers" and it begins with "Read", which makes it the single easiest function
to misclassify. It writes. Treating it as a read would let a state change past
the check that exists specifically to catch state changes, and it is 20.7% of all
traffic here.

### The host picture

| Host | Operations | Reads | Writes | Targets | Inferred role |
|---|---|---|---|---|---|
| 192.168.2.166 | 49,701 | 28,721 | 20,980 | 4 | engineering workstation / HMI |
| 192.168.2.44 | 22 | 22 | 0 | 5 | monitoring |
| 192.168.2.133 | 26 | 26 | 0 | 5 | monitoring |
| 192.168.2.137 | 1 | 1 | 0 | 1 | monitoring |

One host issues every write on the network. Everything else only reads. That is a
clean, defensible baseline, and it is exactly what a detection rule keys on:
**alert on any write from a host that is not 192.168.2.166.**

### A bug worth documenting

The first run of this analysis reported three PLCs as engineering workstations,
each issuing thousands of writes.

That was wrong, and the output looked entirely reasonable. Modbus servers echo the
function code when they reply, so counting every packet carrying function code 15
counts each write twice: once as the command, once as the device confirming it.
The effect is that every PLC appears to be issuing the writes it merely answered,
which inverts the entire question of who is commanding whom.

The fix is to decide direction from which side owns port 502. Traffic where
neither side is on 502 is still counted rather than discarded, because Modbus on
a non-standard port is exactly the traffic worth seeing.

This is the kind of error that produces a confident, well-formatted, wrong answer.
Nothing crashed and no number looked implausible.

## Part 2: What crosses the wire in the clear

Four protocols on this network transmit authentication with no encryption.

| Protocol | Exposures | Hosts | What was found |
|---|---|---|---|
| SNMP | 536 | 2 | Community string `public` on every packet |
| Telnet | 49 sessions | 13 | Full session in plaintext, credentials included |
| FTP | 42 | 7 | USER and PASS as plaintext commands |
| HTTP | 18 | 9 | NTLM authentication headers to PLCs |

**SNMP `public` on every packet.** This is the factory-default read community. It
grants read access to the device's entire management tree: interfaces, routing,
configuration, uptime. Finding it is equivalent to finding equipment still on its
shipped password.

**Telnet across 13 hosts.** Telnet transmits everything in the clear, including
the password as it is typed. Sessions here run to nearly 2,000 packets.

**FTP credentials from 7 hosts.** USER and PASS are plaintext commands by
specification (RFC 959).

**NTLM headers to PLCs** was the unexpected one. It appeared in a check written
for HTTP Basic auth. NTLM is not plaintext, but it is a challenge-response scheme
with well-documented relay and cracking weaknesses, and finding it protecting a
PLC's web interface is a different and more interesting problem than Basic auth.

### On redaction

Every password in this analysis is redacted to its length. The finding is that
credentials for a named account crossed this network unencrypted, and the
username, protocol and endpoints establish that completely. Printing the password
adds nothing and makes the report a second exposure, one that lives in a
repository and on a website.

Usernames and community strings are **not** redacted. Which account or device is
exposed is the actionable half, and `public` is the finding itself.

Telnet is recorded as session endpoints only. Reconstructing typed keystrokes is
possible, since Telnet is character-by-character with server echo, and it would
produce a document containing working credentials for someone else's equipment.

## Why ICS inverts the usual detection question

On an IT network you look for credentials being misused. **Modbus has no
credentials.** It has no authentication of any kind. The protocol was designed in
1979 for a serial cable inside a locked cabinet, and putting it on TCP did not add
a security model. Any host that can reach port 502 can command a PLC, and the PLC
will comply, because nothing in the protocol lets it refuse.

So the question changes shape. Not "was this authorised" but "which hosts are
supposed to write, and is anything else writing". That allow-list is an
operational fact about the site. It cannot be derived from the traffic, because
deriving it from observed behaviour would define whatever happened as authorised,
which is precisely the assumption an intruder benefits from.

## Limitations

1. **This is a conference demonstration lab, not a production plant.** The traffic
   is real and the equipment is real, but the baseline of a working facility would
   be busier and messier.
2. **No attack is present in this capture.** These are baseline and hygiene
   findings. The write-authorisation control is demonstrated against normal
   traffic, which shows it produces no false positives here, not that it catches
   an attacker.
3. **Inferred roles are labels for an analyst, not verdicts.** A compromised
   engineering workstation performing its normal function would carry exactly the
   same label.
4. **The capture is from 2015.** Modbus and S7comm have not changed, so the
   protocol analysis holds. Specific device software has moved on.
5. **106,421 S7comm packets are present and not analysed here.** Siemens S7comm
   is a proprietary protocol with no public specification, so it warrants its own
   treatment rather than a footnote.

## Provenance

Capture: 4SICS Geek Lounge ICS lab, hosted by Netresec, credit CS3Sthlm as the
publisher requests. Protocol semantics follow the Modbus Application Protocol
Specification v1.1b3. Analysis is `python3 scripts/run_analysis.py` and
`python3 scripts/run_cleartext.py`; 24 tests cover the classification logic.
