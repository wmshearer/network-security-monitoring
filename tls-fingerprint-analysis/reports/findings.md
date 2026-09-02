# TLS client fingerprinting: what a handshake reveals without decryption

Capture: CTU-13 scenario 42 (Neris botnet, CC BY 2.0), 323,154 packets, 4.8 hours.
Infected host per the publisher's own documentation: `147.32.84.165`.

Nothing here decrypts anything. Every conclusion comes from the ClientHello, which
is sent in the clear before encryption begins, plus connection metadata.

## What was measured

60 TLS ClientHellos, resolving to **5 distinct JA4 fingerprints**.

| JA4 | Seen | TLS | Sends SNI | Server name |
|---|---|---|---|---|
| `t10i460300_234845559c90_a875e5012fde` | 16 | 1.0 | **no** | - |
| `t10i110100_3609b414f052_bc98f8e001b5` | 14 | 1.0 | **no** | - |
| `t10d120300_d94e65cdb899_33a13ba74d1c` | 14 | 1.0 | yes | my.screenname.aol.com |
| `t10i290100_cdba58456bdf_e78b541c01a9` | 12 | 1.0 | **no** | - |
| `t10i110000_3609b414f052_000000000000` | 4 | 1.0 | **no** | - |

**Four of five fingerprints send no server name at all.** The `i` in position 3 of a
JA4 string is the fingerprint declaring that fact about itself.

## Why absent SNI is a question worth asking

A browser fetching a website must send SNI. Shared hosting means one IP serves many
sites, so without a server name the server cannot know which certificate to present.
By 2011 every mainstream browser sent it.

A client that omits SNI is usually connecting to an address rather than a name. That
describes some legitimate software, so it is not proof of anything. It is a narrowing
question: *what is this talking to, and why does it not need to name it?*

## The finding: mirrored fingerprints

Grouping by source rather than by fingerprint alone showed something that a
fingerprint-only table hides completely.

| Source | JA4 | Count | Ports |
|---|---|---|---|
| `147.32.84.165` | `t10i460300_...` | 8 | 443 |
| `212.117.171.138` | `t10i460300_...` | 8 | 1038, 1881 |
| `147.32.84.165` | `t10i110100_...` | 7 | 443 |
| `212.117.171.138` | `t10i110100_...` | 7 | 1461, 1464 |

Every fingerprint appears **twice**: once from the infected host outbound to port 443,
and once from `212.117.171.138` inbound on ephemeral ports. The counts match exactly.

Identical fingerprints in both directions cannot be two different clients. A
fingerprint is a property of the TLS library that built the message, so the same
fingerprint means the same software produced both.

## Ruling out the obvious explanation

**Hypothesis: a TLS interception proxy.** Enterprise middleboxes terminate TLS and
re-originate it, which produces exactly this duplication. It was the first reading and
it is wrong.

**Test.** Inspect the certificates presented on those connections. An intercepting
proxy must present its own certificate, because it does not hold the real server's
private key.

**Result.** The certificates are genuine VeriSign Class 3 Extended Validation certs.
No interception occurred.

**What it actually is.** `212.117.171.138` receives **17,138 packets on port 65500**,
carrying 11.2 MB outbound against 2.7 MB inbound. Port 65500 is not a service port and
that asymmetry is data leaving the host. The mirrored handshakes are the infected
host's TLS sessions travelling through a tunnel and surfacing inside it.

The fingerprint duplication is a side effect of the tunnel, and it is visible with no
knowledge of the tunnel protocol whatsoever.

## What this demonstrates

Payload inspection is unavailable for most traffic now, and increasingly unavailable
even in principle. What survives encryption:

- **Client identity.** A fingerprint distinguishes software, not users.
- **Absent SNI.** A structural question about what a client is connecting to.
- **Cross-directional correlation.** The same fingerprint on both sides of a
  conversation means one piece of software, which constrains what the topology can be.
- **Volume asymmetry.** Bytes out against bytes in, on a non-service port.

## Limitations

1. **A fingerprint is an identity, not a verdict.** Absent SNI and low destination
   fanout describe update clients, sync agents, and anything talking to a fixed
   endpoint. This narrows a question; it does not answer one.
2. **This capture is from 2011 and every handshake is TLS 1.0.** Modern traffic is
   TLS 1.3, where more of the handshake is encrypted and Encrypted Client Hello
   removes SNI visibility entirely. The method holds; these specific observations do
   not transfer.
3. **60 handshakes is a small sample.** Five fingerprints from one host over five
   hours supports the observations above and nothing broader.
4. **Fingerprints are evadable.** An attacker who controls their TLS stack can mimic
   a browser's fingerprint exactly. This detects software that did not try to hide,
   which is most of it, but not the part that matters most.

## Licensing

Base JA4 is BSD-3-Clause (FoxIO). The extended JA4+ family is FoxIO License 1.1,
non-commercial only, and is not used here. Fingerprints are computed by tshark's own
implementation. Capture is CTU-13 under CC BY 2.0; cite Garcia et al. 2014.
