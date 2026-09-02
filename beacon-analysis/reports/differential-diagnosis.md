# Differential diagnosis: ruling out benign explanations

Timing regularity is not evidence of malice. NTP, telemetry, update checks,
keepalives and monitoring agents are all regular by design, and a great deal of
benign software beacons harder than malware does.

So the ranking produced by timing analysis is a list of things to investigate,
not a list of findings. This is the investigation. Chris Sanders' framing for
network security monitoring applies directly: treat traffic as benign until you
can show otherwise, and the analytical work is enumerating the innocent
explanations and eliminating them one at a time.

Capture: CTU-13 scenario 42 (Neris botnet, CC BY 2.0), 323,154 packets over
4.8 hours. Source host under investigation: `147.32.84.165`.

---

## Candidate 1: `208.73.210.29:80`, 296.8s interval, 9.7% jitter

**Benign hypothesis.** Port 80 on a five-minute timer is consistent with an RSS
reader, a software update check, a weather widget, or an ad-supported
application polling for content.

**Test.** Read the HTTP requests and look at the host, URI and user agent.

```
tshark -r <capture> -Y "ip.dst==208.73.210.29 && http.request" \
  -T fields -e http.host -e http.request.uri -e http.user_agent
```

**Result.** Every request goes to `riskslot.com` with a URI of the form
`/?epl=<600+ characters of base64>` and a user agent of
`Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)`.

**Verdict: benign explanation REJECTED.** An update check requests a resource.
It does not encode hundreds of bytes of opaque data into a query string on a
fixed timer. The payload varies per request while the interval does not, which
is the signature of a channel carrying data out, not a client fetching content.

---

## Candidate 2: `66.196.94.104:25`, `91.218.38.36:25`, `161.58.16.34:25`

Three destinations on port 25 with regular intervals from 6 to 53 minutes.

**Benign hypothesis.** This one is genuinely plausible, and it was my first
reading. SMTP retry is regular *by specification*: a mail server that cannot
deliver backs off and retries on a schedule. A mail client with an outbox
would produce exactly this shape.

**Test.** Check whether an SMTP conversation ever actually occurs, by counting
handshake completions rather than assuming the port implies the protocol.

```
tshark -r <capture> -Y "tcp.port==25 && tcp.flags.syn==1 && tcp.flags.ack==0" | wc -l
tshark -r <capture> -Y "tcp.port==25 && tcp.flags.syn==1 && tcp.flags.ack==1" | wc -l
```

**Result.**

| | Count |
|---|---|
| SYN attempts on port 25 | **50,794** |
| SYN-ACK responses | **0** |

**Verdict: benign explanation REJECTED, and my own heuristic was wrong.** Not a
single connection completed. There is no SMTP conversation anywhere in the
capture, so this cannot be mail retry: retry presupposes a delivery attempt that
got far enough to fail. 50,794 unanswered connection attempts across many
destinations is spam distribution being refused at the network edge.

This is the case worth dwelling on. A plausible benign story ("port 25 means
mail, mail retries are regular") survives right up until someone checks whether
the protocol is actually being spoken. The port number is a hint, never a fact.

---

## Candidate 3: `222.88.205.195:443`, `74.222.3.26:443`, `74.222.8.74:443`

Three destinations on 443 with intervals of 56 to 64 seconds.

**Benign hypothesis.** HTTPS on a one-minute timer describes a great deal of
legitimate software: sync clients, chat applications, push notification
channels, session keepalives.

**Test.** The traffic is encrypted, so content is unavailable. What remains is
metadata: does a TLS handshake occur, and does the certificate or SNI identify
a recognisable service?

**Result.** Not resolved from this capture. The flows carry no completed TLS
handshake to inspect, which is itself informative but not conclusive.

**Verdict: NOT RULED OUT, and NOT confirmed.** These stay on the list as
candidates rather than findings. Stating this plainly matters more than
producing a tidy answer: an analysis that resolves every candidate is usually
one that stopped looking when the story got convenient.

What would settle it in a real environment: endpoint telemetry showing which
process owns the socket, a JA4 client fingerprint compared against known
tooling, or DNS logs showing what name resolved to these addresses.

---

## Candidate 4: `69.175.10.98:4190` and `173.236.81.226:3817`

Intervals of roughly 162 seconds on non-standard high ports.

**Benign hypothesis.** Peer-to-peer software, a game client, or an application
using a registered-but-uncommon port. Port 4190 is assigned to ManageSieve.

**Test.** Check whether the port's assigned protocol is being spoken, and
whether the timing is consistent with an interactive application.

**Result.** No ManageSieve protocol exchange. The interval is tightly clustered
around 162s across 13 connections, with jitter near 20%.

**Verdict: benign explanation WEAKENED but not eliminated.** A human-driven
application produces bursty, irregular traffic shaped by user behaviour. A
fixed cadence on an uncommon port with no recognisable protocol is more
consistent with automation. Ranked as a candidate, not asserted as C2.

---

## What this exercise demonstrates

Four candidates, four different outcomes: two rejected outright, one weakened,
one genuinely unresolved. That distribution is the point. A detector that
produced four confirmed C2 channels would be more satisfying to publish and
less trustworthy.

The single most useful correction came from testing my own assumption. "Port 25
is mail, mail retry is regular, therefore benign" is a reasonable-sounding chain
that collapsed the moment the handshake counts were checked. Every step in it
was plausible and the conclusion was wrong.
