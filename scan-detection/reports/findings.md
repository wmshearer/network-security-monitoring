# Scan detection from connection outcomes

Capture: CTU-13 scenario 44 (rbot botnet, CC BY 2.0), 4.6 days of traffic.
Infected host per the publisher: `147.32.84.165`.

## The signal is failure

A host doing ordinary work connects to things that exist. It resolves a name,
gets an address, and the address answers. A host scanning does not know what
exists, so most of what it contacts never replies.

The TCP handshake makes that observable with no payload inspection at all. A SYN
with no SYN-ACK back means nothing was listening, or a firewall dropped it.

## What the capture shows

| | |
|---|---|
| Connection attempts to port 22 | **159,108** |
| Distinct target hosts | **26,851** |
| Hosts that answered | **491** |
| Response rate | **1.83%** |
| Distinct /24 subnets touched | **21,676** |

One host produced 99.4% of all SSH connection attempts in the capture. The other
324 sources look entirely ordinary: a handful of attempts each to a single
destination.

A 1.83% response rate is the finding. Ordinary traffic does not look like this,
because ordinary traffic goes to addresses someone already knows are there.

Subnet spread reinforces it. 21,676 distinct /24 blocks is not a client reaching
a lot of servers, which would cluster in a few providers' networks. It is a sweep.

## Rate over time

Twenty equal buckets across 66 hours:

```
  1  #                                        860
  2-9                                         0
 10  #################################        29,944
 11-16                                        0
 17  ########################                 21,770
 18  #######################################  35,252
 19  #######################################  35,210
 20  ######################################## 36,072
```

Long idle periods, then sustained bursts of tens of thousands of attempts. The
gaps are as informative as the bursts: this is not a background process with a
steady trickle, it is something being told to go.

## A bug that fragmented the finding

The first run reported hundreds of sources with names like
`124.194.209.50,147.32.84.165`.

tshark emits multiple values for `ip.src` when a frame carries nested IP headers,
and joins them with a comma. Without splitting on that, every tunnelled packet
became its own phantom host. The real scanner was fragmented across thousands of
fake sources and its 159,108 attempts were scattered into groups of six.

The outermost header comes first and is the one that actually routed the packet.
Splitting on the comma and taking the first value collapses the phantoms back
into the single host that was really doing the work.

Nothing errored. The output was a well-formatted table of hosts that did not
exist.

## Two different shapes

Scanning and brute-forcing look different from the wire and are reported
separately.

- **Scanning**: many targets, few answers. The failure is at connection.
- **Brute force**: one target, many attempts, and it *does* answer. Reachability
  is fine; whatever fails, fails after connecting, which on SSH happens inside
  the encrypted session and is invisible here.

Folding both into one number would bury the brute-force case behind hosts with
far more targets.

## What this does not establish

**Shape is not intent.** A vulnerability scanner, an asset inventory tool, a
research crawler and malware spreading itself all produce this picture. The
classification deliberately never claims malice and a test enforces that wording.

Attribution here comes from outside the traffic: CTU documents `147.32.84.165` as
the infected host. The analysis found the behaviour; the publisher confirms whose
it was.

## Limitations

1. **Thresholds are descriptive, not authoritative.** 10% response rate and 50
   minimum targets are stated in the source so they can be argued with. A real
   deployment would set them from its own baseline.
2. **A patient scanner evades this.** Pacing below a rate threshold and targeting
   only live hosts defeats the response-rate signal.
3. **Authentication failures are invisible** on encrypted services. This measures
   reachability, not credential attempts.
4. **One capture, one botnet, 2011.** The method holds; these numbers describe
   this capture.
