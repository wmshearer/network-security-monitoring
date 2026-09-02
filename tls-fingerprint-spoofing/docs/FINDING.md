# How well can a script pretend to be a browser's TLS handshake?

## What a TLS fingerprint even is

When any program (a browser, curl, a Python script) opens an HTTPS
connection, the very first thing it sends is a message called a
ClientHello. That message lists things like: which TLS version it
supports, which encryption methods (cipher suites) it's willing to use,
and a bunch of optional extras (extensions) like which HTTP protocol it
wants to speak next (ALPN) and what hostname it's trying to reach
(SNI).

Every piece of software builds this list a little differently, because
they use different TLS libraries and different settings. So if you
hash the list into a short string, you get something close to a
fingerprint of "what program sent this." That's what JA3 and its
successor JA4 do. A server (or a security tool watching the traffic)
can look at that string and take a guess at what's really talking to
it, before it ever looks at the HTTP headers.

This project measures how close a script (curl, Python's `requests`,
Python's `ssl` module, and a Chrome-impersonating library called
`curl_cffi`) can get to a real browser's fingerprint, and what still
gives it away when it can't get all the way there. Everything here was
captured against a TLS server running on `localhost` on this machine,
using `tshark`, which computes JA3 and JA4 natively (no plugin
required for the base JA4 fields used here).

Companion project: `tls-fingerprint-analysis` looks at this from the
defender's side (how do you use these fingerprints to detect bots).
This project is the other half: given that a defender is looking,
how far can a client actually get away with faking it.

## Environment this was measured on

- tshark 4.6.6
- OpenSSL 3.6.3 (both the local test server and curl/requests link
  against this)
- curl 8.21.0
- Python 3.14.6, `requests` 2.32.5 in the venv used for capture
- Firefox 140.13.0esr, Chromium 150.0.7871.181
- `curl_cffi` 0.16.3

## The clients tested and what they produced

| Client | JA3 | JA4 | GREASE seen |
|---|---|---|---|
| Firefox 140.13.0esr | `3ec5d3c9a10d43b0576e31e639c83cd0` | `t13i1716h2_5b57614c22b0_3cbfd9057e0d` | no |
| Chromium 150.0.7871.181 | `f3d2f101dd5bbeea457b4bc55913fcb1` (varies per connection) | `t13i1515h2_8daaf6152771_806a8c22fdea` | yes |
| curl 8.21.0 | `adc2bd4bb269872516eeaa7ade78fe75` | `t13i9012h2_c6771aded2ed_57a60bdf03d1` | no |
| curl_cffi 0.16.3 (`impersonate="chrome"`) | `572354403d1bb05c934cc6e600e48450` | `t13i1515h2_8daaf6152771_806a8c22fdea` | yes |
| Python `requests` (stock) | `adc2bd4bb269872516eeaa7ade78fe75` | `t13i9012h1_c6771aded2ed_57a60bdf03d1` | no |
| Python `urllib` (stock, default `SSLContext`) | `da2e319a5accae0c10cc3d156bbfa65e` | `t13i911000_0d5420ba6086_ec21bdc2dd35` | no |
| Python `ssl` (customized cipher list + ALPN) | `2e6182f1d1c9778812d40f81e35b9ba2` | `t13i1011h2_61a7ad8aa9b6_ec21bdc2dd35` | no |

Raw pcaps aren't committed to the repo (see `.gitignore`), but the
exact tshark output that produced every row above is in
`data/summary.json`, which is committed, and the tests in
`tests/test_findings.py` run directly against it.

## Question 1: do Firefox and Chromium produce different JA4?

Yes. `t13i1716h2_5b57614c22b0_3cbfd9057e0d` (Firefox) versus
`t13i1515h2_8daaf6152771_806a8c22fdea` (Chromium). Running both raw
JA4 strings through `src/compare.py` shows more than one field
differs: cipher count (17 vs 15), extension count, and the actual
cipher/extension sets differ (Firefox includes cipher suites Chromium
doesn't offer, like `c009`/`c00a`, and vice versa). This is expected;
Firefox uses NSS and Chromium uses BoringSSL, and they ship different
default cipher lists.

## Question 2: does stock Python give itself away, and how

Yes, clearly, in two separate ways depending on which stdlib HTTP
client is used.

curl and `requests` produced **the exact same cipher/extension/sigalg
list** (`ja3_full` identical, `ja4_r` identical up to one character).
The only difference between them is the ALPN component: curl's JA4
ends in `h2` (it negotiates HTTP/2 by default) and `requests`'s ends in
`h1` (urllib3 under `requests` doesn't offer h2 by default in this
setup). Running `compare.py` on the two `ja4_r` strings confirms this
is the *only* field that differs:

```
$ python3 src/compare.py --json <curl ja4_r> <requests ja4_r>
{
  "alpn": {"left": "h2", "right": "h1"}
}
```

That's the whole story for `requests`: it's libcurl-adjacent (both sit
on OpenSSL with similar settings) enough that its TLS fingerprint is
nearly a match for curl, but neither one is anywhere close to a real
browser's cipher/extension set, and neither sends GREASE.

`urllib` with a totally default `SSLContext` looks different again: it
adds cipher `00ff` (`TLS_EMPTY_RENEGOTIATION_INFO_SCSV`) to the list
and doesn't offer ALPN at all (`alpn` component reads `00`, decoded by
JA4 as no ALPN offered, shown as `t13i911000...`). None of the three
stock clients (curl, requests, urllib) come close to a browser's
extension set or send GREASE.

## Question 3: does GREASE actually appear where expected? (the hypothesis test)

This was the single most useful thing measured here, because the
starting assumption ("browsers send GREASE, scripts don't") turned out
to be **half right and worth correcting**:

- **Chromium: GREASE present**, in the cipher list, extension list,
  and supported-groups list, on every connection observed (2/2).
- **Firefox: GREASE absent**, in all 3 ClientHellos captured. Firefox
  built on NSS does not implement GREASE the way Chromium does.
- **curl, `requests`, `urllib`, customized `ssl`: GREASE absent** in
  all cases. None of these use a TLS stack that emits GREASE.
- **`curl_cffi` with `impersonate="chrome"`: GREASE present.** It
  reproduces Chromium's GREASE behavior because it ships a patched
  libcurl built on a fork of BoringSSL that implements it.

So "GREASE present" is not a universal browser signal, it's a
**Chromium-family signal**. A detector that treats GREASE-absence as
"this is a script" will incorrectly flag every real Firefox connection
too.

That matters because the claim is repeated confidently across a lot of
industry writing, and it does not appear in RFC 8701, in FoxIO's JA4
spec, or in any vendor documentation found while researching this.
Measuring it took one afternoon and one browser. Firefox alone is
enough to show the rule as commonly stated is wrong.

## Question 4: how much of JA4 can stock Python `ssl` actually control?

JA4 breaks down into: protocol, TLS version, SNI flag, cipher
count/set, extension count/set, ALPN, and (in the raw form) the
signature algorithm list.

Measured directly by diffing a completely default `SSLContext`
(`python_urllib`) against one with `set_ciphers()` and
`set_alpn_protocols()` called (`python_ssl_custom`):

- **TLS version: controllable** (`minimum_version`/`maximum_version`).
- **SNI flag: controllable** (whether `server_hostname` is passed to
  `wrap_socket`).
- **ALPN: controllable** (`set_alpn_protocols()`), confirmed by the
  urllib-vs-custom JA4 ALPN component actually changing (`00` to
  `h2`).
- **Cipher set: partially controllable.** `set_ciphers()` changed the
  TLS 1.2-and-below list, dropping `00ff` from the capture. But the
  three TLS 1.3 cipher suites (`1301`, `1302`, `1303`) were present
  and in the same order in every single capture regardless of what was
  passed to `set_ciphers()`. This matches CPython issue #80665,
  "Can't reorder TLS 1.3 ciphersuites," opened in 2019 and confirmed
  still open (checked live via the GitHub API, last updated 2023).
  There's a newer, narrower issue (#137197, opened July 2025) that
  proposed a get/set API specifically for the TLS 1.3 suite set; it
  was closed without landing a working feature as far as this
  environment shows, since Python 3.14.6's `set_ciphers()` still
  leaves TLS 1.3 suites untouched.
- **Extension set: not controllable.** Diffing the extension list
  between the default and customized contexts gave an identical set,
  `000a,000b,000d,0016,0017,001b,0023,002b,002d,0033` in both. There's
  no stdlib API to add, remove, or reorder individual extensions.
- **Signature algorithm list: not controllable.** Byte-for-byte
  identical between the default and customized captures. No stdlib
  API touches this at all; it comes straight from OpenSSL's defaults.

Out of 7 JA4 components, stock Python `ssl` gives real control over
3 (TLS version, SNI flag, ALPN) and partial control over 1 more
(cipher set, TLS 1.2 tier only). That's roughly **3 to 4 out of 7**,
and the two components a script can't touch at all (extension set and
signature algorithm order) are exactly the ones that make a Python
`ssl` client's fingerprint unmistakably not a browser's, regardless of
what cipher list you feed `set_ciphers()`.

## Question 5: does the sorting claim hold? (same set, different order)

This is JA4's central design difference from JA3: JA4 sorts the cipher
list and the extension list before hashing (SNI and ALPN are pulled
out first), which means the order they appear on the wire is thrown
away. JA3 does not sort, so wire order is part of its hash.

Two scripts (`scripts/client_ssl_order_a.py` and
`client_ssl_order_b.py`) were written to offer the exact same 4
ciphers, in reverse order from each other, over otherwise identical
connections. Captured result:

- order_a JA3: `fe0496d957be4791e062a386891ff419`
- order_b JA3: `e48788b9ae9e3ea5a2fadef0081aaa0c`
- order_a JA4: `t13i0811h1_48922242edce_ec21bdc2dd35`
- order_b JA4: `t13i0811h1_48922242edce_ec21bdc2dd35`

JA3 differs. JA4, including the full raw `ja4_r` string, is
byte-for-byte identical. **The claim holds, measured directly.** A
script only has to get the right set of ciphers/extensions, not the
right sequence, to satisfy JA4. Real detection setups that rely on
JA4 alone would miss this; that's presumably why the same detection
literature that recommends JA4 also recommends stacking it with
order-sensitive signals like HTTP/2 SETTINGS frame order or HTTP
header order, which are not covered by this project.

## Extra finding: one Chromium, two connections, two different JA3 values

The order test above was built on purpose to prove the sorting point.
The same thing showed up on its own, unprompted, in the plain Chromium
capture, which is better evidence because nothing was staged to
produce it.

A single Chromium session opened two connections during one capture.
The two ClientHellos it sent were not identical:

```
ClientHello 1   JA3 f3d2f101dd5bbeea457b4bc55913fcb1   JA4 t13i1515h2_8daaf6152771_806a8c22fdea
ClientHello 2   JA3 eff9cced34ebaf06e0b64dca70a2d751   JA4 t13i1515h2_8daaf6152771_806a8c22fdea
```

Two different JA3 values. One JA4, identical. Firefox, for contrast,
produced the same JA3 and the same JA4 on all three of its
connections in its own capture.

This is Chrome's extension order randomization, caught live rather
than cited from a blog post. It is the reason JA4 sorts at all. It
also means the two fingerprints answer different questions on the same
traffic:

- **JA3 would treat one browser as two clients.** Blocking or counting
  by JA3 splits a single Chrome user across as many identities as it
  has connections.
- **JA4 treats them as one**, which is what an analyst wants here.

The tradeoff runs in both directions, and this capture shows both
sides of it in one file. Sorting is what makes JA4 stable enough to
recognize a real browser, and sorting is also what let `curl_cffi`
match that browser exactly in the next section. The property that
fixes the false split is the same property that permits the
impersonation.

## Extra finding not in the original question list: curl_cffi can hit an exact JA4 match

`curl_cffi`'s `impersonate="chrome"` mode produced a `ja4_r` string
**identical in every field** to the real Chromium capture on this
machine:
`t13i1515h2_8daaf6152771_806a8c22fdea` for both. Confirmed with
`compare.py`, which returned an empty diff. JA3 still differed
slightly (`572354403d1bb05c934cc6e600e48450` vs
`f3d2f101dd5bbeea457b4bc55913fcb1`) because JA3 doesn't sort, and
curl_cffi's extension order isn't byte-identical to this particular
Chromium build's runtime randomization on this run. This is the
clearest evidence in the lab that a purpose-built impersonation
library beats a general-purpose one (`requests`/`urllib`/customized
`ssl`) by a wide margin on this specific metric, and that JA4 alone
is not enough to catch it.

## What this project did not check

- HTTP/2 SETTINGS frame order and values, which several real detection
  stacks pair with JA4 specifically because JA4 throws wire order
  away. Out of scope here; this project only measured the TLS layer.
- TCP/IP stack fingerprinting (JA4T and friends). Explicitly out of
  scope: those are JA4+ variants under the FoxIO non-commercial
  license, not used here (see README for the licensing note).
- Whether curl_cffi's match to Chromium holds across different
  Chromium builds/versions or different curl_cffi impersonation
  targets; only `impersonate="chrome"` against the Chromium build
  installed on this machine was tested.
- Server-side behavior (JA4S) and any of the other JA4+ family members.
  Not used, per the licensing note in the README.
