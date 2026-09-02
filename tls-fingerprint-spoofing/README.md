# tls-fingerprint-spoofing

A small lab that measures how close a scripted HTTPS client can get to
looking like a real browser at the TLS handshake level, and what still
gives it away when it can't.

A TLS fingerprint is a short hash built from the first message a
client sends when opening an HTTPS connection (the ClientHello): which
TLS version it offers, which cipher suites, which extensions, in what
order. Different software builds that message differently, so the hash
works as a rough "what program is this" tag before any HTTP data is
even sent. JA3 and JA4 are the two common ways to compute that hash.
This project captures real traffic on this machine from Firefox,
Chromium, curl, Python's `requests`/`urllib`/`ssl`, and `curl_cffi`
(a library built specifically to impersonate a browser's TLS
handshake), and compares the results.

This is the evasion-side counterpart to the `tls-fingerprint-analysis`
project in this same portfolio, which looks at the same fingerprints
from the defender's side (using them to spot bots). Read that one for
detection, this one for what a client can and can't hide.

Full write-up with the actual numbers: [`docs/FINDING.md`](docs/FINDING.md).

## What's here

- `src/server.py`: a small local TLS server (self-signed cert). Every
  capture in this project is against `127.0.0.1`, nothing is sent to
  any third-party host.
- `scripts/capture.sh`: starts the server, captures loopback traffic
  with `tshark` while a client connects, stops both, writes a
  `.pcapng`.
- `scripts/extract.sh`: pulls JA3/JA4/JA4_r straight out of a pcap
  with `tshark`'s native TLS dissector fields.
- `scripts/client_*.py`: the different clients captured (stock
  `requests`, stock `urllib`, a hand-tuned `ssl.SSLContext`, two
  clients used for the cipher-order test, and a `curl_cffi` client).
- `scripts/summarize.py`: walks every pcap in `data/` and writes
  `data/summary.json`, which is what the tests actually run against.
- `src/compare.py`: given two raw JA4 (`ja4_r`) strings, says exactly
  which component differs (TLS version, cipher set, extension set,
  ALPN, signature algorithm order, and so on), instead of just saying
  "these hashes don't match."
- `src/grease.py`: checks a pcap for GREASE values (RFC 8701) in the
  cipher, extension, and supported-group lists, independent of
  JA3/JA4 (both of those strip GREASE before hashing, so you can't see
  it in the fingerprint itself).
- `tests/test_findings.py`: pytest suite pinning the measured numbers.
- `data/summary.json`: committed. The raw `.pcapng` captures and the
  server's private key are gitignored, so this JSON is what makes the
  tests reproducible from a fresh clone without needing root, tshark,
  or a live capture.

## Running it

```
python3 -m venv .venv
source .venv/bin/activate
pip install requests curl_cffi pytest

# generate a fresh self-signed cert (already gitignored)
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.pem \
    -days 3650 -nodes -subj "/CN=localhost"

# capture one client against the local server
scripts/capture.sh curl curl -sk https://127.0.0.1:8443/

# pull the fingerprint out of the capture
scripts/extract.sh data/curl.pcapng

# regenerate data/summary.json from everything in data/
python3 scripts/summarize.py

# run the tests
python3 -m pytest tests/ -v
```

No step here needs `sudo`. `dumpcap` on this machine has
`cap_net_admin,cap_net_raw` capabilities set and the capturing user is
in the `wireshark` group, which is what makes unprivileged loopback
capture possible.

Browser captures were done with:

```
firefox --headless --no-remote --new-instance -profile /tmp/<unique> https://127.0.0.1:8443/
chromium --headless=new --user-data-dir=/tmp/<unique> --no-first-run --no-default-browser-check ...
```

Always with a throwaway profile directory, never the default profile.

## Licensing note

Base JA4 is BSD-3-Clause and is what this project uses throughout
(`tls.handshake.ja4` / `tls.handshake.ja4_r` from tshark's built-in TLS
dissector, no plugin needed). The JA4+ family (JA4S, JA4H, JA4L, JA4X,
JA4T, and the rest) is under FoxIO's non-commercial license and is not
used anywhere in this repo.

## What's not verified here

See the last section of `docs/FINDING.md` for what this lab left
unmeasured (HTTP/2 SETTINGS order, TCP/IP stack fingerprinting, other
Chromium builds).
