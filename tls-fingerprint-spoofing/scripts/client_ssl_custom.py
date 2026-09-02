"""Python ssl client with a hand-tuned SSLContext: custom cipher list
and ALPN protocols set to look more like a browser. This is the "how
close can a scripted client get with only stdlib knobs" test.

Known limitation being tested here: CPython's SSLContext.set_ciphers()
cannot reorder or select TLS 1.3 cipher suites (cpython issue #80665,
open since 2019). TLS 1.3 suites are controlled by OpenSSL and always
sent in OpenSSL's own default order/set, regardless of what
set_ciphers() is given. Only the TLS 1.2-and-below cipher list is
actually configurable from Python.
"""
import socket
import ssl
import sys

host, port = "127.0.0.1", 8443
if len(sys.argv) > 1:
    host = sys.argv[1]
if len(sys.argv) > 2:
    port = int(sys.argv[2])

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# Try to push the TLS 1.2-era cipher list toward something
# browser-shaped. This has no effect on TLS 1.3 suite selection.
ctx.set_ciphers(
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
)
ctx.set_alpn_protocols(["h2", "http/1.1"])

with socket.create_connection((host, port), timeout=5) as sock:
    with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
        tls_sock.sendall(b"GET / HTTP/1.1\r\nHost: %b\r\nConnection: close\r\n\r\n" % host.encode())
        try:
            data = tls_sock.recv(4096)
            print(data)
        except Exception as exc:
            print(f"read failed: {exc}", file=sys.stderr)
