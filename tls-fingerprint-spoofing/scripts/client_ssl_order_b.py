"""Same cipher SET as client_ssl_order_a.py, listed in a different
wire order (reversed pairs). See client_ssl_order_a.py for what this
tests.
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
ctx.set_ciphers(
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256"
)
ctx.set_alpn_protocols(["http/1.1"])

with socket.create_connection((host, port), timeout=5) as sock:
    with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
        tls_sock.sendall(b"GET / HTTP/1.1\r\nHost: %b\r\nConnection: close\r\n\r\n" % host.encode())
        try:
            print(tls_sock.recv(4096))
        except Exception as exc:
            print(f"read failed: {exc}", file=sys.stderr)
