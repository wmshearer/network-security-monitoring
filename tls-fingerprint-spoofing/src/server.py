"""
Tiny local TLS server used as a fixed target for fingerprint capture.

It does one thing: complete a TLS handshake and return a one-line HTTP
response. We don't care what it says back. The only thing that matters
for JA3/JA4 is the client's ClientHello, which the server never touches.

Usage:
    python3 src/server.py --port 8443 --cert server.pem --key server.key
"""
import argparse
import socket
import ssl
import sys
import threading


RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 2\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"ok"
)


def handle_client(conn, ctx):
    try:
        with ctx.wrap_socket(conn, server_side=True) as tls_conn:
            try:
                tls_conn.settimeout(2.0)
                tls_conn.recv(4096)
            except Exception:
                pass
            try:
                tls_conn.sendall(RESPONSE)
            except Exception:
                pass
    except Exception as exc:
        # A failed handshake still shows up in the capture as a ClientHello,
        # which is all we need. Log and move on.
        print(f"[server] handshake/IO error: {exc}", file=sys.stderr)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def serve(port: int, cert: str, key: str, host: str = "127.0.0.1"):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    # Only offer http/1.1 over ALPN. We don't speak real HTTP/2, and we
    # need the response bytes to be readable by every client so the
    # handshake completes cleanly and shows up in the capture as done,
    # not reset.
    ctx.set_alpn_protocols(["http/1.1"])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(20)
    print(f"[server] listening on {host}:{port}", file=sys.stderr)

    try:
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, ctx), daemon=True)
            t.start()
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--cert", default="server.pem")
    ap.add_argument("--key", default="server.key")
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    serve(args.port, args.cert, args.key, args.host)
