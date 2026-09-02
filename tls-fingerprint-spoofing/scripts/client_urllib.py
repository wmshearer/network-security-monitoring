"""Stock Python urllib client using the default SSLContext. No
customization at all, no cipher/ALPN settings."""
import ssl
import sys
import urllib.request

url = sys.argv[1] if len(sys.argv) > 1 else "https://127.0.0.1:8443/"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    with urllib.request.urlopen(url, context=ctx, timeout=5) as resp:
        print(resp.status, resp.read())
except Exception as exc:
    print(f"request failed: {exc}", file=sys.stderr)
