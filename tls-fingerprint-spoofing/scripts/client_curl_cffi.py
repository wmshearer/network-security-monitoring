"""curl_cffi with browser impersonation turned on. This wraps a patched
libcurl (curl-impersonate under the hood) that ships real browser TLS
extension order and cipher lists baked in, unlike stock requests/urllib
which just use whatever OpenSSL defaults to.
"""
import sys
from curl_cffi import requests

url = sys.argv[1] if len(sys.argv) > 1 else "https://127.0.0.1:8443/"
try:
    r = requests.get(url, verify=False, impersonate="chrome", timeout=5)
    print(r.status_code, r.text)
except Exception as exc:
    print(f"request failed: {exc}", file=sys.stderr)
