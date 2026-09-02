"""Stock Python requests client, no customization. This is the baseline
"a script wrote this" fingerprint."""
import sys
import requests

url = sys.argv[1] if len(sys.argv) > 1 else "https://127.0.0.1:8443/"
try:
    r = requests.get(url, verify=False, timeout=5)
    print(r.status_code, r.text)
except Exception as exc:
    print(f"request failed: {exc}", file=sys.stderr)
