#!/usr/bin/env python3
"""Score every scanner alert against the Juice Shop challenge manifest.

For each alert or finding raised by ZAP (unauth), ZAP (auth), or nuclei, this
maps it to a Juice Shop challenge key ONLY where the alert's own description
matches what the challenge actually asks for. An alert that is real and
correct but does not correspond to any scored challenge (for example, a CORS
header observation with no matching manifest entry) is recorded as
"real finding, not a scored challenge", not forced into a match. Manual
findings from Burp are added by hand from evidence/burp/basket-idor-notes.md,
since Burp Community has no automated output to parse.

Output: evidence/scoring/coverage_by_category.csv and
evidence/scoring/alert_mapping.csv, the two tables FINDINGS.md is built from.
"""
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "evidence" / "scoring"

# Each row: (scanner, alert name, mapped challenge key or None, note)
# Mappings are only made where the alert's own description matches the
# challenge's own description in data/challenges.yml. See comments per row.
ALERT_MAPPING = [
    # --- ZAP (identical in both unauth and auth runs) ---
    ("ZAP", "Content Security Policy (CSP) Header Not Set", None,
     "Real finding (no CSP header set). No manifest challenge asks for this "
     "specifically; 'CSP Bypass' (XSS) assumes a CSP already exists and asks "
     "to bypass it, which is a different flaw. Not a scored challenge."),
    ("ZAP", "Cross-Domain Misconfiguration", None,
     "Real finding (Access-Control-Allow-Origin: *). No manifest challenge "
     "matches this exact configuration. Not a scored challenge."),
    ("ZAP", "Timestamp Disclosure - Unix", None,
     "Real finding (a Unix timestamp in a response). No manifest challenge "
     "asks for this. Not a scored challenge."),
    ("ZAP", "Modern Web Application", None,
     "Informational fingerprint (detects the app is an Angular SPA). Not a "
     "vulnerability finding and not a scored challenge."),
    ("ZAP", "User Agent Fuzzer", None,
     "ZAP resending requests with different User-Agent strings to see if "
     "responses change. Raised 24 times in the authenticated run with no "
     "behavioural difference found. Not a scored challenge."),
    # --- nuclei ---
    ("nuclei", "prometheus-metrics", "exposedMetricsChallenge",
     "Exact match: challenge asks to find the Prometheus /metrics endpoint, "
     "nuclei's template detects exactly that endpoint. Confirmed hit."),
    ("nuclei", "swagger-api", None,
     "Real finding (a Swagger/OpenAPI doc is served). No manifest challenge "
     "asks for this. Not a scored challenge."),
    ("nuclei", "robots-txt-endpoint", None, "Informational. Not a scored challenge."),
    ("nuclei", "robots-txt", None, "Informational, duplicate of the above. Not a scored challenge."),
    ("nuclei", "security-txt", None,
     "Detects /.well-known/security.txt. The 'Security Advisory' challenge "
     "(csafChallenge, category Miscellaneous) hints that advisories are "
     "'often listed in the security.txt', but solving it requires finding a "
     "specific CVE checksum, not just detecting the file exists. Not counted "
     "as a hit: nuclei found the file, not the challenge's actual objective."),
    ("nuclei", "http-missing-security-headers", None,
     "8 instances (missing headers like X-Content-Type-Options). No single "
     "manifest challenge matches. Not a scored challenge."),
    ("nuclei", "addeventlistener-detect", None, "Informational DOM fingerprint. Not a scored challenge."),
    ("nuclei", "deprecated-feature-policy", None, "Informational header fingerprint. Not a scored challenge."),
    ("nuclei", "owasp-juice-shop-detect", None,
     "Nuclei recognising the target as Juice Shop itself. Not a vulnerability."),
    ("nuclei", "fingerprinthub-web-fingerprints", None, "Tech fingerprinting. Not a scored challenge."),
    ("nuclei", "tech-detect", None, "Tech fingerprinting (Wappalyzer signatures). Not a scored challenge."),
    ("nuclei", "x-recruiting-header", None,
     "Detects the X-Recruiting response header pointing to /#/jobs. The "
     "closest manifest entry, 'Login Support Team' (Security Misconfiguration), "
     "requires finding leaked support-team credentials, a different mechanism "
     "than reading this header. Not counted as a hit."),
    # --- Manual (Burp Proxy + Repeater) ---
    ("Burp (manual)", "Basket IDOR (attacker token reads victim's basket)", "basketAccessChallenge",
     "Confirmed hit, found only by manual testing. See evidence/burp/basket-idor-notes.md."),
]


def load_manifest() -> dict:
    manifest_csv = ROOT / "evidence" / "manifest" / "challenges_table.csv"
    by_key = {}
    with open(manifest_csv) as f:
        for row in csv.DictReader(f):
            by_key[row["key"]] = row
    return by_key


def main() -> int:
    manifest = load_manifest()
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    hit_keys = set()
    mapping_rows = []
    for scanner, alert, key, note in ALERT_MAPPING:
        category = manifest[key]["category"] if key else ""
        challenge_name = manifest[key]["name"] if key else ""
        if key:
            hit_keys.add(key)
        mapping_rows.append(
            {
                "scanner": scanner,
                "alert": alert,
                "mapped_challenge_key": key or "",
                "mapped_challenge_name": challenge_name,
                "mapped_category": category,
                "note": note,
            }
        )

    with open(OUT_DIR / "alert_mapping.csv", "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["scanner", "alert", "mapped_challenge_key", "mapped_challenge_name", "mapped_category", "note"]
        )
        writer.writeheader()
        writer.writerows(mapping_rows)

    # Per-category coverage: how many of the manifest's challenges in each
    # category were found by an automated scanner (ZAP or nuclei) versus
    # only by manual testing (Burp) versus not found by anyone.
    manual_keys = {k for s, a, k, n in ALERT_MAPPING if k and s == "Burp (manual)"}
    automated_keys = {k for s, a, k, n in ALERT_MAPPING if k and s != "Burp (manual)"}

    by_category_total: dict[str, int] = {}
    for row in manifest.values():
        by_category_total[row["category"]] = by_category_total.get(row["category"], 0) + 1

    by_category_automated: dict[str, int] = {}
    by_category_manual: dict[str, int] = {}
    for key, row in manifest.items():
        cat = row["category"]
        if key in automated_keys:
            by_category_automated[cat] = by_category_automated.get(cat, 0) + 1
        elif key in manual_keys:
            by_category_manual[cat] = by_category_manual.get(cat, 0) + 1

    with open(OUT_DIR / "coverage_by_category.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["category", "total_challenges", "found_by_automated_scanner", "found_by_manual_only", "found_by_neither"])
        for cat in sorted(by_category_total, key=lambda c: -by_category_total[c]):
            total = by_category_total[cat]
            auto = by_category_automated.get(cat, 0)
            manual = by_category_manual.get(cat, 0)
            neither = total - auto - manual
            writer.writerow([cat, total, auto, manual, neither])

    total_challenges = len(manifest)
    total_auto = len(automated_keys)
    total_manual = len(manual_keys)
    print(f"Manifest: {total_challenges} challenges")
    print(f"Found by automated scanner (ZAP or nuclei): {total_auto} ({100*total_auto/total_challenges:.1f}%)")
    print(f"Found only by manual testing (Burp): {total_manual} ({100*total_manual/total_challenges:.1f}%)")
    print(f"Found by neither: {total_challenges - total_auto - total_manual}")
    print(f"Wrote {OUT_DIR / 'alert_mapping.csv'}")
    print(f"Wrote {OUT_DIR / 'coverage_by_category.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
