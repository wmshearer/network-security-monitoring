#!/usr/bin/env python3
"""
Verify two negative claims and two license claims used in FINDINGS.md:

1. security_content has zero detections mentioning the XZ Utils backdoor
   (CVE-2024-3094 / xz-utils / liblzma).
2. security_content has zero detections mentioning Codecov.
3. security_content's LICENSE file is Apache-2.0.
4. attack_data's LICENSE file is Apache-2.0.

Read-only against both corpora. Writes evidence/02_absences_and_licenses.json.
SKIPs (does not fail) if a corpus path is missing, so this is safe to run in
an environment that has not cloned both repos.
"""
import json
import re
import sys
from pathlib import Path

SECURITY_CONTENT = Path("/home/kali/director/projects/_corpora/security_content")
ATTACK_DATA = Path("/home/kali/director/projects/_corpora/attack_data")
OUT = Path(__file__).resolve().parent.parent / "evidence" / "02_absences_and_licenses.json"

XZ_PATTERNS = [r"xz-utils", r"liblzma", r"xz_utils", r"CVE-2024-3094"]
CODECOV_PATTERNS = [r"codecov"]


def grep_corpus(root, patterns):
    hits = []
    if not root.exists():
        return None
    combined = re.compile("|".join(patterns), re.IGNORECASE)
    for sub in ("detections", "stories"):
        d = root / sub
        if not d.exists():
            continue
        for path in d.rglob("*"):
            if path.is_file():
                try:
                    text = path.read_text(errors="replace")
                except Exception:
                    continue
                if combined.search(text):
                    hits.append(str(path.relative_to(root)))
    return hits


def check_license(root):
    if not root.exists():
        return None
    for name in ("LICENSE", "LICENSE.md", "LICENSE.txt"):
        p = root / name
        if p.exists():
            head = p.read_text(errors="replace")[:200]
            is_apache2 = "Apache License" in head and "Version 2.0" in head
            return {"file": name, "is_apache2": is_apache2, "head": head.strip()[:120]}
    return {"file": None, "is_apache2": False, "head": None}


def main():
    result = {}

    if not SECURITY_CONTENT.exists():
        print(f"SKIP: {SECURITY_CONTENT} not found", file=sys.stderr)
    else:
        xz_hits = grep_corpus(SECURITY_CONTENT, XZ_PATTERNS)
        codecov_hits = grep_corpus(SECURITY_CONTENT, CODECOV_PATTERNS)
        result["security_content_xz_hits"] = xz_hits
        result["security_content_codecov_hits"] = codecov_hits
        result["security_content_license"] = check_license(SECURITY_CONTENT)

    if not ATTACK_DATA.exists():
        print(f"SKIP: {ATTACK_DATA} not found", file=sys.stderr)
    else:
        result["attack_data_license"] = check_license(ATTACK_DATA)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2) + "\n")

    print(f"Wrote {OUT}")
    if "security_content_xz_hits" in result:
        print(f"  XZ Utils / CVE-2024-3094 hits in security_content: {len(result['security_content_xz_hits'])}")
        print(f"  Codecov hits in security_content: {len(result['security_content_codecov_hits'])}")
    if "security_content_license" in result:
        print(f"  security_content LICENSE: {result['security_content_license']['file']} "
              f"(Apache-2.0: {result['security_content_license']['is_apache2']})")
    if "attack_data_license" in result:
        print(f"  attack_data LICENSE: {result['attack_data_license']['file']} "
              f"(Apache-2.0: {result['attack_data_license']['is_apache2']})")


if __name__ == "__main__":
    main()
