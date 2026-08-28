#!/usr/bin/env python3
"""Register a throwaway account on the local Juice Shop container and log in,
then print the bearer token. Used to build the authenticated ZAP context.

Only ever targets 127.0.0.1:3000. Idempotent: if the account already exists,
registration fails harmlessly and the script still logs in.
"""
import json
import sys

import requests

BASE = "http://127.0.0.1:3000"
EMAIL = "scanner-coverage@example.test"
PASSWORD = "ScannerCoverage!1"


def register(email: str, password: str) -> None:
    r = requests.post(
        f"{BASE}/api/Users",
        json={"email": email, "password": password, "passwordRepeat": password},
        timeout=10,
    )
    if r.status_code == 200:
        print(f"registered {email}", file=sys.stderr)
    else:
        print(f"register skipped ({r.status_code}): {r.text[:200]}", file=sys.stderr)


def login(email: str, password: str) -> str:
    r = requests.post(
        f"{BASE}/rest/user/login",
        json={"email": email, "password": password},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["authentication"]["token"]


def main() -> int:
    if not BASE.startswith("http://127.0.0.1:3000"):
        print("refusing: target is not the local container", file=sys.stderr)
        return 1
    register(EMAIL, PASSWORD)
    token = login(EMAIL, PASSWORD)
    print(json.dumps({"email": EMAIL, "password": PASSWORD, "token": token}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
