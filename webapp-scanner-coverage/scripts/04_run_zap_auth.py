#!/usr/bin/env python3
"""Render the authenticated ZAP automation plan with a fresh bearer token,
then launch ZAP (GUI mode, so the real window can be screenshotted) with
-autorun against the rendered plan.

Only ever targets the local Juice Shop container. The rendered plan carries
a live token, so it is written next to the template and gitignored.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "scripts" / "zap-plans" / "auth-plan-template.yaml"
RENDERED = ROOT / "scripts" / "zap-plans" / "auth-plan.rendered.yaml"
LOGIN_SCRIPT = ROOT / "scripts" / "02_register_and_login.py"


def get_token() -> str:
    result = subprocess.run(
        [sys.executable, str(LOGIN_SCRIPT)],
        capture_output=True,
        text=True,
        check=True,
    )
    last_line = result.stdout.strip().splitlines()[-1]
    return json.loads(last_line)["token"]


def main() -> int:
    token = get_token()
    text = TEMPLATE.read_text()
    rendered = text.replace("__TOKEN__", token)
    RENDERED.write_text(rendered)
    print(f"rendered plan with live token to {RENDERED}", file=sys.stderr)

    env = os.environ.copy()
    env["DISPLAY"] = env.get("DISPLAY", ":0")
    subprocess.Popen(
        ["zaproxy", "-autorun", str(RENDERED), "-silent"],
        env=env,
        stdout=open(ROOT / "evidence" / "zap-auth" / "zap-auth-launch.log", "w"),
        stderr=subprocess.STDOUT,
    )
    print("ZAP launched in background for authenticated scan", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
