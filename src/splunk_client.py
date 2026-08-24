"""REST client against the local Splunk instance's search API.

Credentials are read from environment variables with NO default value.
SPLUNK_URL, SPLUNK_USER, SPLUNK_PASS must all be set in the shell before
running anything in this project. There is no fallback password baked into
this file. If you do not set them, every call raises RuntimeError before
any network request is made.

This is a poller, not a Splunk-native scheduled alert action.
Splunk's own scheduler (the thing that would let a saved search call a
webhook the moment it fires) is exactly the capability Splunk Free removes.
Ad-hoc search and the REST API survive on Free, so this client only ever
uses oneshot search jobs against /services/search/jobs, never anything that
depends on the scheduler. See README.md "Why a poller" section.
"""

from __future__ import annotations

import os

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class MissingCredentials(RuntimeError):
    pass


def _env_or_raise(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise MissingCredentials(
            f"{name} is not set. Export SPLUNK_URL, SPLUNK_USER, SPLUNK_PASS "
            "before running anything against Splunk. There is no default."
        )
    return val


class SplunkClient:
    def __init__(self) -> None:
        self.url = _env_or_raise("SPLUNK_URL")
        self.user = _env_or_raise("SPLUNK_USER")
        self.password = _env_or_raise("SPLUNK_PASS")

    def search(self, spl: str, earliest: str = "0", latest: str = "now", count: int = 0) -> dict:
        if not spl.strip().startswith(("search", "|")):
            spl = "search " + spl
        resp = requests.post(
            f"{self.url}/services/search/jobs",
            data={
                "search": spl,
                "exec_mode": "oneshot",
                "output_mode": "json",
                "earliest_time": earliest,
                "latest_time": latest,
                "count": count,
            },
            auth=(self.user, self.password),
            verify=False,
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()
