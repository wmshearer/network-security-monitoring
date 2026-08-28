"""Tests that touch the live Juice Shop container. SKIP (not FAIL) when it is
not running, since the container is stopped between working sessions per the
project's safety protocol.
"""
import pytest
import requests

TARGET = "http://127.0.0.1:3000"


def _container_up() -> bool:
    try:
        r = requests.get(TARGET, timeout=2)
        return r.status_code == 200
    except requests.exceptions.RequestException:
        return False


def test_container_reachable_or_skip():
    if not _container_up():
        pytest.skip("Juice Shop container is not running (expected when stopped between sessions)")
    r = requests.get(TARGET, timeout=5)
    assert r.status_code == 200


def test_register_and_login_flow_or_skip():
    if not _container_up():
        pytest.skip("Juice Shop container is not running")
    email = "pytest-check@example.test"
    password = "PytestCheck1!"
    requests.post(
        f"{TARGET}/api/Users",
        json={"email": email, "password": password, "passwordRepeat": password},
        timeout=10,
    )
    r = requests.post(f"{TARGET}/rest/user/login", json={"email": email, "password": password}, timeout=10)
    assert r.status_code == 200
    assert "token" in r.json()["authentication"]
