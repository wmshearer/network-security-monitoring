"""Confirms the tool versions claimed in README/FINDINGS by asking the
tools themselves, not by trusting a written-down number."""
import subprocess

import pytest


def test_yara_cli_version_is_4_5_8():
    result = subprocess.run(["yara", "--version"], capture_output=True, text=True, check=True)
    assert result.stdout.strip() == "4.5.8"


def test_yara_python_version_is_4_5_4():
    yara = __import__("yara")
    assert yara.__version__ == "4.5.4"


def test_yara_x_version_is_1_20_0():
    import importlib.metadata

    # yara-x lives in this project's .venv, not in the system Python. Running
    # the suite with a different interpreter must SKIP this, the way the rest
    # of the suite skips when a ruleset or evidence file is absent. Raising
    # PackageNotFoundError here reports a missing optional dependency as a
    # failed assertion about the environment, which reads as a broken project
    # to anyone who runs pytest without activating the venv first.
    try:
        version = importlib.metadata.version("yara-x")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("yara-x not installed for this interpreter; use .venv/bin/python")
    assert version == "1.20.0"


def test_yara_x_has_no_cli_binary_in_this_venv():
    import shutil

    # yara-x ships as a library only; there should be no `yr` binary that
    # this project's own scripts could accidentally reach for.
    assert shutil.which("yr") is None or "yara-rule-engineering/.venv" not in shutil.which("yr")
