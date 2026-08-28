from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORPORA = Path("/home/kali/director/projects/_corpora")
T1558 = CORPORA / "attack_data" / "datasets" / "attack_techniques" / "T1558.003"
SECURITY_CONTENT = CORPORA / "security_content"
DAC_VENV = Path("/home/kali/director/projects/detection-as-code/.venv")
SIGMA_CLI = DAC_VENV / "bin" / "sigma"
ZIRCOLITE_PY = DAC_VENV / "bin" / "python"
ZIRCOLITE_SCRIPT = Path(
    "/home/kali/director/projects/detection-as-code/vendor/Zircolite/zircolite.py"
)


def _corpus_present() -> bool:
    return (
        T1558.is_dir()
        and (T1558 / "kerberoasting_spn_request_with_rc4_encryption" / "windows-xml.log").exists()
        and (T1558 / "unusual_number_of_kerberos_service_tickets_requested" / "windows-xml.log").exists()
    )


def _sigma_cli_present() -> bool:
    return SIGMA_CLI.exists()


def _zircolite_present() -> bool:
    if not (ZIRCOLITE_PY.exists() and ZIRCOLITE_SCRIPT.exists()):
        return False
    proc = subprocess.run(
        [str(ZIRCOLITE_PY), "-c", "import orjson"],
        capture_output=True,
    )
    return proc.returncode == 0


def _yara_present() -> bool:
    return shutil.which("yara") is not None


CORPUS_PRESENT = _corpus_present()
SIGMA_CLI_PRESENT = _sigma_cli_present()
ZIRCOLITE_PRESENT = _zircolite_present()
YARA_PRESENT = _yara_present()

requires_corpus = pytest.mark.skipif(
    not CORPUS_PRESENT, reason="T1558.003 attack_data corpus not found on disk"
)
requires_sigma_cli = pytest.mark.skipif(
    not SIGMA_CLI_PRESENT, reason="sigma-cli not found in detection-as-code/.venv"
)
requires_zircolite = pytest.mark.skipif(
    not ZIRCOLITE_PRESENT, reason="Zircolite/orjson not importable in detection-as-code/.venv"
)
requires_yara = pytest.mark.skipif(not YARA_PRESENT, reason="yara CLI not found on PATH")
