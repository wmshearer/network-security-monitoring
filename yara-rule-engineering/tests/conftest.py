import json
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = PROJECT_DIR / "evidence"
RULESETS_DIR = PROJECT_DIR / ".rulesets"


def load_json(name: str):
    path = EVIDENCE_DIR / name
    if not path.exists():
        pytest.skip(f"evidence file missing: {path}")
    with open(path) as fh:
        return json.load(fh)


@pytest.fixture(scope="session")
def corpus_manifest():
    return load_json("corpus_manifest.json")


@pytest.fixture(scope="session")
def compile_results_yara_python():
    return load_json("02_compile_results_yara_python.json")


@pytest.fixture(scope="session")
def compile_results_yara_x():
    return load_json("03_compile_results_yara_x.json")


@pytest.fixture(scope="session")
def scan_results():
    return load_json("04_scan_clean_corpus_yara_python.json")


@pytest.fixture(scope="session")
def diff_results():
    return load_json("05_diff_yara_vs_yarax.json")


@pytest.fixture(scope="session")
def cost_experiment_results():
    return load_json("06_cost_experiment_timing.json")


@pytest.fixture(scope="session")
def module_support_results():
    return load_json("03b_module_support.json")


def require_ruleset_cloned(name: str):
    if not (RULESETS_DIR / name).exists():
        pytest.skip(f"ruleset not cloned: .rulesets/{name} (run scripts/01_fetch_rulesets.sh)")
