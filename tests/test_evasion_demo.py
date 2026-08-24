"""Tests for src/evasion_demo.py's D2/D6 match predicates and transforms.

These exercise the offline evasion demonstration against the real captured
event (data/converted/attack/empire_schtasks_creation_standard_user.json) --
skipped if that file is not present (data/converted/ is gitignored and
regenerated from ../ai-triage-engine/data/raw per README.md's reproduction
steps), so this suite does not hard-fail in an environment that never ran
the conversion step.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from evasion_demo import (  # noqa: E402
    REAL_EVENT_FILE,
    d2_fires,
    d6_fires,
    load_real_event,
    run_demo,
    transform_interpreter_neutral_path,
    transform_renamed_interpreter_same_dir,
    transform_windowstyle_hidden,
    transform_windowstyle_numeric,
)

REPO_ROOT = Path(__file__).parent.parent

pytestmark = pytest.mark.skipif(
    not (REPO_ROOT / REAL_EVENT_FILE).exists(),
    reason=f"{REAL_EVENT_FILE} not present; run src/convert_otrf.py per README.md first",
)


@pytest.fixture(autouse=True)
def _chdir_repo_root(monkeypatch):
    monkeypatch.chdir(REPO_ROOT)


def test_load_real_event_returns_the_real_schtasks_event():
    event = load_real_event()
    assert event["EventID"] == 1
    assert event["Image"].endswith("schtasks.exe")
    assert event["ParentImage"].endswith("powershell.exe")
    assert "powershell" in event["CommandLine"].lower()
    assert "hidden" in event["CommandLine"].lower()


def test_d2_fires_on_the_unmodified_real_event():
    event = load_real_event()
    assert d2_fires(event) is True


def test_d6_fires_on_the_unmodified_real_event():
    event = load_real_event()
    assert d6_fires(event) is True


def test_windowstyle_hidden_rewrite_does_not_evade_d2():
    """The word 'hidden' survives -W hidden -> -windowstyle hidden, so D2
    must still fire. This is the exact wrong claim FINDINGS.md corrected on
    2026-08-24 -- if this assertion ever flips to False, it means the
    predicate or the transform changed in a way that would silently
    resurrect the corrected error."""
    event = load_real_event()
    edited = transform_windowstyle_hidden(event)
    assert "hidden" in edited["CommandLine"].lower()
    assert d2_fires(edited) is True


def test_renamed_interpreter_same_directory_does_not_evade_d2():
    """Renaming just the executable leaves 'powershell' present in the
    WindowsPowerShell directory segment of the path, so D2 must still
    fire."""
    event = load_real_event()
    edited = transform_renamed_interpreter_same_dir(event)
    assert "powershell" in edited["CommandLine"].lower()
    assert d2_fires(edited) is True


def test_windowstyle_numeric_evades_d2_but_not_d6():
    """-WindowStyle 1 is the numeric form of the same option; 'hidden'
    disappears from CommandLine, so D2 (a CommandLine substring match) must
    stop firing, while D6 (Image/ParentImage only, no CommandLine read)
    must keep firing on the same edited event."""
    event = load_real_event()
    edited = transform_windowstyle_numeric(event)
    assert "hidden" not in edited["CommandLine"].lower()
    assert d2_fires(edited) is False
    assert d6_fires(edited) is True


def test_neutral_interpreter_path_evades_d2_but_not_d6():
    """Copying the interpreter to a neutral path removes BOTH occurrences of
    'powershell' from CommandLine, so D2 must stop firing, while D6 (which
    never reads CommandLine) must keep firing."""
    event = load_real_event()
    edited = transform_interpreter_neutral_path(event)
    assert "powershell" not in edited["CommandLine"].lower()
    assert d2_fires(edited) is False
    assert d6_fires(edited) is True


def test_original_captured_file_is_never_modified_by_the_demo():
    """load_real_event only reads the source file; run_demo (which drives
    the full transformation table) must not change its on-disk contents."""
    path = REPO_ROOT / REAL_EVENT_FILE
    before = path.read_bytes()
    run_demo()
    after = path.read_bytes()
    assert before == after


def test_run_demo_produces_the_documented_fire_pattern():
    """End-to-end: the full transform table must reproduce exactly the
    D2/D6 fire pattern documented in FINDINGS.md's 2026-08-24 correction --
    true/true for the two non-evading edits, false/true for the two
    evading edits."""
    results = run_demo()
    by_label = {r["transformation"]: r for r in results}

    original = next(r for r in results if r["transformation"].startswith("original"))
    assert original["d2_fires"] is True
    assert original["d6_fires"] is True

    windowstyle_hidden = next(
        r for r in results if "windowstyle hidden" in r["transformation"]
    )
    assert windowstyle_hidden["d2_fires"] is True
    assert windowstyle_hidden["d6_fires"] is True

    renamed = next(
        r for r in results if r["transformation"].startswith("interpreter renamed")
    )
    assert renamed["d2_fires"] is True
    assert renamed["d6_fires"] is True

    windowstyle_1 = next(r for r in results if "WindowStyle 1" in r["transformation"])
    assert windowstyle_1["d2_fires"] is False
    assert windowstyle_1["d6_fires"] is True

    neutral_path = next(
        r for r in results if "svc.exe" in r["transformation"]
    )
    assert neutral_path["d2_fires"] is False
    assert neutral_path["d6_fires"] is True
