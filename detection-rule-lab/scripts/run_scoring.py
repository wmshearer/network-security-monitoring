#!/usr/bin/env python3
"""Score every Windows Sigma rule against the labeled corpus, both classes.

Usage:
    python3 scripts/run_scoring.py [--limit-benign N] [--ruleset NAME]

Writes reports/scoring-run.json and prints a summary. Both classes are exported
and scored separately, then joined by Sigma rule id.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRIAGE = Path("/home/kali/director/projects/ai-triage-engine")

# BOTH projects have a top-level `src` package, so a naive two-path sys.path lets
# whichever is first shadow the other's `src.*` imports entirely. This project's
# modules are therefore loaded by explicit file path, and only the triage engine
# keeps the `src` name on sys.path.
if str(TRIAGE) not in sys.path:
    sys.path.insert(0, str(TRIAGE))

import importlib.util  # noqa: E402


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    # Register BEFORE exec: @dataclass resolves its own module via
    # sys.modules[cls.__module__] while the class body runs, so an unregistered
    # module makes every dataclass in the file raise on import.
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_export = _load("drl_export", ROOT / "src" / "export.py")
_score = _load("drl_score", ROOT / "src" / "score.py")
_report = _load("drl_report", ROOT / "src" / "report.py")
write_jsonl = _export.write_jsonl
run_zircolite = _score.run_zircolite
score = _score.score
write_reports = _report.write_reports


def rule_eventid_coverage(ruleset: Path, events_paths: list[Path]) -> float:
    """Share of the ruleset whose target EventIDs appear in the corpus.

    This is the control for the headline: if most rules stayed silent simply
    because the corpus never contained the event types they key on, the result
    would say more about the data than about the rules. Computing it makes the
    difference checkable instead of asserted.
    """
    present: set[str] = set()
    for p in events_paths:
        with p.open() as fh:
            for line in fh:
                try:
                    present.add(str(json.loads(line).get("EventID")))
                except json.JSONDecodeError:
                    continue

    rules = json.loads(ruleset.read_text())
    eligible = 0
    for r in rules:
        eids = r.get("eventid")
        if eids is None:
            continue
        if not isinstance(eids, list):
            eids = [eids]
        if {str(e) for e in eids} & present:
            eligible += 1
    return 100.0 * eligible / len(rules) if rules else 0.0

ZIRCOLITE = ROOT / "vendor" / "Zircolite"
EVENTS = ROOT / "data" / "events"
OUT = ROOT / "data" / "out"
REPORTS = ROOT / "reports"


def load_malicious():
    """Every OTRF capture that has both metadata and a local zip, plus APT29.

    The APT29 ATT&CK Evals captures live in `compound_captures/` and have NO
    per-capture metadata YAML, because each spans 15+ techniques rather than the
    single technique an "atomic" capture demonstrates. They load through a
    separate normalizer that takes a capture id directly.

    They are included because the atomic captures alone are thin on EventID 1
    (process creation), which is the event type the majority of Sigma rules key
    on. Scoring a ruleset against a corpus that barely contains its primary
    event type would understate coverage for a reason that has nothing to do
    with rule quality.
    """
    import yaml
    from src.ingest.normalize import normalize_capture
    from src.ingest.normalize_compound import normalize_compound_capture

    meta_dir = TRIAGE / "data/raw/otrf/metadata"
    cap_dir = TRIAGE / "data/raw/otrf/captures"
    compound_dir = TRIAGE / "data/raw/otrf/compound_captures"

    records = []
    used = []

    for zip_path in sorted(compound_dir.glob("*.zip")):
        capture_id = zip_path.stem
        try:
            recs = normalize_compound_capture(capture_id, [zip_path])
        except Exception as e:  # noqa: BLE001
            print("  skip %s: %s" % (zip_path.name, str(e)[:70]))
            continue
        records.extend(recs)
        used.append(zip_path.name)
    for meta in sorted(meta_dir.glob("*.yaml")):
        try:
            doc = yaml.safe_load(meta.read_text()) or {}
        except Exception:  # noqa: BLE001
            continue
        names = []
        for f in doc.get("files") or []:
            val = f.get("link") if isinstance(f, dict) else f
            if isinstance(val, str) and val.endswith(".zip"):
                names.append(val.rsplit("/", 1)[-1])
        zips = [cap_dir / n for n in names if (cap_dir / n).exists()]
        if not zips:
            continue
        try:
            recs = normalize_capture(meta, zips)
        except Exception as e:  # noqa: BLE001
            print("  skip %s: %s" % (meta.name, str(e)[:70]))
            continue
        records.extend(recs)
        used.append(zips[0].name)
    return records, used


# Only these channels carry events the normalizer maps. Measured, not assumed:
# of the 330 .evtx files in the baseline corpus, exactly 3 yield any records
# (Sysmon 107,454, Security 2,636, PowerShell/Operational 5). The other 327 are
# printer, AppV, WMI-activity and similar channels with nothing security-relevant.
#
# This is named explicitly rather than taking the first N files alphabetically,
# which was the original bug: the alphabetical head is all empty channels, so a
# capped run silently produced a ZERO-record benign class while looking like it
# had loaded 40 files.
BENIGN_CHANNELS = (
    "Microsoft-Windows-Sysmon%4Operational.evtx",
    "Security.evtx",
    "Microsoft-Windows-PowerShell%4Operational.evtx",
)


def load_benign(limit_files: int | None):
    """Benign baseline from the NextronSystems evtx-baseline corpus."""
    from src.ingest.normalize_benign import normalize_evtx_capture

    base = TRIAGE / "data/raw/evtx_baseline/win2022-evtx/win2022-evtx"
    files = [base / n for n in BENIGN_CHANNELS if (base / n).exists()]
    if limit_files:
        files = files[:limit_files]
    if not files:
        return [], []
    recs = normalize_evtx_capture(files, capture_id="evtx-baseline-win2022")
    return recs, [f.name for f in files]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit-benign", type=int, default=None,
                    help="cap number of benign .evtx files (for a fast pass)")
    ap.add_argument("--ruleset", default="rules_windows_sysmon.json")
    args = ap.parse_args()

    ruleset = ZIRCOLITE / "rules" / args.ruleset
    if not ruleset.exists():
        print("ruleset not found: %s" % ruleset)
        print("available: %s" % ", ".join(p.name for p in (ZIRCOLITE / "rules").glob("*.json")))
        return 2

    rules_loaded = len(json.loads(ruleset.read_text()))
    print("ruleset: %s (%d rules)" % (ruleset.name, rules_loaded))

    t0 = time.time()
    print("\n[1/4] loading malicious captures")
    mal, mal_caps = load_malicious()
    print("      %d records from %d captures" % (len(mal), len(mal_caps)))

    print("[2/4] loading benign baseline")
    ben, ben_files = load_benign(args.limit_benign)
    print("      %d records from %d evtx files" % (len(ben), len(ben_files)))

    if not mal or not ben:
        print("\nABORT: need both classes populated (mal=%d ben=%d)" % (len(mal), len(ben)))
        return 1

    print("[3/4] exporting to json lines")
    mal_x = write_jsonl(mal, EVENTS / "malicious.jsonl")
    ben_x = write_jsonl(ben, EVENTS / "benign.jsonl")
    print("      malicious %d written, %d skipped (no EventID)"
          % (mal_x.written, mal_x.skipped_no_eventid))
    print("      benign    %d written, %d skipped (no EventID)"
          % (ben_x.written, ben_x.skipped_no_eventid))

    print("[4/4] running zircolite over each class")
    mal_out = run_zircolite(mal_x.path, OUT / "malicious.json", ZIRCOLITE, ruleset)
    print("      malicious: %d rules fired" % len(mal_out))
    ben_out = run_zircolite(ben_x.path, OUT / "benign.json", ZIRCOLITE, ruleset)
    print("      benign:    %d rules fired" % len(ben_out))

    authors = _score.authors_from_ruleset(ruleset)
    run = score(mal_out, ben_out, rules_loaded, mal_x.written, ben_x.written,
                authors=authors)
    attributed = sum(1 for r in run.results if r.author)
    print("      DRL attribution: %d/%d fired rules carry an author"
          % (attributed, len(run.results)))
    s = run.summary()

    coverage = rule_eventid_coverage(ruleset, [mal_x.path, ben_x.path])
    print("      rule/EventID coverage: %.1f%% of rules target EventIDs present in corpus"
          % coverage)

    REPORTS.mkdir(parents=True, exist_ok=True)
    payload = {
        "summary": s,
        "elapsed_seconds": round(time.time() - t0, 1),
        "ruleset": ruleset.name,
        "malicious_captures": mal_caps,
        "benign_files": len(ben_files),
        "rule_eventid_coverage_pct": round(coverage, 1),
        "results": [r.as_row() for r in run.results],
    }
    (REPORTS / "scoring-run.json").write_text(json.dumps(payload, indent=2))
    written = write_reports(payload, REPORTS)
    for k, v in written.items():
        print("      wrote %s: %s" % (k, v.name))

    print("\n" + "=" * 68)
    for k, v in s.items():
        print("%-26s %s" % (k, v))
    print("=" * 68)

    fired = [r for r in run.results if r.fired]
    print("\nNOISIEST RULES (most benign matches):")
    print("%-52s %8s %8s" % ("RULE", "MAL", "BENIGN"))
    for r in fired[:12]:
        print("%-52s %8d %8d" % (r.title[:52], r.malicious_hits, r.benign_hits))

    clean = [r for r in fired if r.benign_hits == 0]
    clean.sort(key=lambda r: -r.malicious_hits)
    print("\nCLEANEST RULES (fired on attacks, never on baseline):")
    for r in clean[:12]:
        print("%-52s %8d %8d" % (r.title[:52], r.malicious_hits, r.benign_hits))

    print("\nwrote %s" % (REPORTS / "scoring-run.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
