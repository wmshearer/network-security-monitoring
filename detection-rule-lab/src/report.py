"""Turn a scoring run into the published artifacts: a markdown report and an
ATT&CK Navigator layer.

Two constraints shape everything here:

1. **DRL 1.1 attribution.** SigmaHQ rules are licensed under the Detection Rule
   License 1.1, which requires per-rule author attribution wherever matches are
   displayed. So every table that names a rule also names its author. This is a
   per-rule obligation, not a blanket notice at the bottom of the page.

2. **No false-positive RATES.** The benign baseline is one Windows Server 2022
   host. A percentage implies a generality one host cannot support, so results
   are stated as observed counts with the corpus composition alongside them.
   Elastic's DEBMM treats FP reduction as a maturity metric but gives no
   guidance on baseline size, and no primary practitioner source on
   small-baseline caveats could be located, so none is cited.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

# Navigator layer spec. 4.5 is the current published version in
# mitre-attack/attack-navigator/layers/spec/.
NAVIGATOR_SPEC = "4.5"


def build_navigator_layer(results, name: str = "Sigma rule coverage (measured)") -> dict:
    """Build an ATT&CK Navigator layer from rules that actually fired.

    Scores techniques by how many DISTINCT RULES fired for them, not by how many
    events matched. Event counts are dominated by whichever noisy rule happened to
    match thousands of times, which would render the map as a picture of corpus
    composition rather than of detection coverage.
    """
    fired_techniques: Counter = Counter()
    for r in results:
        if r.malicious_hits <= 0:
            continue
        for tech in r.attack_techniques:
            fired_techniques[tech] += 1

    techniques = [
        {
            "techniqueID": tech,
            "score": count,
            "comment": "%d Sigma rule(s) fired on this technique in the measured corpus" % count,
            "enabled": True,
        }
        for tech, count in sorted(fired_techniques.items())
    ]

    return {
        "name": name,
        "versions": {"layer": NAVIGATOR_SPEC, "navigator": "5.1.0"},
        "domain": "enterprise-attack",
        "description": (
            "Techniques for which at least one Sigma rule fired against a labeled "
            "corpus. Score = number of distinct rules that fired, NOT event count. "
            "Absence of a technique means no rule fired on THIS corpus; it does not "
            "mean the technique is undetectable."
        ),
        "techniques": techniques,
        "gradient": {"colors": ["#deebf7", "#08306b"], "minValue": 0,
                     "maxValue": max(fired_techniques.values()) if fired_techniques else 1},
        "legendItems": [],
        "showTacticRowBackground": True,
        "sorting": 3,
    }


def _table(rows: list[list[str]], headers: list[str]) -> str:
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


def build_markdown(payload: dict) -> str:
    """Render the full findings report."""
    s = payload["summary"]
    results = payload["results"]

    fired = [r for r in results if (r["malicious_hits"] + r["benign_hits"]) > 0]
    clean = sorted(
        [r for r in fired if r["benign_hits"] == 0 and r["malicious_hits"] > 0],
        key=lambda r: -r["malicious_hits"],
    )
    noisy = sorted([r for r in fired if r["benign_hits"] > 0],
                   key=lambda r: -r["benign_hits"])
    fp_only = [r for r in noisy if r["malicious_hits"] == 0]

    pct_fired = 100.0 * s["rules_fired"] / s["rules_loaded"]
    pct_silent = 100.0 * s["rules_silent"] / s["rules_loaded"]

    lines = [
        "# Sigma rule scoring against a labeled corpus",
        "",
        "## What was measured",
        "",
        "Every rule in Zircolite's Windows/Sysmon ruleset was run against two",
        "separately-labeled bodies of Windows telemetry, and each rule's matches were",
        "counted per class.",
        "",
        _table([
            ["Sigma rules evaluated", "{:,}".format(s["rules_loaded"])],
            ["Malicious events", "{:,}".format(s["malicious_events"])],
            ["Benign events", "{:,}".format(s["benign_events"])],
            ["Attack captures", str(len(payload.get("malicious_captures", [])))],
            ["Benign source", "Windows Server 2022 baseline, %d channels"
             % payload.get("benign_files", 0)],
        ], ["", "Value"]),
        "",
        "## Headline",
        "",
        "**{:,} of {:,} rules ({:.1f}%) fired at all. {:,} ({:.1f}%) never matched"
        " anything.**".format(
            s["rules_fired"], s["rules_loaded"], pct_fired,
            s["rules_silent"], pct_silent),
        "",
        "- {:,} rules fired only on attack data".format(s["rules_malicious_only"]),
        "- {:,} rules fired on the benign baseline".format(s["rules_touching_benign"]),
        "- {:,} rules fired on benign data and caught nothing".format(len(fp_only)),
        "",
        "### The silence is not a corpus-coverage artifact",
        "",
        "The obvious explanation for 90%+ silence is that the corpus lacks the event",
        "types those rules need. That was tested and is not what happened:",
        "**{:.1f}% of the ruleset targets EventIDs the corpus actually contains.**".format(
            payload.get("rule_eventid_coverage_pct", 0.0)),
        "Those rules saw eligible events and did not match.",
        "",
        "## Rules that fired only on attacks",
        "",
        "These matched malicious activity and never touched the benign baseline.",
        "",
        _table(
            [[r["title"][:58], r["level"], "{:,}".format(r["malicious_hits"]),
              r["benign_hits"], ", ".join(r["attack_techniques"][:3]) or "-",
              r["author"][:40] or "-"]
             for r in clean[:30]],
            ["Rule", "Severity", "Attack hits", "Benign hits", "ATT&CK", "Author"],
        ),
        "",
        "## Rules that fired on the benign baseline",
        "",
        "Every rule in the ruleset that matched ordinary Windows activity.",
        "",
        _table(
            [[r["title"][:58], r["level"], "{:,}".format(r["malicious_hits"]),
              "{:,}".format(r["benign_hits"]),
              "-" if r["precision"] is None else "%.2f" % r["precision"],
              r["author"][:40] or "-"]
             for r in noisy],
            ["Rule", "Severity", "Attack hits", "Benign hits", "Precision", "Author"],
        ),
        "",
        "## Limitations",
        "",
        "1. **These are counts on one corpus, not rates.** The benign baseline is a",
        "   single Windows Server 2022 host. A rule that is quiet here may be noisy on a",
        "   workstation fleet, a developer machine, or a domain controller. Nothing here",
        "   supports a claim about any rule's false-positive rate in general.",
        "2. **Absence of a match is not evidence a rule is bad.** A rule that never fired",
        "   may target behaviour this corpus never performed. Silence measures the",
        "   corpus and the rule together, not the rule alone.",
        "3. **The attack corpus is finite and specific.** It covers OTRF atomic captures",
        "   plus the APT29 ATT&CK Evals scenarios. Coverage against those attacks says",
        "   nothing about coverage against attacks not represented here.",
        "4. **Event counts are not alert counts.** A rule matching 4,000 events would not",
        "   produce 4,000 alerts in a real SIEM, which would aggregate them. Counts here",
        "   measure match volume, not analyst workload.",
        "5. **One ruleset, one engine.** Results are for Zircolite's packaged Windows",
        "   ruleset. A different Sigma distribution or backend may convert rules",
        "   differently.",
        "",
        "## Provenance and licensing",
        "",
        "- Detection rules: SigmaHQ, **Detection Rule License 1.1**, which requires",
        "  per-rule author attribution. Authors are named in every table above.",
        "- Execution engine: Zircolite (wagga40), LGPL.",
        "- Attack telemetry: OTRF Security-Datasets, MIT.",
        "- Benign telemetry: NextronSystems evtx-baseline, Apache-2.0.",
        "",
        "Run is reproducible: `python3 scripts/run_scoring.py`.",
    ]
    return "\n".join(lines)


def write_reports(payload: dict, reports_dir: Path) -> dict[str, Path]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    md = reports_dir / "findings.md"
    md.write_text(build_markdown(payload))

    class _R:
        def __init__(self, d):
            self.malicious_hits = d["malicious_hits"]
            self.attack_techniques = d["attack_techniques"]

    layer = build_navigator_layer([_R(d) for d in payload["results"]])
    nav = reports_dir / "attack-navigator-layer.json"
    nav.write_text(json.dumps(layer, indent=2))
    return {"markdown": md, "navigator": nav}
