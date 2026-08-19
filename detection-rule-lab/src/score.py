"""Score Sigma detection rules against a labeled corpus.

The question this answers, per rule: how many MALICIOUS records does it fire on,
and how many BENIGN records does it fire on. That pair is the whole point. A rule
that catches an attack is worthless if it also fires on a thousand ordinary events,
and neither number means anything without the other.

Design decisions worth knowing:

1. Malicious and benign are scored in SEPARATE Zircolite runs, then joined by rule
   id. Zircolite has no notion of a label, so the only way to attribute a match to
   a class is to keep the classes in separate inputs. Interleaving them and trying
   to attribute afterwards would require matching events back by identity, which
   the match records do not reliably support.

2. Counts are of MATCHED EVENTS, not of "did this rule fire at all". A rule that
   fires on 900 benign events is a different animal from one that fires on 2, and
   a boolean would erase that.

3. Nothing here computes a "false positive RATE" as a headline. See `Score.notes`:
   the benign corpus is a handful of hosts, so a rate implies a generality the
   sample cannot support. Counts plus stated corpus composition is the honest unit.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class RuleResult:
    """One Sigma rule's behaviour across both classes of the corpus."""

    rule_id: str
    title: str
    level: str            # sigma severity: informational|low|medium|high|critical
    author: str           # DRL 1.1 requires per-rule attribution wherever matches show
    sigmafile: str
    attack_techniques: tuple[str, ...]
    malicious_hits: int
    benign_hits: int

    @property
    def fired(self) -> bool:
        return (self.malicious_hits + self.benign_hits) > 0

    @property
    def precision(self) -> float | None:
        """Of everything this rule flagged, the share that was malicious.

        None when the rule never fired: 0/0 is undefined, and reporting it as
        0.0 would rank a silent rule alongside a rule that is always wrong.
        """
        total = self.malicious_hits + self.benign_hits
        if total == 0:
            return None
        return self.malicious_hits / total

    def as_row(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "level": self.level,
            "author": self.author,
            "sigmafile": self.sigmafile,
            "attack_techniques": list(self.attack_techniques),
            "malicious_hits": self.malicious_hits,
            "benign_hits": self.benign_hits,
            "precision": self.precision,
        }


@dataclass
class ScoreRun:
    """A complete scoring run over both classes."""

    results: list[RuleResult] = field(default_factory=list)
    malicious_events: int = 0
    benign_events: int = 0
    rules_loaded: int = 0

    def summary(self) -> dict:
        fired = [r for r in self.results if r.fired]
        clean = [r for r in fired if r.benign_hits == 0 and r.malicious_hits > 0]
        noisy = [r for r in fired if r.benign_hits > 0]
        return {
            "malicious_events": self.malicious_events,
            "benign_events": self.benign_events,
            "rules_loaded": self.rules_loaded,
            "rules_fired": len(fired),
            "rules_silent": self.rules_loaded - len(fired),
            "rules_malicious_only": len(clean),
            "rules_touching_benign": len(noisy),
        }


def _attack_techniques(tags: list) -> tuple[str, ...]:
    """Pull ATT&CK technique IDs out of a Sigma rule's tag list.

    Sigma tags ATT&CK as `attack.t1059.001` alongside tactic tags like
    `attack.execution`. Only the technique tags are kept, uppercased to the
    conventional `T1059.001` form.
    """
    out = []
    for tag in tags or []:
        t = str(tag).lower()
        if t.startswith("attack.t") and len(t) > 8:
            out.append(t.split(".", 1)[1].upper())
    return tuple(sorted(set(out)))


def run_zircolite(
    events_path: Path,
    out_path: Path,
    zircolite_dir: Path,
    ruleset: Path,
    python_exe: str = "python3",
    timeout: float = 3600.0,
) -> list[dict]:
    """Run Zircolite over one JSON-lines event file and return its rule records.

    Zircolite is executed as a script from inside its own clone, which is how it
    is designed to run. It is not pip-installable: it is absent from PyPI, and
    installing from the clone fails because setuptools rejects its flat layout.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        python_exe,
        str((zircolite_dir / "zircolite.py").resolve()),
        "--events", str(events_path.resolve()),
        "--json-input",
        "-r", str(ruleset.resolve()),
        "-o", str(out_path.resolve()),
    ]
    proc = subprocess.run(
        cmd, cwd=str(zircolite_dir), capture_output=True, text=True, timeout=timeout,
    )
    if not out_path.exists():
        raise RuntimeError(
            "Zircolite produced no output.\nstdout:\n%s\nstderr:\n%s"
            % (proc.stdout[-2000:], proc.stderr[-2000:])
        )
    with out_path.open() as fh:
        return json.load(fh)


def score(
    malicious_records: list[dict],
    benign_records: list[dict],
    rules_loaded: int,
    malicious_events: int,
    benign_events: int,
) -> ScoreRun:
    """Join two Zircolite outputs into per-rule malicious/benign counts.

    Rules are keyed by their Sigma `id` (a UUID), not by title. Titles are not
    unique across the ruleset and are edited over time; the id is the stable
    identifier, so joining on title would silently merge distinct rules.
    """
    by_id: dict[str, dict] = {}

    def absorb(records: list[dict], key: str) -> None:
        for rec in records:
            rid = rec.get("id") or rec.get("title", "")
            slot = by_id.setdefault(
                rid,
                {
                    "title": rec.get("title", ""),
                    "level": rec.get("rule_level", "") or "",
                    "sigmafile": rec.get("sigmafile", "") or "",
                    "tags": rec.get("tags") or [],
                    "author": rec.get("author", "") or "",
                    "malicious": 0,
                    "benign": 0,
                },
            )
            # `count` is Zircolite's own matched-event count for the rule.
            slot[key] += int(rec.get("count") or len(rec.get("matches") or []))

    absorb(malicious_records, "malicious")
    absorb(benign_records, "benign")

    results = [
        RuleResult(
            rule_id=rid,
            title=v["title"],
            level=v["level"],
            author=v["author"],
            sigmafile=v["sigmafile"],
            attack_techniques=_attack_techniques(v["tags"]),
            malicious_hits=v["malicious"],
            benign_hits=v["benign"],
        )
        for rid, v in by_id.items()
    ]
    # Most benign noise first: the practical question a detection engineer asks of
    # a new ruleset is "what is going to flood my queue", not "what worked".
    results.sort(key=lambda r: (-r.benign_hits, -r.malicious_hits, r.title))

    return ScoreRun(
        results=results,
        malicious_events=malicious_events,
        benign_events=benign_events,
        rules_loaded=rules_loaded,
    )
