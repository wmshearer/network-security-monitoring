"""Map SigmaHQ's cloud detection rules against the ATT&CK cloud technique set.

WHAT THIS MEASURES, AND WHAT IT DOES NOT

This measures what rules CLAIM to cover. Every Sigma rule carries `tags:` naming
the ATT&CK techniques it targets, so cross-referencing those against the
techniques ATT&CK marks as cloud-relevant gives a claimed-coverage map.

It does NOT measure what fires. A sibling project ran 2,691 Sigma rules against
834K real Windows events and found 135 fired, which is a very different and much
stronger claim. That method needs an event corpus.

There is no properly licensed public cloud audit-log corpus to use here. The
flaws.cloud CloudTrail dataset is real, freely downloadable, and holds 1.94M
genuine AWS events, which would have been ideal. It carries no stated licence.
Downloadable is not the same as licensed, so it is not used.

So this project reports a weaker measurement than its sibling, and says so
rather than presenting a claimed-coverage number as if rules had been tested.

SOURCES
  ATT&CK Enterprise STIX bundle, v19.2 (2026-08-05), MITRE, from
    github.com/mitre-attack/attack-stix-data
  SigmaHQ rules, Detection Rule License 1.1, from github.com/SigmaHQ/sigma
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STIX = ROOT / "data" / "enterprise-attack.json"
SIGMA = ROOT / "data" / "sigma"

# The four ATT&CK platform values that denote cloud. "Containers" is deliberately
# excluded: Kubernetes runs plenty of places that are not a cloud provider, and
# folding it in would inflate the cloud technique count with on-prem workloads.
CLOUD_PLATFORMS = {"IaaS", "SaaS", "Identity Provider", "Office Suite"}

TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


@dataclass
class Technique:
    id: str
    name: str
    platforms: set[str]
    is_subtechnique: bool
    tactics: list[str] = field(default_factory=list)


def load_cloud_techniques() -> dict[str, Technique]:
    """Every non-deprecated ATT&CK technique touching at least one cloud platform."""
    bundle = json.loads(STIX.read_text(encoding="utf-8"))
    out: dict[str, Technique] = {}
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        platforms = set(obj.get("x_mitre_platforms") or [])
        if not (platforms & CLOUD_PLATFORMS):
            continue
        ext = [r for r in obj.get("external_references", [])
               if r.get("source_name") == "mitre-attack"]
        if not ext:
            continue
        tid = ext[0].get("external_id", "")
        if not tid:
            continue
        tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                   if p.get("kill_chain_name") == "mitre-attack"]
        out[tid.upper()] = Technique(
            id=tid.upper(),
            name=obj.get("name", ""),
            platforms=platforms & CLOUD_PLATFORMS,
            is_subtechnique=bool(obj.get("x_mitre_is_subtechnique")),
            tactics=tactics,
        )
    return out


def parse_rule_tags(path: Path) -> tuple[set[str], str]:
    """Pull ATT&CK technique ids from a Sigma rule's tags.

    Deliberately a line scanner rather than a YAML parse. The tags block is a
    flat list of scalars in every SigmaHQ rule, and a full YAML dependency buys
    nothing here. It also means a malformed rule yields no tags instead of
    raising, which is the behaviour wanted when walking 225 files written by
    many different authors.
    """
    tags: set[str] = set()
    in_tags = False
    title = ""
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("title:"):
            title = line.split(":", 1)[1].strip()
        if line.startswith("tags:"):
            in_tags = True
            continue
        if in_tags:
            stripped = line.strip()
            if stripped.startswith("- "):
                match = TECHNIQUE_TAG.match(stripped[2:].strip())
                if match:
                    tags.add(match.group(1).upper())
                continue
            if stripped and not stripped.startswith("#"):
                in_tags = False
    return tags, title


@dataclass
class RuleSet:
    label: str
    root: Path
    rules: list[tuple[Path, set[str], str]] = field(default_factory=list)

    def load(self) -> RuleSet:
        for path in sorted(self.root.rglob("*.yml")):
            tags, title = parse_rule_tags(path)
            self.rules.append((path, tags, title))
        return self

    @property
    def covered(self) -> set[str]:
        out: set[str] = set()
        for _, tags, _ in self.rules:
            out |= tags
        return out


def parent_of(technique_id: str) -> str:
    """T1078.004 -> T1078. A sub-technique rule counts toward its parent."""
    return technique_id.split(".")[0]


def analyse() -> dict:
    techniques = load_cloud_techniques()
    cloud = RuleSet("rules/cloud", SIGMA / "rules" / "cloud").load()

    claimed = cloud.covered
    # A rule tagged with a sub-technique demonstrates coverage of that branch of
    # the parent too, so both are credited. Counting only exact matches would
    # understate coverage wherever rule authors were more specific than the
    # matrix row being measured.
    claimed_expanded = claimed | {parent_of(t) for t in claimed}

    cloud_ids = set(techniques)
    covered = cloud_ids & claimed_expanded
    uncovered = cloud_ids - claimed_expanded

    # Rules whose tags name a technique ATT&CK does not mark as cloud. Not an
    # error: a rule reading cloud audit logs may legitimately target a technique
    # whose platform list does not include a cloud platform.
    off_matrix = claimed_expanded - cloud_ids

    by_platform: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "covered": 0})
    for tid, tech in techniques.items():
        for platform in tech.platforms:
            by_platform[platform]["total"] += 1
            if tid in covered:
                by_platform[platform]["covered"] += 1

    rules_per_technique = Counter()
    for _, tags, _ in cloud.rules:
        for tag in tags:
            if tag in cloud_ids:
                rules_per_technique[tag] += 1
            elif parent_of(tag) in cloud_ids:
                rules_per_technique[parent_of(tag)] += 1

    untagged = [str(p.relative_to(SIGMA)) for p, tags, _ in cloud.rules if not tags]

    return {
        "attack_version": "19.2",
        "cloud_techniques": len(cloud_ids),
        "rules": len(cloud.rules),
        "untagged_rules": untagged,
        "covered": sorted(covered),
        "uncovered": sorted(uncovered),
        "off_matrix": sorted(off_matrix),
        "by_platform": dict(by_platform),
        "rules_per_technique": rules_per_technique,
        "techniques": techniques,
    }


def main() -> None:
    result = analyse()
    techniques = result["techniques"]
    total = result["cloud_techniques"]
    covered = len(result["covered"])

    print("SigmaHQ cloud rule coverage against ATT&CK cloud techniques")
    print(f"ATT&CK v{result['attack_version']}, "
          f"platforms: {', '.join(sorted(CLOUD_PLATFORMS))}\n")

    print(f"  {result['rules']} rules under rules/cloud/")
    print(f"  {total} ATT&CK techniques touching a cloud platform")
    print(f"  {covered} of those techniques have at least one rule claiming them "
          f"({covered / total:.1%})")
    print(f"  {total - covered} have none\n")

    print("By platform:")
    for platform in sorted(result["by_platform"]):
        row = result["by_platform"][platform]
        pct = row["covered"] / row["total"] if row["total"] else 0
        print(f"  {platform:<20} {row['covered']:>3} / {row['total']:<3}  {pct:>6.1%}")

    print("\nMost-claimed techniques:")
    for tid, n in result["rules_per_technique"].most_common(8):
        name = techniques[tid].name if tid in techniques else "?"
        print(f"  {n:>3} rules  {tid:<12} {name}")

    if result["untagged_rules"]:
        print(f"\n{len(result['untagged_rules'])} rules carry no ATT&CK technique tag "
              "and cannot be mapped:")
        for path in result["untagged_rules"][:5]:
            print(f"  {path}")
        if len(result["untagged_rules"]) > 5:
            print(f"  ... and {len(result['untagged_rules']) - 5} more")

    print(f"\n{len(result['off_matrix'])} techniques are claimed by cloud rules but "
          "are not marked\ncloud-relevant by ATT&CK. That is not an error: a rule "
          "reading cloud audit\nlogs can target a technique whose platform list "
          "omits cloud.")

    print("\nThis counts what rules CLAIM. It does not measure what fires.")
    print("No properly licensed public cloud audit-log corpus was available.")


if __name__ == "__main__":
    main()
