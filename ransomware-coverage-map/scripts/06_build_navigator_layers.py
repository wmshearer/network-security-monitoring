#!/usr/bin/env python3
"""Stage 6: emit one MITRE ATT&CK Navigator layer JSON per family, matching
the exact schema Splunk's own (deprecated) mitre-map coverage files use
(verified against
security_content/deprecated/mitre-map/cisa-2021-top-malware-coverage/Qakbot_sec_content_mitre_coverage.json:
top-level version/name/description/domain/techniques[], each technique a
{techniqueID, score, comment} object), so these layers could be dropped into
the same Navigator import flow Splunk's own coverage files use.

Score encoding (this project's own choice, documented here since Splunk's
original files only ever encoded "how many detections", never a 4-state
gap/telemetry/no-claim distinction):
  GREEN         -> 100  (behaviour observed, a candidate detection's own
                          literals match the capture)
  RED-LOGIC      -> 40   (behaviour observed, a candidate detection exists
                          for this exact family+technique but its own
                          literals do not match this capture)
  RED-TELEMETRY  -> 10   (behaviour observed, Splunk ships no detection
                          tagged to this technique+family at all)
  GREY           -> technique OMITTED from the layer entirely, not scored
                     0/blank, so Navigator's own "no score" rendering (grey
                     in Navigator's own default gradient) is what a viewer
                     sees, rather than this project inventing a meaning for
                     an in-range score that would look like a real
                     measurement of something that was never observed.

One layer per REAL family (ransomware_ttp excluded: it is the reference
bucket, not a family, and is never presented as one, consistent with every
other output in this project).
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "matrix" / "coverage_matrix.json"
OUT_DIR = ROOT / "matrix" / "navigator_layers"

SCORE_BY_STATE = {"GREEN": 100, "RED-LOGIC": 40, "RED-TELEMETRY": 10}


def main() -> None:
    matrix = json.loads(MATRIX_PATH.read_text())
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    written = []
    for fam_name in matrix["family_order"]:
        fam_meta = matrix["families"][fam_name]
        if fam_meta["is_reference_bucket"]:
            continue  # ransomware_ttp is not a family; never given its own coverage layer

        techniques = []
        for tech_id in matrix["technique_order"]:
            cell = matrix["cells"][f"{fam_name}|{tech_id}"]
            if cell["state"] == "GREY":
                continue  # omitted, not scored 0 (see module docstring)
            comment_lines = [f"state={cell['state']}"]
            for d in cell["candidate_detections"]:
                comment_lines.append(f"{d['name']} ({d['verdict']}): {d['source_file']}")
            techniques.append({
                "techniqueID": tech_id,
                "score": SCORE_BY_STATE[cell["state"]],
                "comment": "\n".join(comment_lines),
            })

        display_name = fam_name.replace("_ransomware", "").replace("_", " ").title()
        layer = {
            "version": "4.3",
            "name": f"{display_name} Ransomware Coverage (this project)",
            "description": (
                f"Coverage of {display_name} ransomware behaviour by Splunk security_content "
                f"detections, scored from this project's evidence (matrix/coverage_matrix.json), "
                f"not from Splunk's own (deprecated, ransomware-family-absent) mitre-map. "
                f"Score 100=covered, 40=detection exists but its own logic does not match this "
                f"capture, 10=behaviour occurred but Splunk ships no detection for it. Techniques "
                f"not observed in this family's capture are omitted (GREY / no claim), not scored 0."
            ),
            "domain": "mitre-enterprise",
            "techniques": techniques,
            # Remaining fields match the exact optional-field set Splunk's own
            # deprecated mitre-map files carry (verified against
            # Qakbot_sec_content_mitre_coverage.json), so a layer here is a
            # drop-in comparison against that schema, not just the required
            # minimum Navigator needs to render something.
            "filters": {"platforms": ["Windows"]},
            "gradient": {"colors": ["#d8d6cd", "#ec835a", "#d03b3b", "#0ca30c"], "minValue": 0, "maxValue": 100},
            "legendItems": [
                {"label": "GREEN: covered", "color": "#0ca30c"},
                {"label": "RED-LOGIC: detection exists, logic does not match", "color": "#d03b3b"},
                {"label": "RED-TELEMETRY: no detection shipped for this technique+family", "color": "#ec835a"},
            ],
            "sorting": 0,
            "showTacticRowBackground": False,
            "tacticRowBackground": "#dddddd",
        }

        out_path = OUT_DIR / f"{fam_name}_coverage_navigator_layer.json"
        out_path.write_text(json.dumps(layer, indent=2))
        written.append(str(out_path))
        print(f"wrote {out_path} ({len(techniques)} scored techniques, {len(matrix['technique_order']) - len(techniques)} omitted as GREY)")

    print(f"\n{len(written)} Navigator layers written to {OUT_DIR}")


if __name__ == "__main__":
    main()
