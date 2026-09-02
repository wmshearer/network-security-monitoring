#!/usr/bin/env python3
"""
Walk every pcap in data/, pull JA3/JA4/GREASE numbers out of each with
tshark, and write data/summary.json. This is the file tests run
against, because the pcaps themselves are gitignored (they are
regenerable, and a self-signed key touches the same directory).
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
sys.path.insert(0, str(ROOT / "src"))

from grease import check_pcap  # noqa: E402


def extract_fields(pcap: Path) -> list[dict]:
    out = subprocess.run(
        [
            "tshark", "-r", str(pcap),
            "-Y", "tls.handshake.type==1",
            "-T", "fields",
            "-e", "tls.handshake.ja3",
            "-e", "tls.handshake.ja3_full",
            "-e", "tls.handshake.ja4",
            "-e", "tls.handshake.ja4_r",
            "-E", "separator=\t",
        ],
        capture_output=True, text=True,
    )
    rows = []
    for line in out.stdout.strip().split("\n"):
        if not line:
            continue
        parts = line.split("\t")
        parts += [""] * (4 - len(parts))
        rows.append({
            "ja3": parts[0],
            "ja3_full": parts[1],
            "ja4": parts[2],
            "ja4_r": parts[3],
        })
    return rows


def main():
    summary = {}
    for pcap in sorted(DATA_DIR.glob("*.pcapng")):
        label = pcap.stem
        rows = extract_fields(pcap)
        grease = check_pcap(str(pcap))
        summary[label] = {
            "clienthellos": rows,
            "grease": grease,
        }
    out_path = DATA_DIR / "summary.json"
    out_path.write_text(json.dumps(summary, indent=2) + "\n")
    print(f"wrote {out_path} with {len(summary)} client(s)")


if __name__ == "__main__":
    main()
