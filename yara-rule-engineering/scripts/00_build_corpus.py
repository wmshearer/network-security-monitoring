#!/usr/bin/env python3
"""
Build a fixed, reproducible file-list manifest for the "clean corpus" used by
every other script in this project. Running this script twice on the same
machine produces the same file list (same paths, same order), so every later
scan is scanning exactly what this manifest says it is scanning.

Corpus definition (documented here, not just in the README):
  - /usr/bin              : ordinary Kali system binaries, files only, <=50MB each
  - /usr/lib/x86_64-linux-gnu (top level only, not recursive into plugin dirs)
                          : shared libraries, files only, <=50MB each
  - firmware-analysis/extracted        : OpenWrt 24.10.8 squashfs, full tree, no cap
  - firmware-binary-analysis/extracted : OWASP IoTGoat (MIT), full tree, no cap
                                          NOTE: IoTGoat is a deliberately vulnerable
                                          TRAINING image, not malware. See README/FINDINGS.

The 50MB-per-file cap on /usr/bin and /usr/lib exists ONLY to keep total scan
time inside the ~10 minute timebox (a handful of files, e.g. sliver-server at
254MB and pandoc at 203MB, otherwise dominate wall-clock time for no benefit
to the false-positive question). Every excluded file is logged so the cap is
auditable, not silent.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

MAX_FILE_BYTES = 50 * 1024 * 1024  # 50MB cap, see module docstring

CORPORA = {
    "usr_bin": {
        "root": "/usr/bin",
        "recursive": True,
        "cap_bytes": MAX_FILE_BYTES,
    },
    "usr_lib_x86_64": {
        "root": "/usr/lib/x86_64-linux-gnu",
        "recursive": False,  # top level only
        "cap_bytes": MAX_FILE_BYTES,
    },
    "openwrt_firmware": {
        "root": "/home/kali/director/projects/firmware-analysis/extracted",
        "recursive": True,
        "cap_bytes": None,
    },
    "iotgoat_firmware": {
        "root": "/home/kali/director/projects/firmware-binary-analysis/extracted",
        "recursive": True,
        "cap_bytes": None,
    },
}

EVIDENCE_DIR = Path(__file__).resolve().parent.parent / "evidence"


def iter_files(root: str, recursive: bool):
    """Yield only REGULAR files, never symlinks. A symlink-to-file is skipped
    even if its target would pass is_file(), because otherwise a directory
    with many internal symlinks (e.g. /usr/bin has 1123 of them, 608 pointing
    outside /usr/bin entirely) double-counts the same bytes under two names
    and inflates file_count/total_bytes relative to `find -type f`."""
    root_path = Path(root)
    if not root_path.exists():
        return
    if recursive:
        for dirpath, _dirnames, filenames in os.walk(root_path, followlinks=False):
            for name in filenames:
                p = Path(dirpath) / name
                if p.is_symlink():
                    continue
                yield p
    else:
        for p in sorted(root_path.iterdir()):
            if p.is_file() and not p.is_symlink():
                yield p


def build_corpus(name: str, spec: dict):
    included = []
    excluded_too_large = []
    excluded_unreadable = []
    total_bytes = 0
    for p in sorted(iter_files(spec["root"], spec["recursive"])):
        try:
            if p.is_symlink() and not p.exists():
                excluded_unreadable.append(str(p))
                continue
            if not p.is_file():
                continue
            size = p.stat().st_size
        except OSError:
            excluded_unreadable.append(str(p))
            continue
        if spec["cap_bytes"] is not None and size > spec["cap_bytes"]:
            excluded_too_large.append({"path": str(p), "size_bytes": size})
            continue
        try:
            with open(p, "rb") as fh:
                fh.read(1)
        except OSError:
            excluded_unreadable.append(str(p))
            continue
        included.append({"path": str(p), "size_bytes": size})
        total_bytes += size
    return {
        "name": name,
        "root": spec["root"],
        "recursive": spec["recursive"],
        "cap_bytes": spec["cap_bytes"],
        "file_count": len(included),
        "total_bytes": total_bytes,
        "excluded_too_large_count": len(excluded_too_large),
        "excluded_too_large": excluded_too_large,
        "excluded_unreadable_count": len(excluded_unreadable),
        "excluded_unreadable": excluded_unreadable,
        "files": included,
    }


def main():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    manifest = {"corpora": {}}
    for name, spec in CORPORA.items():
        print(f"Building corpus manifest: {name} (root={spec['root']})", file=sys.stderr)
        result = build_corpus(name, spec)
        manifest["corpora"][name] = result
        print(
            f"  {result['file_count']} files, {result['total_bytes']/1024/1024:.1f} MB, "
            f"{result['excluded_too_large_count']} excluded (too large), "
            f"{result['excluded_unreadable_count']} excluded (unreadable)",
            file=sys.stderr,
        )

    out_path = EVIDENCE_DIR / "corpus_manifest.json"
    with open(out_path, "w") as fh:
        json.dump(manifest, fh, indent=2)
    print(f"Wrote {out_path}", file=sys.stderr)

    # A compact summary that's cheap to read back in tests.
    summary = {
        name: {
            "file_count": c["file_count"],
            "total_bytes": c["total_bytes"],
            "excluded_too_large_count": c["excluded_too_large_count"],
            "excluded_unreadable_count": c["excluded_unreadable_count"],
        }
        for name, c in manifest["corpora"].items()
    }
    summary_path = EVIDENCE_DIR / "corpus_manifest_summary.json"
    with open(summary_path, "w") as fh:
        json.dump(summary, fh, indent=2)
    print(f"Wrote {summary_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
