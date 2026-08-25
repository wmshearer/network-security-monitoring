"""Locate the shared _corpora directory without assuming how deep this project sits.

The original code reached the corpus with a fixed number of parent hops
(`parent.parent.parent`). That broke the moment this project moved one level
deeper, when several sibling projects were consolidated into one repository.
The path silently resolved to a directory that does not exist, and five tests
failed with FileNotFoundError.

Searching upward for the directory works at any depth, so moving the project
again will not break it.
"""

from pathlib import Path


def find_corpora(start: Path | None = None) -> Path:
    """Return the nearest _corpora directory above `start`.

    Raises FileNotFoundError with the searched path if there is none, rather
    than returning a path that does not exist and failing later somewhere less
    obvious.
    """
    here = (start or Path(__file__)).resolve()
    for parent in here.parents:
        candidate = parent / "_corpora"
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError(f"no _corpora directory in any parent of {here}")


def lockbit_sysmon_log() -> Path:
    """The ActiveMQ to LockBit Sysmon capture this project extracts indicators from."""
    return (
        find_corpora()
        / "attack_data/datasets/apt_simulations"
        / "ActiveMQ_exploit_Lockbit_Ransomware/windows-sysmon.log"
    )
