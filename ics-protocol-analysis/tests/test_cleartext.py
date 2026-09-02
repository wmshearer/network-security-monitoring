"""Tests for cleartext credential detection.

The redaction tests matter most. This tool reads real credentials off a wire and
writes a report that ends up in a repository and on a website. A redaction bug
would publish someone else's working password.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.cleartext import (  # noqa: E402
    DEFAULT_COMMUNITIES,
    Exposure,
    ProtocolFindings,
)


def test_passwords_are_redacted_but_length_is_kept():
    """The finding is that a password crossed the wire, not what it was.

    Length is retained so the report shows something real was captured, without
    the report itself becoming a second exposure.
    """
    e = Exposure("FTP", "10.0.0.1", "10.0.0.2", "password", "hunter2")
    assert e.redacted() == "<7 chars redacted>"
    assert "hunter2" not in e.redacted()


def test_usernames_are_not_redacted():
    """Which account is exposed is the actionable half of the finding."""
    e = Exposure("FTP", "10.0.0.1", "10.0.0.2", "username", "anonymous")
    assert e.redacted() == "anonymous"


def test_secret_field_is_also_redacted():
    e = Exposure("X", "a", "b", "secret", "s3cr3t")
    assert e.redacted() == "<6 chars redacted>"


def test_community_strings_are_shown_because_they_identify_the_exposure():
    """`public` IS the finding. Masking it would hide what was found."""
    e = Exposure("SNMP", "a", "b", "community_string", "public")
    assert e.redacted() == "public"


def test_default_community_list_covers_the_common_ones():
    for c in ("public", "private", "admin", "manager"):
        assert c in DEFAULT_COMMUNITIES


def test_findings_count_and_host_set():
    f = ProtocolFindings(protocol="FTP")
    f.exposures.append(Exposure("FTP", "a", "b", "username", "u"))
    f.exposures.append(Exposure("FTP", "a", "b", "password", "p"))
    f.hosts.update(["a", "b"])
    assert f.count == 2
    assert len(f.hosts) == 2


def test_as_row_never_leaks_a_password():
    """The serialised report must be safe by construction.

    This is the last gate before a finding reaches a JSON file that gets
    committed and published.
    """
    f = ProtocolFindings(protocol="FTP")
    f.exposures.append(Exposure("FTP", "a", "b", "password", "SuperSecret123"))
    row = f.as_row()
    assert "SuperSecret123" not in str(row)
    assert "<14 chars redacted>" in str(row)


def test_as_row_caps_samples():
    """A report should not embed thousands of records verbatim."""
    f = ProtocolFindings(protocol="Telnet")
    for i in range(50):
        f.exposures.append(Exposure("Telnet", "a", "b", "session", str(i)))
    assert len(f.as_row()["samples"]) == 10
    assert f.as_row()["exposures"] == 50


def test_field_breakdown_counts_by_type():
    f = ProtocolFindings(protocol="FTP")
    f.exposures += [
        Exposure("FTP", "a", "b", "username", "u1"),
        Exposure("FTP", "a", "b", "username", "u2"),
        Exposure("FTP", "a", "b", "password", "p1"),
    ]
    assert f.as_row()["field_breakdown"] == {"username": 2, "password": 1}
