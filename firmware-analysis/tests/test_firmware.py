"""Tests for the firmware analyzer.

Both detectors shipped false positives on the first run, and both were the same
mistake in different clothes: matching a marker instead of the thing the marker
describes.

  - /etc/shadow: four HIGH findings claiming ntp, dnsmasq, logd and ubus had
    password hashes baked into the image. All four fields are the single
    character "x", a placeholder meaning no password is set. There was no hash
    in the file. Meanwhile the one interesting line, `root:::`, went unreported.

  - Private keys: a HIGH finding claiming libmbedcrypto.so contains a private
    key. It contains 23 PEM header strings because it PARSES key files. Every
    crypto library would trip that check.

The positive-direction tests are what make the current clean result meaningful.
A detector that finds nothing and a detector that cannot find anything produce
identical output.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from analyse import (  # noqa: E402
    CRYPT_HASH,
    KEY_PATTERNS,
    Report,
    analyse,
    check_keys,
    check_shadow,
    find_rootfs,
)


# --- shadow, both directions ----------------------------------------------

@pytest.mark.parametrize("field", ["$6$salt$hash", "$1$abc$def", "$y$j9T$xyz", "$2b$10$abc"])
def test_crypt_formats_are_recognised(field):
    assert CRYPT_HASH.match(field)


@pytest.mark.parametrize("field", ["x", "*", "!", "!!", ""])
def test_placeholders_are_not_hashes(field):
    """The exact false positive. 'x' is a placeholder, not a hash."""
    assert not CRYPT_HASH.match(field)


def test_detects_a_real_hash(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "shadow").write_text(
        "root:$6$abcdefgh$LongHashValue123:0:0:99999:7:::\n"
        "svc:x:0:0:99999:7:::\n"
        "daemon:*:0:0:99999:7:::\n",
        encoding="utf-8",
    )
    report = Report(rootfs="t")
    check_shadow(tmp_path, report)
    assert len(report.findings) == 1
    assert report.findings[0].severity == "high"
    assert "root" in report.findings[0].detail


def test_reports_empty_password_field(tmp_path):
    """The finding the first version missed while reporting four that were not
    there."""
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "shadow").write_text("root:::0:99999:7:::\n", encoding="utf-8")
    report = Report(rootfs="t")
    check_shadow(tmp_path, report)
    assert len(report.findings) == 1
    assert "empty password" in report.findings[0].title.lower()


def test_placeholder_accounts_produce_nothing(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "shadow").write_text(
        "ntp:x:0:0:99999:7:::\ndnsmasq:x:0:0:99999:7:::\nftp:*:0:0:99999:7:::\n",
        encoding="utf-8",
    )
    report = Report(rootfs="t")
    check_shadow(tmp_path, report)
    assert report.findings == []


# --- keys, both directions ------------------------------------------------

def test_detects_a_key_with_a_body(tmp_path):
    (tmp_path / "real.key").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + "MIIEowIBAAKCAQEAvx2mQKz8Nk1pQoP9rTvXwJ4kLm3nB6yH8dFgWqZcXeRtYuIoP\n" * 3
        + "-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    report = Report(rootfs="t")
    check_keys(tmp_path, report)
    assert len(report.findings) == 1
    assert report.findings[0].severity == "high"


def test_ignores_pem_parser_strings(tmp_path):
    """The libmbedcrypto false positive, reduced to its essence: header strings
    with no key material between them."""
    (tmp_path / "libfake.so").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "-----END RSA PRIVATE KEY-----\n"
        "-----BEGIN CERTIFICATE-----\n"
        "-----END CERTIFICATE-----\n",
        encoding="utf-8",
    )
    report = Report(rootfs="t")
    check_keys(tmp_path, report)
    assert report.findings == []


def test_key_pattern_requires_a_base64_body():
    header_only = b"-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----\n"
    for pattern, _ in KEY_PATTERNS:
        assert not pattern.search(header_only)


# --- against the real image -----------------------------------------------

def _rootfs() -> Path | None:
    return find_rootfs()


@pytest.mark.skipif(_rootfs() is None, reason="firmware not extracted")
def test_image_is_the_expected_build():
    report = analyse(_rootfs())
    assert report.release.get("DISTRIB_ID") == "OpenWrt"
    assert report.release.get("DISTRIB_ARCH") == "mips_24kc"
    assert report.files > 1000


@pytest.mark.skipif(_rootfs() is None, reason="firmware not extracted")
def test_no_password_hash_in_this_image():
    """The corrected result. If a future image genuinely ships a hash, this
    fails and the write-up needs revisiting rather than silently disagreeing."""
    report = analyse(_rootfs())
    hashes = [f for f in report.findings if "hash baked" in f.title]
    assert hashes == []


@pytest.mark.skipif(_rootfs() is None, reason="firmware not extracted")
def test_no_private_key_in_this_image():
    report = analyse(_rootfs())
    keys = [f for f in report.findings if "private key" in f.title.lower()]
    assert keys == []


@pytest.mark.skipif(_rootfs() is None, reason="firmware not extracted")
def test_root_empty_password_is_reported():
    """OpenWrt ships root with no password by design. Reporting it is correct;
    calling it a vulnerability would not be, which is why it is MEDIUM with the
    caveat attached."""
    report = analyse(_rootfs())
    empty = [f for f in report.findings if "empty password" in f.title.lower()]
    assert len(empty) == 1
    assert "dropbear" in empty[0].cannot_establish


@pytest.mark.skipif(_rootfs() is None, reason="firmware not extracted")
def test_every_finding_states_what_it_cannot_establish():
    for finding in analyse(_rootfs()).findings:
        assert len(finding.cannot_establish) > 25
        assert finding.evidence in {"PROVES", "SUGGESTS"}
