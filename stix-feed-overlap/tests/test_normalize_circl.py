import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from normalize_circl import load_circl_indicators


def _write_fake_event(cache_dir: Path, uuid: str, attributes: list[dict]) -> None:
    event = {"Event": {"uuid": uuid, "Attribute": attributes}}
    (cache_dir / f"{uuid}.json").write_text(json.dumps(event))


def test_sha256_attribute_is_extracted_and_uppercased():
    with tempfile.TemporaryDirectory() as tmp:
        cache_dir = Path(tmp)
        _write_fake_event(
            cache_dir, "e1", [{"type": "sha256", "value": "a" * 64}]
        )
        result = load_circl_indicators(cache_dir)
        assert result["sha256"] == ["A" * 64]


def test_domain_and_hostname_both_map_to_dns():
    with tempfile.TemporaryDirectory() as tmp:
        cache_dir = Path(tmp)
        _write_fake_event(
            cache_dir,
            "e1",
            [
                {"type": "domain", "value": "Evil.Example.NET"},
                {"type": "hostname", "value": "bad-host.example.com"},
            ],
        )
        result = load_circl_indicators(cache_dir)
        assert "evil.example.net" in result["dns"]
        assert "bad-host.example.com" in result["dns"]


def test_filename_sha256_pair_extracts_hash_only():
    with tempfile.TemporaryDirectory() as tmp:
        cache_dir = Path(tmp)
        h = "b" * 64
        _write_fake_event(
            cache_dir,
            "e1",
            [{"type": "filename|sha256", "value": f"malware.exe|{h}"}],
        )
        result = load_circl_indicators(cache_dir)
        assert result["sha256"] == [h.upper()]


def test_unmapped_types_are_counted_but_not_extracted():
    with tempfile.TemporaryDirectory() as tmp:
        cache_dir = Path(tmp)
        _write_fake_event(
            cache_dir,
            "e1",
            [
                {"type": "md5", "value": "d" * 32},
                {"type": "sha256", "value": "e" * 64},
            ],
        )
        result = load_circl_indicators(cache_dir)
        assert result["sha256"] == ["E" * 64]
        assert result["attribute_type_counts"]["md5"] == 1
        # md5 value must not leak into the sha256 list
        assert "D" * 32 not in result["sha256"]


def test_malformed_json_file_is_counted_as_parse_error_not_crash():
    with tempfile.TemporaryDirectory() as tmp:
        cache_dir = Path(tmp)
        (cache_dir / "broken.json").write_text("{not valid json")
        result = load_circl_indicators(cache_dir)
        assert result["parse_errors"] == 1
        assert result["events_loaded"] == 0
