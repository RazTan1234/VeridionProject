import pytest

from techdetect.models import Signal, SignalKind, Tier
from techdetect.store import content_ref, read_content, read_records, write_content, write_records


def test_content_is_deduplicated_by_hash(tmp_path):
    first = write_content(tmp_path, b"same bytes")
    second = write_content(tmp_path, b"same bytes")
    assert first == second == content_ref(b"same bytes")
    assert len([path for path in (tmp_path / "content").rglob("*") if path.is_file()]) == 1
    assert read_content(tmp_path, first) == b"same bytes"


def test_missing_content_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_content(tmp_path, "sha256:" + "0" * 64)


def test_records_round_trip(tmp_path):
    signals = [
        Signal(
            domain="a.com",
            document_id="home",
            observation_id="home:header:server",
            kind=SignalKind.HTTP_HEADER,
            key="server",
            value="nginx",
            tier=Tier.HTTP,
            location="https://a.com/",
        )
    ]
    path = tmp_path / "nested" / "signals.jsonl"
    assert write_records(path, signals) == 1
    assert list(read_records(path, Signal)) == signals
    assert write_records(tmp_path / "empty.jsonl", []) == 0
    assert list(read_records(tmp_path / "empty.jsonl", Signal)) == []
