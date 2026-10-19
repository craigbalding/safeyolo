"""Live JSONL reads used by proxy migration assertions."""

import json

import pytest

from tests.proxy_contracts.harness import read_events


@pytest.mark.parametrize("split", ["json", "complete", "utf8"])
def test_read_events_waits_for_trailing_newline(tmp_path, split):
    path = tmp_path / "audit.jsonl"
    first = {"event": "traffic.request_outcome"}
    last = {"event": "traffic.websocket.end", "detail": "café"}
    record = json.dumps(last, ensure_ascii=False).encode()
    if split == "json":
        cut = record.index(b"traffic.websocket.end") + len(b"proxy.websocket.en")
    elif split == "utf8":
        cut = record.index("é".encode()) + 1
    else:
        cut = len(record)

    with path.open("wb") as writer:
        writer.write(json.dumps(first).encode() + b"\n" + record[:cut])
        writer.flush()
        assert read_events(path) == [first]

        writer.write(record[cut:] + b"\n")
        writer.flush()
        assert read_events(path) == [first, last]


def test_read_events_rejects_malformed_complete_record(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b'{"event":"traffic.request_outcome"}\n{"event":}\n{"event":"unfinished"')

    with pytest.raises(json.JSONDecodeError):
        read_events(path)
