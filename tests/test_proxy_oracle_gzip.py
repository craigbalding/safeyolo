"""The source oracle's gzip fixture must not depend on the host OS byte."""

import gzip
import json
import subprocess
import sys
from pathlib import Path

import pytest

from proxy.tests import oracle_gzip

ROOT = Path(__file__).resolve().parents[1]


def test_only_gzip_os_byte_is_canonicalized(monkeypatch):
    payload = b"source-oracle-gzip"
    encoded = gzip.compress(payload, mtime=0)
    mac_encoded = encoded[:9] + b"\x0d" + encoded[10:]
    monkeypatch.setattr(oracle_gzip.gzip, "compress", lambda value, *, mtime: mac_encoded)

    observed = oracle_gzip.compress(payload)
    assert observed == encoded[:9] + b"\x03" + encoded[10:]
    assert gzip.decompress(observed) == payload


def test_non_os_gzip_changes_remain_visible(monkeypatch):
    payload = b"source-oracle-gzip"
    encoded = gzip.compress(payload, mtime=0)
    changed = encoded[:-1] + bytes([encoded[-1] ^ 1])
    monkeypatch.setattr(oracle_gzip.gzip, "compress", lambda value, *, mtime: changed)

    observed = oracle_gzip.compress(payload)
    assert observed[:-1] == encoded[:9] + b"\x03" + encoded[10:-1]
    assert observed[-1] == changed[-1]
    assert observed != encoded[:9] + b"\x03" + encoded[10:]


@pytest.mark.parametrize(
    ("script", "golden", "name", "field"),
    [
        ("http_content_source.py", "http_content_source.json", "gzip_valid", "encoded_hex"),
        ("agent_api_flows_oracle.py", "agent_api_flows_source.json", "search_gzip", "input_hex"),
    ],
)
def test_oracles_still_reject_other_gzip_byte_changes(tmp_path, script, golden, name, field):
    source = ROOT / "proxy/tests"
    expected = json.loads((source / golden).read_text())
    row = next(row for row in expected["rows"] if row["name"] == name)
    encoded = row[field]
    row[field] = encoded[:20] + ("0" if encoded[20] != "0" else "1") + encoded[21:]
    altered_golden = tmp_path / golden
    altered_golden.write_text(json.dumps(expected))

    args = [str(altered_golden), "--check"] if script == "http_content_source.py" else ["--check", str(altered_golden)]
    result = subprocess.run(
        [sys.executable, str(source / script), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "AssertionError" in result.stderr
