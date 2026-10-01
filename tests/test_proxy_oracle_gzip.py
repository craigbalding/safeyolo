"""The source oracle's gzip fixture must not depend on the host OS byte."""

import gzip

from proxy.tests import oracle_gzip


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
