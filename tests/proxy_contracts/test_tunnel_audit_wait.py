"""HTTP audit readiness must include each required path and event type."""

import json

import pytest

from tests.proxy_contracts import test_tunnel_contract as contract


@pytest.mark.parametrize("event, path", [
    ("traffic.request", "/untrusted"),
    ("traffic.response", "/other-host"),
])
def test_http_audit_wait_reads_delayed_complete_record(tmp_path, monkeypatch, event, path):
    audit = tmp_path / "audit.jsonl"
    lifecycle = {"event": "traffic.passthrough_end", "details": {}}
    other = {"event": "traffic.request", "details": {"path": "/other-host"}}
    delayed = {"event": event, "details": {"path": path, "canary": "café"}}
    record = json.dumps(delayed, ensure_ascii=False).encode()
    cut = record.index("é".encode()) + 1
    audit.write_bytes(json.dumps(lifecycle).encode() + b"\n" +
                      json.dumps(other).encode() + b"\n" + record[:cut])
    polls = []

    def publish(_interval):
        polls.append(1)
        with audit.open("ab") as writer:
            writer.write(record[cut:] + b"\n")

    monkeypatch.setattr(contract.time, "sleep", publish)
    rows = contract.wait_for_http_audit(tmp_path, {(event, path)})
    assert polls == [1]
    assert rows == [other, delayed]


def test_http_audit_wait_fails_for_missing_evidence(tmp_path, monkeypatch):
    # The expected path alone does not prove the required event type.
    audit = tmp_path / "audit.jsonl"
    audit.write_text(json.dumps({
        "event": "traffic.request", "details": {"path": "/other-host"},
    }) + "\n")
    clock = [0.0]
    monkeypatch.setattr(contract.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(contract.time, "sleep", lambda interval: clock.__setitem__(0, clock[0] + interval))
    required = {("traffic.request", "/untrusted"), ("traffic.response", "/other-host")}

    with pytest.raises(AssertionError, match="timed out waiting for HTTP audit events") as failure:
        contract.wait_for_http_audit(tmp_path, required, timeout=0.02)

    assert "('traffic.request', '/untrusted')" in str(failure.value)
    assert "('traffic.response', '/other-host')" in str(failure.value)
    assert "observed=" in str(failure.value)
    assert clock[0] == 0.02
