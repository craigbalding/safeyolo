"""Doctor reports blocked decisions without treating approval as a repair."""

import json

from safeyolo.commands import doctor as doctor_module
from safeyolo.commands import factory as factory_module
from safeyolo.core.audit_stream import pending_approval_review
from safeyolo.factory_doctor import (
    FactoryDoctorCheck,
    FactoryDoctorReport,
    _inspect_pending_approvals,
)


def _append(log_path, event):
    with log_path.open("a") as stream:
        stream.write(json.dumps(event) + "\n")


def _credential_event(agent, key, host, ts):
    return {
        "ts": ts,
        "event": "security.credential_guard",
        "decision": "require_approval",
        "agent": agent,
        "host": host,
        "approval": {
            "required": True,
            "approval_type": "credential",
            "key": key,
            "target": host,
        },
        "details": {
            "rule": "huggingface[red]",
            "credential": "raw-secret-must-not-appear",
        },
    }


def test_doctor_warns_on_deduplicated_pending_decision_without_exposing_secret(
    tmp_path, monkeypatch
):
    log_path = tmp_path / "safeyolo.jsonl"
    event = _credential_event("forge", "hmac:private-fingerprint", "chatgpt.com", "2026-09-26T00:00:00Z")
    _append(log_path, event)
    _append(log_path, {**event, "ts": "2026-09-26T00:01:00Z"})

    review = pending_approval_review(log_path)
    assert review.count == 1
    assert review.examples == (
        "agent=forge kind=credential destination=chatgpt.com "
        "classified=huggingface?red? seen_since=2026-09-26T00:00:00Z requests=2",
    )
    monkeypatch.setattr(doctor_module, "get_logs_dir", lambda: tmp_path)
    result = doctor_module._check_pending_approvals()
    assert result.status == "warn"
    assert "provisional" in result.detail
    assert "SAFEYOLO_CONFIG_DIR and SAFEYOLO_LOGS_DIR" in result.detail
    assert "not an instruction to approve" in result.detail
    assert result.remediation == ""
    assert "raw-secret" not in result.detail
    assert "private-fingerprint" not in result.detail


def test_factory_doctor_warns_only_for_its_workers_and_resolution_clears_it(tmp_path, monkeypatch):
    log_path = tmp_path / "safeyolo.jsonl"
    _append(log_path, _credential_event("forge", "hmac:forge", "chatgpt.com", "2026-09-26T00:00:00Z"))
    _append(log_path, _credential_event("other", "hmac:other", "example.com", "2026-09-26T00:00:00Z"))
    monkeypatch.setattr("safeyolo.factory_doctor.get_logs_dir", lambda: tmp_path)
    payload = {"roles": {"owner": {"agent": "forge"}, "reviewer": {"agent": "lens"}}}

    checks = []
    _inspect_pending_approvals(checks, payload)
    assert FactoryDoctorReport("test", tuple(checks)).status == "WARN"
    assert len(checks) == 1
    assert "agent=forge" in checks[0].detail
    assert "example.com" not in checks[0].detail
    assert "verify agent, destination, and requested action" in checks[0].recovery
    assert "SAFEYOLO_CONFIG_DIR and SAFEYOLO_LOGS_DIR" in checks[0].recovery
    assert "not an instruction to approve" in checks[0].recovery

    _append(log_path, {
        "event": "admin.approval_added",
        "details": {"cred_id": "hmac:forge", "destination": "chatgpt.com"},
    })
    checks = []
    _inspect_pending_approvals(checks, payload)
    assert checks == []


def test_pending_approval_warning_does_not_block_factory_start(monkeypatch):
    report = FactoryDoctorReport(
        "backlog",
        (
            FactoryDoctorCheck("PASS", "supervisor", "running"),
            FactoryDoctorCheck("WARN", "operator-approvals", "1 unresolved decision"),
        ),
    )
    monkeypatch.setattr(factory_module, "inspect_factory", lambda _name: report)

    assert report.status == "WARN"
    assert factory_module._wait_for_operational_preflight("backlog") is report
