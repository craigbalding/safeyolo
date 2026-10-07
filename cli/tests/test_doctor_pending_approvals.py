"""Doctor reports blocked decisions without treating approval as a repair."""


import json

from safeyolo.commands import doctor as doctor_module
from safeyolo.core.audit_stream import pending_approval_review


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
