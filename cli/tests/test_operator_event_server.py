"""Tests for the Command Centre's live event hint channel."""

from __future__ import annotations

import json
import logging
from unittest.mock import patch

import pytest
from websockets.exceptions import InvalidStatus
from websockets.sync.client import connect

from safeyolo.core.audit_schema import InvalidAuditEvent
from safeyolo.core.operator_event_server import (
    OperatorEventServer,
    is_operator_event,
)


def test_stream_diagnostics_sanitize_errors_without_truncating(tmp_path, caplog):
    server = OperatorEventServer(log_path=tmp_path / "audit.jsonl", token="operator-token")
    detail = "broken\r\n\x1b[31m\u202e" + "x" * 250

    def read_events(path, *, parse_line, **kwargs):
        parse_line("{}")
        raise ConnectionError(detail)

    with (
        caplog.at_level(logging.DEBUG, logger="safeyolo.operator-events"),
        patch("safeyolo.core.audit_stream.parse_audit_event", side_effect=InvalidAuditEvent(detail, {}), autospec=True),
        patch("safeyolo.core.operator_event_server.follow_jsonl", side_effect=read_events, autospec=True),
    ):
        server._handle_connection(object())

    assert [record.getMessage() for record in caplog.records] == [
        "Audit schema drift: broken?" + "x" * 250,
        "Operator event client disconnected: broken?" + "x" * 250,
    ]


def _event(event_id: str, event_type: str, **extra) -> dict:
    return {
        "event_id": event_id,
        "event": event_type,
        "kind": event_type.split(".", 1)[0],
        "severity": "low",
        "summary": event_type,
        "details": {},
        **extra,
    }


@pytest.fixture
def event_server(tmp_path):
    log = tmp_path / "safeyolo.jsonl"
    log.write_text("")
    server = OperatorEventServer(log_path=log, token="operator-token", port=0)
    server.start()
    try:
        yield server, log
    finally:
        server.stop()


def test_filter_includes_approvals_resolutions_lifecycle_and_proxy_state():
    approval = _event(
        "evt-approval",
        "security.credential_guard",
        approval={"required": True},
    )
    resolution = _event(
        "evt-resolution",
        "admin.host_allowed",
        details={"host": "example.com"},
    )

    assert is_operator_event(approval)
    assert is_operator_event(resolution)
    assert is_operator_event(_event("evt-agent", "agent.started"))
    assert is_operator_event(_event("evt-proxy", "ops.proxy_stop"))
    assert is_operator_event(_event("evt-command-centre", "ops.command_centre_tailnet_failed"))
    assert is_operator_event(
        _event(
            "evt-security",
            "security.pattern_detected",
            severity="high",
        )
    )
    assert is_operator_event(
        _event(
            "evt-gateway",
            "gateway.route_denied",
            severity="critical",
        )
    )
    assert is_operator_event(_event("evt-circuit", "ops.circuit_breaker.open"))
    assert not is_operator_event(
        _event(
            "evt-low-security",
            "security.pattern_detected",
            severity="low",
        )
    )
    assert not is_operator_event(_event("evt-traffic", "traffic.request"))


def test_websocket_requires_admin_bearer_token(event_server):
    server, _ = event_server
    with pytest.raises(InvalidStatus, match="401"):
        connect(
            f"ws://127.0.0.1:{server.port}/admin/events",
            proxy=None,
        )


def test_websocket_streams_complete_audit_event(event_server):
    server, log = event_server
    expected = _event(
        "evt-approval",
        "security.credential_guard",
        host="api.example.com",
        approval={
            "required": True,
            "approval_type": "credential",
            "key": "hmac:example",
            "target": "api.example.com",
        },
    )

    with connect(
        f"ws://127.0.0.1:{server.port}/admin/events",
        additional_headers={"Authorization": "Bearer operator-token"},
        proxy=None,
    ) as websocket:
        with log.open("a") as stream:
            stream.write(json.dumps(_event("evt-noise", "traffic.request")) + "\n")
            stream.write(json.dumps(expected) + "\n")
            stream.flush()
        assert json.loads(websocket.recv(timeout=3)) == expected
