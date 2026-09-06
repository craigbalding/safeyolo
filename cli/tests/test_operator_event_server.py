"""Tests for the Command Centre's live event hint channel."""

from __future__ import annotations

import json

import pytest
from websockets.exceptions import InvalidStatus
from websockets.sync.client import connect

from safeyolo.core.operator_event_server import (
    OperatorEventServer,
    is_operator_event,
)


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
