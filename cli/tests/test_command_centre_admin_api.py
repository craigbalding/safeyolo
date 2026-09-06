"""Admin API surfaces needed by trusted operator clients."""

from __future__ import annotations

import json
import threading
from unittest.mock import create_autospec

import httpx
import pytest

from safeyolo.api import AdminAPI
from safeyolo.desktop_presenter import DesktopPresentation, DesktopPresenter
from safeyolo.mitm_addons.admin_api import AdminRequestHandler, LoopbackHTTPServer


@pytest.fixture
def command_centre_admin(tmp_path, monkeypatch):
    log = tmp_path / "safeyolo.jsonl"
    monkeypatch.setenv("SAFEYOLO_LOG_PATH", str(log))
    monkeypatch.setenv("SAFEYOLO_COORD_DATA_DIR", str(tmp_path / "coord"))
    AdminRequestHandler.admin_token = "test-admin-token"
    server = LoopbackHTTPServer(("127.0.0.1", 0), AdminRequestHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", log
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
        AdminRequestHandler.admin_token = None
        AdminRequestHandler.desktop_presenter = None


def _approval_event(event_id: str = "evt-approval") -> dict:
    return {
        "event_id": event_id,
        "event": "security.credential_guard",
        "kind": "security",
        "severity": "high",
        "decision": "require_approval",
        "summary": "Credential needs operator approval",
        "host": "api.example.com",
        "approval": {
            "required": True,
            "approval_type": "credential",
            "key": "hmac:example",
            "target": "api.example.com",
        },
        "details": {},
    }


def test_instance_endpoint_is_authenticated_and_stable(command_centre_admin):
    base_url, _ = command_centre_admin
    unauthorized = httpx.get(f"{base_url}/admin/instance")
    assert unauthorized.status_code == 401

    api = AdminAPI(base_url=base_url, token="test-admin-token")
    first = api.instance()
    second = api.instance()

    assert first == second
    assert first["safeyolo_instance_id"].startswith("sy-")
    assert first["capabilities"] == {
        "approvals": True,
        "audit_events": True,
        "desktop_present": True,
    }


def test_pending_approvals_come_from_durable_audit_log(command_centre_admin):
    base_url, log = command_centre_admin
    event = _approval_event()
    log.write_text(json.dumps(event) + "\n")
    api = AdminAPI(base_url=base_url, token="test-admin-token")

    assert api.pending_approvals() == [event]

    resolution = {
        "event_id": "evt-resolution",
        "event": "admin.approval_added",
        "kind": "admin",
        "severity": "low",
        "summary": "Approved",
        "details": {
            "cred_id": "hmac:example",
            "destination": "api.example.com",
        },
    }
    with log.open("a") as stream:
        stream.write(json.dumps(resolution) + "\n")

    assert api.pending_approvals() == []


def test_desktop_present_uses_stable_agent_id(command_centre_admin):
    base_url, _ = command_centre_admin
    presenter = create_autospec(DesktopPresenter, instance=True, spec_set=True)
    presenter.present.return_value = DesktopPresentation(
        agent_id="ag-forge",
        agent="forge",
        url="http://127.0.0.1:12345/vnc.html",
        unlock_code="1234-5678",
        reused=False,
    )
    AdminRequestHandler.desktop_presenter = presenter
    api = AdminAPI(base_url=base_url, token="test-admin-token")

    assert api.present_desktop("ag-forge") == {
        "agent_id": "ag-forge",
        "agent": "forge",
        "url": "http://127.0.0.1:12345/vnc.html",
        "unlock_code": "1234-5678",
        "reused": False,
    }
    presenter.present.assert_called_once_with("ag-forge")
