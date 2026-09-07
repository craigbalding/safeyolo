"""Admin API surfaces needed by trusted operator clients."""

from __future__ import annotations

import json
import logging
import os
import pwd
import sys
import threading
from unittest.mock import create_autospec, patch

import httpx
import pytest

from safeyolo.agent_lifecycle import AgentRuntime
from safeyolo.api import AdminAPI
from safeyolo.desktop_presenter import DesktopPresentation, DesktopPresenter
from safeyolo.mitm_addons.admin_api import AdminRequestHandler, LoopbackHTTPServer


def test_request_logging_sanitizes_formatted_text_without_truncating(caplog):
    handler = object.__new__(AdminRequestHandler)
    suffix = "x" * 250
    with caplog.at_level(logging.DEBUG, logger="safeyolo.admin"):
        handler.log_message("request %s", "ag-probe\r\n\x1b[31m\u202e" + suffix)

    assert caplog.records[-1].getMessage() == "Admin API: request ag-probe?" + suffix


@pytest.mark.parametrize("action", ["desktop", "start", "stop"])
def test_failed_actions_sanitize_log_identity_and_preserve_traceback(action, caplog):
    handler = object.__new__(AdminRequestHandler)
    agent_id = "ag-probe\r\n\x1b[31m\u202e" + "x" * 250
    presenter = create_autospec(DesktopPresenter, instance=True, spec_set=True)
    presenter.present.side_effect = RuntimeError("presentation failed")
    handler.desktop_presenter = presenter
    with (
        patch.object(handler, "_read_optional_json_object", return_value={}, autospec=True),
        patch.object(handler, "_send_json", autospec=True) as send_json,
        patch("safeyolo.agent_lifecycle.start_agent", side_effect=RuntimeError("start failed"), autospec=True),
        patch("safeyolo.agent_lifecycle.stop_agent", side_effect=RuntimeError("stop failed"), autospec=True),
    ):
        if action == "desktop":
            handler._handle_post_desktop_present(agent_id)
        else:
            handler._handle_post_agent_lifecycle(agent_id, action)

    record = caplog.records[-1]
    prefix = "Desktop presentation failed for agent" if action == "desktop" else f"Agent {action} failed for"
    assert record.getMessage() == prefix + " ag-probe?" + "x" * 250
    assert record.exc_info is not None
    assert record.exc_info[0] is RuntimeError
    assert send_json.call_args.args[1] == 500


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


def test_instance_endpoint_is_authenticated_and_stable(command_centre_admin, monkeypatch):
    monkeypatch.setenv("USER", "not-the-proxy-user")
    monkeypatch.setenv("LOGNAME", "not-the-proxy-user")
    base_url, _ = command_centre_admin
    unauthorized = httpx.get(f"{base_url}/admin/instance")
    assert unauthorized.status_code == 401

    api = AdminAPI(base_url=base_url, token="test-admin-token")
    first = api.instance()
    second = api.instance()

    assert first == second
    assert first["safeyolo_instance_id"].startswith("sy-")
    assert first["host_user"] == pwd.getpwuid(os.geteuid()).pw_name
    assert first["host_python"] == sys.executable
    assert first["webmitm_url"] is None
    assert first["capabilities"] == {
        "agent_inventory": True,
        "agent_lifecycle": True,
        "approvals": True,
        "audit_events": True,
        "desktop_present": True,
    }


def test_instance_reports_live_webmitm_url_without_guessing_port(command_centre_admin, monkeypatch):
    from safeyolo.traffic_master import WebTailnetShare

    share = create_autospec(WebTailnetShare, instance=True, spec_set=True)
    share.get_stats.return_value = {"state": "healthy", "url": "https://dev.example.ts.net:8443/"}
    monkeypatch.setattr(AdminRequestHandler, "addons_with_stats", {"safeyolo-web-tailnet-share": share})
    base_url, _ = command_centre_admin
    api = AdminAPI(base_url=base_url, token="test-admin-token")
    assert api.instance()["webmitm_url"] == "https://dev.example.ts.net:8443/"
    share.get_stats.return_value = {"state": "disabled", "url": None}
    assert api.instance()["webmitm_url"] is None


def test_instance_identity_survives_unmapped_host_uid(command_centre_admin):
    base_url, _ = command_centre_admin
    api = AdminAPI(base_url=base_url, token="test-admin-token")
    with patch("safeyolo.mitm_addons.admin_api.pwd.getpwuid", side_effect=KeyError, autospec=True):
        instance = api.instance()
    assert instance["host_user"] is None
    assert instance["safeyolo_instance_id"].startswith("sy-")


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

    with patch(
        "safeyolo.mitm_addons.admin_api.write_event",
        autospec=True,
    ) as write_event:
        assert api.present_desktop(
            "ag-forge",
            approval_request_id="req-desktop",
        ) == {
            "agent_id": "ag-forge",
            "agent": "forge",
            "url": "http://127.0.0.1:12345/vnc.html",
            "unlock_code": "1234-5678",
            "reused": False,
        }
    presenter.present.assert_called_once_with("ag-forge")
    assert write_event.call_args.kwargs["details"]["approval_request_id"] == "req-desktop"


def test_agent_inventory_and_lifecycle_use_stable_agent_ids(command_centre_admin):
    base_url, _ = command_centre_admin
    api = AdminAPI(base_url=base_url, token="test-admin-token")
    stopped = AgentRuntime(agent_id="ag-probe", name="probe", sandbox_state="stopped")
    running = AgentRuntime(agent_id="ag-probe", name="probe", sandbox_state="ready", agent_state="running")

    with (
        patch(
            "safeyolo.agent_lifecycle.list_agent_runtimes",
            return_value=[stopped],
            autospec=True,
        ),
        patch(
            "safeyolo.agent_lifecycle.start_agent",
            return_value=running,
            autospec=True,
        ) as start,
        patch(
            "safeyolo.agent_lifecycle.stop_agent",
            return_value=stopped,
            autospec=True,
        ) as stop,
    ):
        assert api.agents() == [stopped.to_dict()]
        assert api.start_agent("ag-probe") == running.to_dict()
        assert api.stop_agent("ag-probe") == stopped.to_dict()

    start.assert_called_once_with("ag-probe")
    stop.assert_called_once_with("ag-probe")


def test_stopping_agent_closes_its_active_desktop(command_centre_admin):
    base_url, _ = command_centre_admin
    stopped = AgentRuntime(agent_id="ag-probe", name="probe", sandbox_state="stopped")
    presenter = create_autospec(DesktopPresenter, instance=True, spec_set=True)
    AdminRequestHandler.desktop_presenter = presenter
    api = AdminAPI(base_url=base_url, token="test-admin-token")

    with patch(
        "safeyolo.agent_lifecycle.stop_agent",
        return_value=stopped,
        autospec=True,
    ):
        api.stop_agent("ag-probe")

    presenter.close.assert_called_once_with("ag-probe")


@pytest.mark.parametrize("action", ["start", "start-interactive", "stop"])
@pytest.mark.parametrize("payload", [{"command": "anything"}, {"launcher": "/tmp/host.sh"}, {"argv": ["--option"]}])
def test_agent_lifecycle_rejects_command_arguments(command_centre_admin, action, payload):
    base_url, _ = command_centre_admin
    with (
        patch("safeyolo.agent_lifecycle.start_agent", autospec=True) as start,
        patch("safeyolo.agent_lifecycle.stop_agent", autospec=True) as stop,
    ):
        response = httpx.post(
            f"{base_url}/admin/agents/ag-probe/{action}",
            headers={"Authorization": "Bearer test-admin-token"},
            json=payload,
        )

    assert response.status_code == 400
    assert response.json()["error"] == "Agent lifecycle requests do not accept arguments"
    start.assert_not_called()
    stop.assert_not_called()


def test_interactive_start_is_a_fixed_named_action(command_centre_admin):
    base_url, _ = command_centre_admin
    api = AdminAPI(base_url=base_url, token="test-admin-token")
    runtime = AgentRuntime(agent_id="ag-probe", name="probe", sandbox_state="ready", agent_state="starting")
    with patch("safeyolo.agent_lifecycle.start_agent", return_value=runtime, autospec=True) as start:
        assert api.start_agent("ag-probe", interactive=True) == runtime.to_dict()
    start.assert_called_once_with("ag-probe", interactive=True)
