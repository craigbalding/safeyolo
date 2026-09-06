"""Fast Command Centre model and Qt UI tests."""

from __future__ import annotations

import json
import os
import time
from unittest.mock import create_autospec, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication
from typer.testing import CliRunner

from safeyolo.command_centre import credentials
from safeyolo.command_centre.client import SafeYoloClient, default_event_url
from safeyolo.command_centre.model import ApprovalItem
from safeyolo.command_centre.ui import ApprovalDialog, CommandCentre
from safeyolo.commands.command_centre import command_centre_app
from safeyolo.config import load_config
from safeyolo.core.operator_event_server import OperatorEventServer


def _application() -> QApplication:
    return QApplication.instance() or QApplication([])


def _wait_for(predicate, timeout: float = 3) -> None:
    application = _application()
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.01)
    assert predicate()


def _approval_event() -> dict:
    return {
        "event_id": "evt-one",
        "event": "gateway.risky_route",
        "kind": "gateway",
        "severity": "high",
        "summary": "GitHub write needs approval",
        "agent": "forge",
        "approval": {
            "required": True,
            "approval_type": "gateway_route",
            "key": "gw:forge:github:POST:/issues",
            "target": "github",
        },
        "details": {
            "service": "github",
            "method": "POST",
            "path": "/issues",
        },
    }


def _desktop_event() -> dict:
    return {
        "event_id": "evt-desktop",
        "event": "agent.desktop_present_requested",
        "kind": "agent",
        "severity": "high",
        "summary": "Lens requests desktop presentation",
        "agent": "lens",
        "approval": {
            "required": True,
            "approval_type": "desktop_present",
            "key": "desktop.present",
            "target": "desktop:ag-lens",
            "scope_hint": {"agent_id": "ag-lens"},
        },
        "details": {},
    }


def test_model_exposes_operator_relevant_fields():
    item = ApprovalItem(_approval_event())

    assert item.key == "gw:forge:github:POST:/issues:github"
    assert item.title == "forge: gateway_route → github"
    assert ("Method", "POST") in item.detail_rows
    assert ("Path", "/issues") in item.detail_rows


def test_default_event_url_preserves_host_and_transport_security():
    assert default_event_url("http://127.0.0.1:9090", 9091) == "ws://127.0.0.1:9091/admin/events"
    assert default_event_url("https://host.tail.example", 9443) == "wss://host.tail.example:9443/admin/events"


def test_approval_dialog_calls_resolution_callback():
    _application()
    item = ApprovalItem(_approval_event())
    resolutions = []

    def resolve(*args):
        resolutions.append(args)

    dialog = ApprovalDialog(item, resolve)

    dialog.allow_button.click()

    assert resolutions == [(item, True, None)]
    assert not dialog.buttons.isEnabled()


def test_approval_dialog_denial_calls_resolution_callback():
    _application()
    item = ApprovalItem(_approval_event())
    resolutions = []

    def resolve(*args):
        resolutions.append(args)

    dialog = ApprovalDialog(item, resolve)

    dialog.deny_button.click()

    assert resolutions == [(item, False, None)]
    assert not dialog.buttons.isEnabled()


def test_tray_lists_and_opens_pending_approval():
    _application()
    client = SafeYoloClient(
        admin_url="http://127.0.0.1:9090",
        events_url="ws://127.0.0.1:9091/admin/events",
        token="test",
    )
    command_centre = CommandCentre(client)

    command_centre._approvals_loaded([_approval_event()])

    assert any("forge: gateway_route" in action.text() for action in command_centre._approval_actions)
    assert command_centre._dialogs["gw:forge:github:POST:/issues:github"].isVisible()


def test_desktop_result_copies_code_and_opens_preview():
    application = _application()
    client = SafeYoloClient(
        admin_url="http://127.0.0.1:9090",
        events_url="ws://127.0.0.1:9091/admin/events",
        token="test",
    )
    command_centre = CommandCentre(client)
    command_centre._approvals_loaded([_desktop_event()])

    with patch(
        "safeyolo.command_centre.ui.QDesktopServices.openUrl",
        autospec=True,
    ) as open_url:
        command_centre._action_finished(
            "desktop.present:desktop:ag-lens",
            True,
            {
                "url": "http://127.0.0.1:54321/vnc.html",
                "unlock_code": "1234-5678",
            },
        )

    assert application.clipboard().text() == "1234-5678"
    assert open_url.call_args.args[0].toString() == "http://127.0.0.1:54321/vnc.html"


def test_resolving_legacy_event_closes_only_matching_dialog():
    _application()
    client = SafeYoloClient(
        admin_url="http://127.0.0.1:9090",
        events_url="ws://127.0.0.1:9091/admin/events",
        token="test",
    )
    command_centre = CommandCentre(client)
    first = _approval_event()
    first.pop("event_id")
    second = _desktop_event()
    second.pop("event_id")
    command_centre._approvals_loaded([first, second])
    command_centre.show_approval("desktop.present:desktop:ag-lens")

    command_centre._action_finished(
        "gw:forge:github:POST:/issues:github",
        True,
        "Approved",
    )

    assert "gw:forge:github:POST:/issues:github" not in command_centre._dialogs
    assert "desktop.present:desktop:ag-lens" in command_centre._dialogs


def test_keychain_commands_are_scoped_to_stable_instance_id():
    keychain = create_autospec(credentials.Keychain, instance=True, spec_set=True)
    keychain.get_password.return_value = "stored-token"
    with patch(
        "safeyolo.command_centre.credentials._keychain",
        return_value=keychain,
        autospec=True,
    ):
        credentials.store_token("sy-one", "stored-token")
        assert credentials.load_token("sy-one") == "stored-token"
        credentials.delete_token("sy-one")

    keychain.set_password.assert_called_once_with("io.safeyolo.command-centre", "sy-one", "stored-token")
    keychain.get_password.assert_called_once_with("io.safeyolo.command-centre", "sy-one")
    keychain.delete_password.assert_called_once_with("io.safeyolo.command-centre", "sy-one")


def test_enable_and_disable_are_explicit_config_changes(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    runner = CliRunner()

    enabled = runner.invoke(command_centre_app, ["enable", "--events-port", "9191"])
    assert enabled.exit_code == 0, enabled.output
    assert "Restart SafeYolo" in enabled.output
    assert load_config()["command_centre"] == {
        "enabled": True,
        "events_port": 9191,
        "share": "local",
        "tailnet_admin_port": 9443,
        "tailnet_events_port": 9444,
    }

    disabled = runner.invoke(command_centre_app, ["disable"])
    assert disabled.exit_code == 0, disabled.output
    assert load_config()["command_centre"]["enabled"] is False


def test_enable_tailnet_records_explicit_transport(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    runner = CliRunner()

    enabled = runner.invoke(
        command_centre_app,
        [
            "enable",
            "--share",
            "tailnet",
            "--tailnet-admin-port",
            "10443",
            "--tailnet-events-port",
            "10444",
        ],
    )

    assert enabled.exit_code == 0, enabled.output
    assert "explicit Tailnet publication" in enabled.output
    assert load_config()["command_centre"] == {
        "enabled": True,
        "events_port": 9091,
        "share": "tailnet",
        "tailnet_admin_port": 10443,
        "tailnet_events_port": 10444,
    }

    state_path = tmp_path / "data" / "command-centre-tailnet-status.json"
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(
            {
                "state": "healthy",
                "admin_url": "https://dev.example.ts.net:10443/",
                "events_url": "wss://dev.example.ts.net:10444/admin/events",
            }
        )
    )
    status = runner.invoke(command_centre_app, ["status"])
    assert status.exit_code == 0, status.output
    assert "Tailnet publication: healthy" in status.output
    assert "https://dev.example.ts.net:10443/" in status.output
    assert "wss://dev.example.ts.net:10444/admin/events" in status.output


def test_qt_client_receives_authenticated_live_event(tmp_path):
    log = tmp_path / "safeyolo.jsonl"
    log.write_text("")
    server = OperatorEventServer(log_path=log, token="operator-token", port=0)
    server.start()
    client = SafeYoloClient(
        admin_url="http://127.0.0.1:1",
        events_url=f"ws://127.0.0.1:{server.port}/admin/events",
        token="operator-token",
    )
    connection_states = []
    received = []
    client.connection_changed.connect(connection_states.append)
    client.event_received.connect(received.append)
    try:
        client._open_websocket()
        _wait_for(lambda: connection_states == [True])
        event = _approval_event()
        with log.open("a") as stream:
            stream.write(json.dumps(event) + "\n")
            stream.flush()
        _wait_for(lambda: received == [event])
    finally:
        client.stop()
        server.stop()
