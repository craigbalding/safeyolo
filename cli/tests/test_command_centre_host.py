"""Fixed host actions and publication cleanup used by the native Admin API."""

from __future__ import annotations

import json
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from safeyolo import command_centre_agent_host, command_centre_tailnet_host
from safeyolo.agent_lifecycle import AgentLifecycleError, AgentRuntime


class _FakeProcess:
    def __init__(self, pid, poll_results=None):
        self.pid = pid
        self.poll_results = list(poll_results or [])

    def poll(self):
        return self.poll_results.pop(0) if self.poll_results else None


class _FakeServe:
    def __init__(self, port, pid, poll_results=None):
        self.port = port
        self.process = _FakeProcess(pid, poll_results)
        self.closed = False

    def url(self, path):
        return f"https://host.test:{self.port}{path}"

    def close(self):
        self.closed = True


@pytest.mark.parametrize(("operation", "interactive"), [
    ("start", False),
    ("start-interactive", True),
])
def test_agent_host_start_uses_existing_fixed_lifecycle(operation, interactive, monkeypatch, capsys):
    monkeypatch.setattr(command_centre_agent_host.sys, "argv", ["host", operation, "ag-probe"])
    runtime = AgentRuntime("ag-probe", "probe", "ready", "running", attachable=True)
    with patch.object(command_centre_agent_host, "start_agent", autospec=True, return_value=runtime) as start:
        assert command_centre_agent_host.main() == 0
    assert json.loads(capsys.readouterr().out)["agent_id"] == "ag-probe"
    start.assert_called_once_with("ag-probe", interactive=interactive)


def test_agent_host_reports_unknown_agent_without_success(monkeypatch, capsys):
    monkeypatch.setattr(command_centre_agent_host.sys, "argv", ["host", "stop", "ag-missing"])
    with patch.object(command_centre_agent_host, "stop_agent", autospec=True,
                      side_effect=AgentLifecycleError("Agent not found", status_code=404)):
        assert command_centre_agent_host.main() == 0
    assert json.loads(capsys.readouterr().out) == {"error": "Agent not found", "status_code": 404}


def test_agent_host_preserves_invalid_start_state(monkeypatch, capsys):
    monkeypatch.setattr(command_centre_agent_host.sys, "argv", ["host", "start", "ag-probe"])
    with patch.object(command_centre_agent_host, "start_agent", autospec=True,
                      side_effect=AgentLifecycleError("Agent is already starting", status_code=409)):
        assert command_centre_agent_host.main() == 0
    assert json.loads(capsys.readouterr().out) == {
        "error": "Agent is already starting", "status_code": 409,
    }


def test_agent_host_rejects_unselected_operation(monkeypatch, capsys):
    monkeypatch.setattr(command_centre_agent_host.sys, "argv", ["host", "shell", "ag-probe"])
    with patch.object(command_centre_agent_host, "start_agent", autospec=True) as start:
        assert command_centre_agent_host.main() == 0
    assert json.loads(capsys.readouterr().out)["status_code"] == 400
    start.assert_not_called()


def test_tailnet_host_closes_both_mappings_when_parent_closes(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(command_centre_tailnet_host.sys, "stdin", SimpleNamespace(buffer=BytesIO()))
    monkeypatch.setattr(command_centre_tailnet_host.select, "select", lambda *_args: ([object()], [], []))
    admin = _FakeServe(9443, 1234)
    events = _FakeServe(9444, 1235)
    state = tmp_path / "tailnet-state.json"
    with patch.object(command_centre_tailnet_host, "start_tailnet_serve", autospec=True,
                      side_effect=[admin, events]) as start:
        assert command_centre_tailnet_host.publish(9090, 9091, 9443, 9444, state) == 0
    start.assert_any_call(9090, 9443)
    start.assert_any_call(9091, 9444)
    assert json.loads(capsys.readouterr().out)["state"] == "healthy"
    assert not state.exists()
    assert events.closed and admin.closed


def test_tailnet_host_closes_first_mapping_if_second_fails(tmp_path, capsys):
    admin = _FakeServe(9443, 1234)
    with patch.object(command_centre_tailnet_host, "start_tailnet_serve", autospec=True,
                      side_effect=[admin, RuntimeError("events port unavailable")]):
        assert command_centre_tailnet_host.publish(9090, 9091, 9443, 9444, tmp_path / "state") == 1
    assert json.loads(capsys.readouterr().out)["state"] == "error"
    assert admin.closed


def test_tailnet_host_marks_failed_mapping_and_closes_both(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(command_centre_tailnet_host.sys, "stdin", SimpleNamespace(buffer=BytesIO()))
    monkeypatch.setattr(command_centre_tailnet_host.select, "select", lambda *_args: ([], [], []))
    admin = _FakeServe(9443, 1234)
    events = _FakeServe(9444, 1235, [None, 1])
    state = tmp_path / "state.json"
    with patch.object(command_centre_tailnet_host, "start_tailnet_serve", autospec=True,
                      side_effect=[admin, events]):
        assert command_centre_tailnet_host.publish(9090, 9091, 9443, 9444, state) == 1
    assert json.loads(state.read_text())["state"] == "error"
    assert "mapping exited" in capsys.readouterr().err
    assert events.closed and admin.closed
