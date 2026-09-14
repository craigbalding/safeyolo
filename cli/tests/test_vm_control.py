"""Exercise the VM control client and commands through actual Unix sockets."""

import json
import socket
import threading
from contextlib import contextmanager

import pytest
from typer.testing import CliRunner

from safeyolo import agent_diag, vm_control
from safeyolo.commands.agent import agent_app


def _reply(**fields):
    return {"schema_version": 1, "instance": "process-one", "ok": True, **fields}


def _status(**changes):
    value = _reply(
        helper={"git_sha": "a" * 40, "build_profile": "production", "architecture": "arm64",
                "helper_version": "0.3.1", "get_task_allow": False, "hardened_runtime": True,
                "schema_version": 1, "version": "0.1.0", "git_dirty": False,
                "swift_compiler": "test", "optimization": "release", "symbols": "DWARF+dSYM"},
        vm={"state": "running", "heartbeat_at": 10}, pid=123, active=1, relay_fd_count=2,
        counts_by_kind={"proxy": 1}, counts_by_phase={"active": 1}, health="responsive",
        monotonic_now=10, accepted_shell_pending=0,
    )
    value.update(changes)
    return value


def _relay(number, kind="proxy"):
    return {"id": number, "kind": kind, "phase": "active", "bytes_in": 100, "bytes_out": 200}


@contextmanager
def _server(tmp_path, monkeypatch, respond, *, fragment_delay=0.0):
    path = tmp_path / "c.sock"
    monkeypatch.setattr(vm_control, "socket_path", lambda name: path)
    requests = []
    errors = []
    stop = threading.Event()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        listener.listen(8)
        listener.settimeout(0.05)

        def serve():
            while not stop.is_set():
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                try:
                    with connection:
                        connection.settimeout(1)
                        data = b""
                        while not data.endswith(b"\n"):
                            chunk = connection.recv(4096)
                            if not chunk:
                                break
                            data += chunk
                        if not data:
                            continue
                        request = json.loads(data)
                        requests.append(request)
                        response = respond(request)
                        encoded = response if isinstance(response, bytes) else json.dumps(response).encode() + b"\n"
                        if fragment_delay:
                            for byte in encoded:
                                if stop.wait(fragment_delay):
                                    break
                                connection.sendall(bytes([byte]))
                        else:
                            connection.sendall(encoded)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # Bounded clients deliberately close malformed/slow replies.
                except Exception as error:  # Re-raise worker failures in the foreground.
                    errors.append(error)
                    return

        worker = threading.Thread(target=serve)
        worker.start()
        try:
            yield requests
        finally:
            stop.set()
            worker.join(2)
            assert not worker.is_alive()
            assert not errors


@pytest.mark.parametrize("name", ["../victim", "a/b", "a\n", "", "a" * 64])
def test_control_path_rejects_invalid_names(name):
    with pytest.raises(vm_control.VMControlError):
        vm_control.socket_path(name)


def test_runtime_status_and_diagnostic_use_same_control_response(tmp_path, monkeypatch):
    with _server(tmp_path, monkeypatch, lambda request: _status()) as requests:
        value = vm_control.read_status("demo")
        checks = agent_diag._check_vm_runtime("demo")
    assert value["pid"] == 123
    assert all(check.status == "PASS" for check in checks)
    assert "a" * 40 in checks[0].message
    assert [request["operation"] for request in requests] == ["status", "status"]


def test_stale_executor_and_vm_queue_are_not_green(tmp_path, monkeypatch):
    response = _status(health="relay_executor_not_progressing", unresponsive_loops=["proxy"],
                       accepted_shell_pending=3, monotonic_now=20)
    with _server(tmp_path, monkeypatch, lambda request: response):
        checks = agent_diag._check_vm_runtime("demo")
    assert checks[1].status == "WARN" and "3 shell accepts pending" in checks[1].message
    assert checks[2].status == "WARN" and "cached" in checks[2].message


@pytest.mark.parametrize("response", [
    b"not json\n", b"[]\n", _reply(schema_version=True), _reply(instance="bad\nname"),
    _reply(ok=False, error="stale instance"), b"x" * (2 * 1024 * 1024 + 1) + b"\n",
], ids=["invalid-json", "array", "boolean-schema", "invalid-instance", "refused", "oversized"])
def test_malformed_or_refused_control_reply_is_an_error(tmp_path, monkeypatch, response):
    with _server(tmp_path, monkeypatch, lambda request: response):
        with pytest.raises(vm_control.VMControlError):
            vm_control.request("demo", "status")


def test_control_read_has_one_deadline_for_slow_fragments(tmp_path, monkeypatch):
    with _server(tmp_path, monkeypatch, lambda request: _status(), fragment_delay=0.03):
        with pytest.raises(vm_control.VMControlError, match="timed out|deadline"):
            vm_control.request("demo", "status", timeout=0.09)


def test_relay_pagination_and_instance_guard(tmp_path, monkeypatch):
    def reply(request):
        if request["after"] == 0:
            return _reply(relays=[_relay(1)], next_after=1)
        return _reply(relays=[_relay(2)], next_after=None)

    with _server(tmp_path, monkeypatch, reply):
        instance, records = vm_control.list_relays("demo")
    assert instance == "process-one" and [row["id"] for row in records] == [1, 2]


@pytest.mark.parametrize("second", [
    _reply(instance="replacement", relays=[_relay(2)], next_after=None),
    _reply(relays=[_relay(1)], next_after=1),
    _reply(relays=[], next_after=1),
    _reply(relays=[_relay(True)], next_after=None),
])
def test_changed_instance_or_nonprogressing_page_is_rejected(tmp_path, monkeypatch, second):
    with _server(tmp_path, monkeypatch, lambda request: _reply(relays=[_relay(1)], next_after=1) if request["after"] == 0 else second):
        with pytest.raises(vm_control.VMControlError):
            vm_control.list_relays("demo")


def test_cancellation_waits_for_observed_removal_and_preserves_reason(tmp_path, monkeypatch):
    polls = 0

    def reply(request):
        nonlocal polls
        if request["operation"] == "cancel":
            return _reply(queued_ids=[1], action_id="audit-one")
        polls += 1
        return _reply(relays=[_relay(1)] if polls == 1 else [], next_after=None)

    with _server(tmp_path, monkeypatch, reply) as requests:
        result = vm_control.cancel_relays("demo", "process-one", [1], reason="stalled download")
    assert polls == 2 and result["closed_ids"] == [1]
    assert requests[0]["instance"] == "process-one" and requests[0]["reason"] == "stalled download"


def test_queued_cancellation_is_not_reported_closed_on_timeout(tmp_path, monkeypatch):
    def reply(request):
        return _reply(queued_ids=[1], action_id="audit-one") if request["operation"] == "cancel" else _reply(relays=[_relay(1)], next_after=None)

    with _server(tmp_path, monkeypatch, reply):
        with pytest.raises(vm_control.VMControlError, match="deadline|timed out"):
            vm_control.cancel_relays("demo", "process-one", [1], reason="test", timeout=0.1)


def test_private_dump_replaces_link_without_writing_its_target(tmp_path, monkeypatch):
    target = tmp_path / "unrelated"
    target.write_text("preserve me")
    output = tmp_path / "dump.json"
    output.symlink_to(target)
    with _server(tmp_path, monkeypatch, lambda request: _status()):
        assert vm_control.write_dump("demo", output) == output
    assert target.read_text() == "preserve me" and not output.is_symlink()
    assert output.stat().st_mode & 0o777 == 0o600
    assert json.loads(output.read_text())["pid"] == 123


def test_bulk_dry_run_only_reads_matching_snapshot(tmp_path, monkeypatch):
    with _server(tmp_path, monkeypatch, lambda request: _reply(relays=[_relay(1), _relay(2, "shell")], next_after=None)) as requests:
        result = CliRunner().invoke(agent_app, ["vm", "cancel", "demo", "--all", "--kind", "proxy", "--dry-run", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["selected_ids"] == [1]
    assert [request["operation"] for request in requests] == ["relays"]


def test_cli_refuses_unscoped_bulk_cancel():
    result = CliRunner().invoke(agent_app, ["vm", "cancel", "demo", "--all"])
    assert result.exit_code != 0 and "requires" in result.output
