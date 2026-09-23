"""Owned-file Rust CLI lifecycle controls with mocked external boundaries."""

import json
import signal
import socket
import subprocess
import time
import urllib.request
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import create_autospec

import pytest

from safeyolo import config as safeyolo_config
from safeyolo import proxy, runtime_identity, rust_proxy, traffic_session

PID = 24680
TOKEN = "owned-process-generation"


@pytest.fixture
def launch(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path / "logs"))
    binary = tmp_path / "owned proxy"
    binary.write_text("not an executable program; subprocess is mocked")
    binary.chmod(0o700)
    monkeypatch.setenv("SAFEYOLO_RUST_PROXY", str(binary))
    config_path = tmp_path / "native config.json"
    ready = tmp_path / "ready.json"
    native = {
        "policy_file": str(tmp_path / "policy.toml"),
        "readiness_file": str(ready),
        "listeners": [{"agent_id": "alice", "socket_path": str(tmp_path / "alice.sock")}],
        "admin_port": None,
    }
    config_path.write_text(json.dumps(native))
    config = {"proxy": {"backend": "rust", "rust_config": str(config_path)}}
    version = create_autospec(
        subprocess.run, spec_set=True, return_value=subprocess.CompletedProcess([], 0, stdout="safeyolo-proxy 0.1.0\n", stderr="")
    )
    monkeypatch.setattr(rust_proxy.subprocess, "run", version)
    monkeypatch.setattr(proxy, "load_config", create_autospec(proxy.load_config, spec_set=True, return_value=config))
    python_start = create_autospec(proxy._start_python_proxy, spec_set=True)
    python_stop = create_autospec(proxy._stop_python_proxy, spec_set=True)
    monkeypatch.setattr(proxy, "_start_python_proxy", python_start)
    monkeypatch.setattr(proxy, "_stop_python_proxy", python_stop)
    pane = create_autospec(rust_proxy.session_process_id, spec_set=True, return_value=None)
    begin = create_autospec(rust_proxy.start_session, spec_set=True, return_value=PID)
    end = create_autospec(traffic_session.stop_session, spec_set=True)
    monkeypatch.setattr(traffic_session, "stop_session", end)
    monkeypatch.setattr(proxy, "stop_session", end)
    capture = create_autospec(rust_proxy.capture_session, spec_set=True, return_value="owned console evidence")
    alive = create_autospec(rust_proxy.process_is_alive, spec_set=True, return_value=True)
    token = create_autospec(rust_proxy.process_start_token, spec_set=True, return_value=TOKEN)
    for name, mock in {
        "session_process_id": pane,
        "start_session": begin,
        "capture_session": capture,
        "process_is_alive": alive,
        "process_start_token": token,
    }.items():
        monkeypatch.setattr(rust_proxy, name, mock)
    kill = create_autospec(rust_proxy.os.kill, spec_set=True)
    monkeypatch.setattr(rust_proxy.os, "kill", kill)
    terminate_original = rust_proxy._terminate
    terminate = create_autospec(terminate_original, spec_set=True, side_effect=lambda process: kill(process.pid, signal.SIGTERM))
    monkeypatch.setattr(rust_proxy, "_terminate", terminate)
    http = create_autospec(urllib.request.urlopen, spec_set=True, side_effect=AssertionError("unconfigured HTTP boundary"))
    monkeypatch.setattr(urllib.request, "urlopen", http)
    clock = create_autospec(time, spec_set=True)
    clock.monotonic.return_value = 0.0
    monkeypatch.setattr(rust_proxy, "time", clock)
    monkeypatch.setattr(proxy, "time", clock)
    return SimpleNamespace(
        root=tmp_path,
        binary=binary,
        path=config_path,
        ready=ready,
        native=native,
        config=config,
        version=version,
        python_start=python_start,
        python_stop=python_stop,
        pane=pane,
        begin=begin,
        end=end,
        capture=capture,
        alive=alive,
        token=token,
        kill=kill,
        terminate=terminate,
        terminate_original=terminate_original,
        http=http,
        clock=clock,
    )


def marker(**changes):
    return {
        "ready": True,
        "pid": PID,
        "backend": "rust-m2",
        "instance_id": "owned-instance",
        "listeners": 1,
        "admin_port": None,
        **changes,
    }


def receipt(launch, *, admin_port=None, token_file=None):
    process = rust_proxy.RustProcess(PID, TOKEN, str(launch.ready), admin_port, str(token_file) if token_file else None)
    rust_proxy.state_file().parent.mkdir(parents=True, exist_ok=True)
    rust_proxy.state_file().write_text(json.dumps(asdict(process)))
    (rust_proxy.get_data_dir() / "proxy.pid").write_text(f"{PID}\n")
    return process


def test_selected_rust_launch_skips_python_setup_and_publishes_owned_receipt(launch, monkeypatch):
    for name in (
        "_ensure_certs",
        "_ensure_tokens",
        "_find_addons_dir",
        "_find_pdp_dir",
        "_merge_system_cas_into_certifi",
    ):
        monkeypatch.setattr(
            proxy, name, create_autospec(getattr(proxy, name), spec_set=True, side_effect=AssertionError("Python setup must not run"))
        )
    launch.ready.write_text(json.dumps(marker(instance_id="stale")))

    def launched(*_args, **_kwargs):
        assert not launch.ready.exists(), "old readiness is removed before launch"
        assert rust_proxy.read_process().pid is None, "unknown ownership is recorded before launch"
        launch.ready.write_text(json.dumps(marker()))
        return PID

    launch.begin.side_effect = launched
    proxy.start_proxy()
    launch.python_start.assert_not_called()
    launch.version.assert_called_once_with(
        [str(launch.binary), "--version"], capture_output=True, text=True, timeout=5, check=False
    )
    args, kwargs = launch.begin.call_args
    assert args == ([str(launch.binary), "--config", str(launch.path)],)
    assert kwargs["exec_command"] is True
    assert kwargs["cwd"] == Path.cwd()
    assert kwargs["env"]["SAFEYOLO_DATA_DIR"] == str(rust_proxy.get_data_dir().absolute())
    assert kwargs["env"]["SAFEYOLO_LOG_PATH"] == str(launch.root / "logs" / "safeyolo.jsonl")
    launch.pane.assert_called_once_with()
    assert rust_proxy.read_process().pid == PID
    assert (rust_proxy.get_data_dir() / "proxy.pid").read_text() == f"{PID}\n"
    launch.http.assert_not_called()


def test_default_native_config_is_generated_for_the_selected_instance(tmp_path, monkeypatch):
    config_dir = tmp_path / "config"
    logs_dir = tmp_path / "logs"
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(logs_dir))
    binary = tmp_path / "safeyolo-proxy"
    binary.write_text("native")
    binary.chmod(0o700)
    monkeypatch.setattr(rust_proxy, "_binary", lambda: binary)

    launch = rust_proxy.prepare(
        {"proxy": {"backend": "rust", "rust_config": safeyolo_config.DEFAULT_NATIVE_CONFIG}}
    )

    native_path = safeyolo_config.get_native_config_path()
    native = json.loads(native_path.read_text())
    assert launch.config == native_path
    assert native["policy_file"] == str(config_dir / "policy.toml")
    assert native["data_dir"] == str(config_dir / "data")
    assert native["admin_api_token_file"] == str(config_dir / "data" / "admin_token")
    assert native["event_log"] == str(logs_dir / "native-events.jsonl")
    assert native_path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "failure", ["missing_config", "bad_json", "nonobject", "missing_binary", "version", "version_io"]
)
def test_selected_rust_startup_errors_never_fall_back_to_python(launch, failure):
    if failure == "missing_config":
        launch.path.unlink()
    elif failure == "bad_json":
        launch.path.write_text("{")
    elif failure == "nonobject":
        launch.path.write_text("[]")
    elif failure == "missing_binary":
        launch.binary.unlink()
    elif failure == "version":
        launch.version.return_value = subprocess.CompletedProcess([], 0, stdout="other program\n", stderr="")
    else:
        launch.version.side_effect = OSError("owned version failure")
    with pytest.raises((RuntimeError, ValueError)):
        proxy.start_proxy()
    launch.python_start.assert_not_called()
    launch.begin.assert_not_called()
    assert not rust_proxy.state_file().exists()


def test_explicit_python_backend_preserves_python_dispatch(launch):
    launch.config["proxy"]["backend"] = "python"
    proxy.start_proxy(proxy_port=18080, admin_port=19090, flow_cache=25, flow_cache_bytes=2048, dev=True)
    launch.python_start.assert_called_once_with(18080, 19090, 25, 2048, True)
    launch.begin.assert_not_called()
    launch.version.assert_not_called()


def test_missing_backend_uses_native_dispatch_without_python_fallback(launch, monkeypatch):
    launch.config["proxy"].pop("backend")
    native_start = create_autospec(rust_proxy.start, spec_set=True)
    monkeypatch.setattr(proxy.rust_proxy, "start", native_start)

    proxy.start_proxy()

    native_start.assert_called_once_with(launch.config)
    launch.python_start.assert_not_called()


def test_binary_prefers_the_packaged_native_artifact(monkeypatch, tmp_path):
    package = tmp_path / "safeyolo"
    package.mkdir()
    (package / "bin").mkdir()
    binary = package / "bin" / "safeyolo-proxy"
    binary.write_text("packaged native proxy")
    binary.chmod(0o700)
    monkeypatch.delenv("SAFEYOLO_RUST_PROXY", raising=False)
    monkeypatch.setattr(rust_proxy, "__file__", str(package / "rust_proxy.py"))
    version = create_autospec(
        subprocess.run,
        spec_set=True,
        return_value=subprocess.CompletedProcess([], 0, stdout="safeyolo-proxy 0.1.0\n", stderr=""),
    )
    monkeypatch.setattr(rust_proxy.subprocess, "run", version)

    assert rust_proxy._binary() == binary
    version.assert_called_once_with(
        [str(binary), "--version"], capture_output=True, text=True, timeout=5, check=False
    )


@pytest.mark.parametrize(
    "bad",
    [
        "{",
        "[]",
        json.dumps(marker(pid=PID + 1)),
        json.dumps(marker(pid=True)),
        json.dumps(marker(ready=False)),
        json.dumps(marker(backend="python")),
        json.dumps(marker(instance_id="")),
        json.dumps(marker(listeners=2)),
        json.dumps({"ready": True, "pid": PID}),
    ],
)
def test_readiness_rejects_partial_wrong_or_stale_process_markers(launch, bad):
    process = receipt(launch)
    launch.ready.write_text(bad)
    assert rust_proxy.readiness(process, listeners=1) is None
    assert rust_proxy.read_process() == process
    launch.http.assert_not_called()


def test_start_waits_past_wrong_pid_before_accepting_its_complete_marker(launch):
    def started(*_args, **_kwargs):
        launch.ready.write_text(json.dumps(marker(pid=PID + 1)))
        return PID

    launch.begin.side_effect = started

    def publish_after_wait(_delay):
        assert rust_proxy.read_process().pid == PID
        assert not (rust_proxy.get_data_dir() / "proxy.pid").exists()
        launch.ready.write_text(json.dumps(marker()))

    launch.clock.sleep.side_effect = publish_after_wait
    rust_proxy.start(launch.config)
    launch.clock.sleep.assert_called_once_with(0.05)
    launch.capture.assert_not_called()
    assert rust_proxy.read_process().pid == PID


def test_before_ready_exit_captures_console_before_cleaning_lifetime_state(launch):
    launch.alive.return_value = False
    bridge = rust_proxy.get_bridge_sockets_dir()
    bridge.mkdir(parents=True)
    other_path = bridge / "other-instance.sock"

    def capture():
        assert rust_proxy.state_file().exists()
        return "owned exit evidence"

    launch.capture.side_effect = capture
    with socket.socket(socket.AF_UNIX) as other:
        other.bind(str(other_path))
        other.listen()
        inode = other_path.stat().st_ino
        with pytest.raises(RuntimeError, match="exited before readiness") as error:
            rust_proxy.start(launch.config)
        assert other_path.stat().st_ino == inode
        with socket.socket(socket.AF_UNIX) as client:
            client.connect(str(other_path))
    assert "owned exit evidence" in str(error.value)
    launch.capture.assert_called_once_with()
    launch.kill.assert_not_called()
    assert not rust_proxy.state_file().exists()
    launch.python_start.assert_not_called()


def test_startup_timeout_captures_evidence_then_requests_graceful_cleanup(launch):
    elapsed = [0.0]
    launch.clock.monotonic.side_effect = lambda: elapsed[0]
    launch.clock.sleep.side_effect = lambda delay: elapsed.__setitem__(0, elapsed[0] + delay)
    launch.kill.side_effect = lambda _pid, _signal: setattr(launch.alive, "return_value", False)
    with pytest.raises(RuntimeError, match="did not signal ready") as error:
        rust_proxy.start(launch.config)
    assert "owned console evidence" in str(error.value)
    assert elapsed[0] >= rust_proxy.STARTUP_TIMEOUT
    launch.kill.assert_called_once_with(PID, signal.SIGTERM)
    assert not rust_proxy.state_file().exists()
    launch.python_start.assert_not_called()


def test_lifetime_state_survives_removed_readiness_and_configured_backend_change(launch):
    process = receipt(launch)
    launch.ready.write_text(json.dumps(marker()))
    launch.ready.unlink()
    launch.config["proxy"]["backend"] = "python"
    assert proxy.is_proxy_running()
    assert rust_proxy.readiness(process) is None
    with pytest.raises(RuntimeError, match="rust proxy is still running"):
        proxy.start_proxy()
    assert rust_proxy.read_process() == process
    launch.python_start.assert_not_called()


def test_graceful_stop_waits_beyond_both_old_deadlines_without_sigkill(launch):
    receipt(launch)
    observations = iter([True] * 122 + [False])
    launch.alive.side_effect = lambda _pid: next(observations)
    proxy.stop_proxy()
    assert launch.clock.sleep.call_count == 121
    assert sum(call.args[0] for call in launch.clock.sleep.call_args_list) > 10.0
    launch.kill.assert_called_once_with(PID, signal.SIGTERM)
    launch.python_stop.assert_not_called()
    launch.end.assert_not_called()
    assert not rust_proxy.state_file().exists()
    assert not (rust_proxy.get_data_dir() / "proxy.pid").exists()


def test_macos_post_signal_unobservable_exit_preserves_other_live_socket(launch):
    """An exited native process cannot authorize removal of another UDS."""
    receipt(launch)
    launch.ready.write_text(json.dumps(marker()))
    launch.token.side_effect = [TOKEN, None]
    bridge = rust_proxy.get_bridge_sockets_dir()
    bridge.mkdir(parents=True)
    other_path = bridge / "other-instance.sock"
    with socket.socket(socket.AF_UNIX) as other:
        other.bind(str(other_path))
        other.listen()
        inode = other_path.stat().st_ino

        proxy.stop_proxy()

        assert other_path.stat().st_ino == inode
        with socket.socket(socket.AF_UNIX) as client:
            client.connect(str(other_path))

    launch.kill.assert_called_once_with(PID, signal.SIGTERM)
    assert not launch.ready.exists()
    assert not rust_proxy.state_file().exists()
    assert not (rust_proxy.get_data_dir() / "proxy.pid").exists()


def test_interrupted_stop_keeps_receipt_and_does_not_kill_tmux(launch):
    process = receipt(launch)
    launch.clock.sleep.side_effect = KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        proxy.stop_proxy()
    assert rust_proxy.read_process() == process
    assert (rust_proxy.get_data_dir() / "proxy.pid").exists()
    launch.kill.assert_called_once_with(PID, signal.SIGTERM)
    launch.end.assert_not_called()
    launch.python_stop.assert_not_called()


def test_missing_identity_token_is_unknown_and_does_not_clear_or_signal(launch):
    process = receipt(launch)
    launch.token.return_value = None
    with pytest.raises(RuntimeError, match="Cannot verify Rust proxy process identity"):
        proxy.is_proxy_running()
    with pytest.raises(RuntimeError, match="Cannot verify Rust proxy process identity"):
        proxy.stop_proxy()
    assert rust_proxy.read_process() == process
    launch.kill.assert_not_called()
    launch.end.assert_not_called()
    launch.python_stop.assert_not_called()


@pytest.mark.parametrize("missing", ["pid", "token"])
def test_start_without_observable_identity_keeps_receipt_and_does_not_claim_ready(launch, missing):
    if missing == "pid":
        launch.begin.return_value = None
    else:
        launch.token.return_value = None
    with pytest.raises(RuntimeError, match="Cannot identify the launched Rust proxy") as error:
        rust_proxy.start(launch.config)
    assert "owned console evidence" in str(error.value)
    process = rust_proxy.read_process()
    assert process is not None
    assert process.pid == (None if missing == "pid" else PID)
    assert process.start_token is None
    assert not (rust_proxy.get_data_dir() / "proxy.pid").exists()
    with pytest.raises(RuntimeError, match="Cannot (identify|verify)"):
        proxy.is_proxy_running()
    launch.kill.assert_not_called()
    launch.end.assert_not_called()


@pytest.mark.parametrize("error", [RuntimeError("owned observation failure"), KeyboardInterrupt()])
def test_interrupted_or_uncertain_launch_keeps_pending_lifetime_receipt(launch, error):
    launch.begin.side_effect = error
    with pytest.raises(type(error)):
        rust_proxy.start(launch.config)
    process = rust_proxy.read_process()
    assert process is not None and process.pid is None and process.start_token is None
    launch.kill.assert_not_called()
    launch.end.assert_not_called()
    launch.python_start.assert_not_called()


@pytest.mark.parametrize("error", [OSError("owned creation failure"), subprocess.CalledProcessError(1, "owned-tmux")])
def test_known_session_creation_failure_clears_pending_receipt(launch, error):
    launch.begin.side_effect = error
    with pytest.raises(type(error)):
        rust_proxy.start(launch.config)
    assert not rust_proxy.state_file().exists()
    launch.kill.assert_not_called()
    launch.python_start.assert_not_called()


@pytest.mark.parametrize("pane_pid", [PID, PID + 1])
def test_reused_pid_or_replacement_pane_is_not_signalled_or_killed(launch, pane_pid):
    receipt(launch)
    launch.token.return_value = "another-process-generation"
    launch.pane.return_value = pane_pid
    proxy.stop_proxy()
    launch.kill.assert_not_called()
    launch.end.assert_not_called()
    launch.python_stop.assert_not_called()
    launch.pane.assert_not_called()


def test_health_uses_actual_receipt_port_and_owned_token_file(launch):
    token_file = launch.root / "owned-test-token"
    token_file.write_text("synthetic-test-value\n")
    receipt(launch, admin_port=19321, token_file=token_file)
    launch.ready.write_text(json.dumps(marker(admin_port=19321)))

    class HealthResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    response = create_autospec(HealthResponse, instance=True, spec_set=True)
    response.__enter__.return_value = response
    response.status = 200
    launch.http.side_effect = None
    launch.http.return_value = response
    assert proxy.wait_for_healthy(admin_port=9090)
    launch.http.assert_called_once()
    request = launch.http.call_args.args[0]
    assert request.full_url == "http://127.0.0.1:19321/health"
    assert request.get_header("Authorization") == "Bearer synthetic-test-value"
    assert launch.http.call_args.kwargs == {"timeout": 2}


def test_start_records_the_actual_ephemeral_admin_port(launch):
    launch.native["admin_port"] = 0
    launch.path.write_text(json.dumps(launch.native))

    def started(*_args, **_kwargs):
        launch.ready.write_text(json.dumps(marker(admin_port=19321)))
        return PID

    launch.begin.side_effect = started
    rust_proxy.start(launch.config)
    assert rust_proxy.read_process().admin_port == 19321
    launch.http.assert_not_called()


def test_native_relative_paths_use_launcher_cwd_and_keep_literal_tilde(launch, monkeypatch):
    monkeypatch.setattr(rust_proxy.os, "getcwd", create_autospec(rust_proxy.os.getcwd, spec_set=True, return_value=str(launch.root)))
    launch.native.update(
        policy_file="policy.toml", readiness_file="~/ready.json", admin_api_token_file="tokens/owned", admin_port=0
    )
    launch.path.write_text(json.dumps(launch.native))
    prepared = rust_proxy.prepare(launch.config)
    assert prepared.config == launch.path
    assert prepared.readiness == launch.root / "~" / "ready.json"
    assert prepared.admin_token == launch.root / "tokens" / "owned"


def test_no_admin_health_uses_owned_readiness_without_http(launch):
    receipt(launch)
    assert not proxy.wait_for_healthy()
    launch.ready.write_text(json.dumps(marker()))
    assert proxy.wait_for_healthy()
    launch.http.assert_not_called()


@pytest.mark.parametrize("operation", ["start", "stop", "running", "health"])
def test_invalid_lifetime_receipt_never_falls_back_to_python(launch, operation):
    rust_proxy.state_file().parent.mkdir(parents=True, exist_ok=True)
    rust_proxy.state_file().write_text("{")
    with pytest.raises(RuntimeError, match="Invalid Rust proxy process record"):
        {
            "start": proxy.start_proxy,
            "stop": proxy.stop_proxy,
            "running": proxy.is_proxy_running,
            "health": proxy.wait_for_healthy,
        }[operation]()
    assert rust_proxy.state_file().read_text() == "{"
    launch.python_start.assert_not_called()
    launch.python_stop.assert_not_called()
    launch.begin.assert_not_called()
    launch.kill.assert_not_called()
    launch.http.assert_not_called()


@pytest.mark.parametrize(("state", "expected"), [("Z", False), ("S", True), ("R", True)])
def test_process_liveness_reads_mocked_linux_state_after_final_command_parenthesis(
    launch, monkeypatch, state, expected
):
    monkeypatch.setattr(runtime_identity.sys, "platform", "linux")
    read = create_autospec(Path.read_text, spec_set=True, return_value=f"{PID} (owned (worker)) {state} 1 2 3\n")
    monkeypatch.setattr(Path, "read_text", read)
    assert runtime_identity.process_is_alive(PID) is expected
    launch.kill.assert_called_once_with(PID, 0)
    read.assert_called_once_with(Path(f"/proc/{PID}/stat"))


def test_process_liveness_does_not_turn_permission_failure_into_exit(launch):
    launch.kill.side_effect = PermissionError("owned fixture denial")
    with pytest.raises(PermissionError, match="owned fixture denial"):
        runtime_identity.process_is_alive(PID)


def test_process_liveness_reports_exited_before_reading_proc(launch, monkeypatch):
    launch.kill.side_effect = ProcessLookupError
    read = create_autospec(Path.read_text, spec_set=True, side_effect=AssertionError("no proc read after exit"))
    monkeypatch.setattr(Path, "read_text", read)
    assert not runtime_identity.process_is_alive(PID)
    read.assert_not_called()


class _PidfdOperations:
    """Concrete PID-handle boundary, independent of the test host OS."""

    def pidfd_open(self, pid: int) -> int:
        raise AssertionError("mock OS boundary required")

    def close(self, descriptor: int) -> None:
        raise AssertionError("mock OS boundary required")

    def kill(self, pid: int, selected_signal: int) -> None:
        raise AssertionError("mock OS boundary required")


class _PidfdSignals:
    SIGTERM = signal.SIGTERM

    def pidfd_send_signal(self, descriptor: int, selected_signal: int) -> None:
        raise AssertionError("mock signal boundary required")


@pytest.mark.parametrize("outcome", ["same", "reused", "unknown", "signal_error"])
def test_termination_pins_descriptor_rechecks_identity_and_always_closes(launch, monkeypatch, outcome):
    process = receipt(launch)
    operations = create_autospec(_PidfdOperations, instance=True, spec_set=True)
    operations.kill = launch.kill
    signals = create_autospec(_PidfdSignals, instance=True, spec_set=True)
    events = []

    def opened(pid):
        events.append(("open", pid))
        return 91

    def observed(pid):
        events.append(("identity", pid))
        return {"same": TOKEN, "reused": "different-generation", "unknown": None, "signal_error": TOKEN}[outcome]

    def sent(descriptor, selected_signal):
        events.append(("signal", descriptor, selected_signal))
        if outcome == "signal_error":
            raise PermissionError("owned signal failure")

    operations.pidfd_open.side_effect = opened
    operations.close.side_effect = lambda descriptor: events.append(("close", descriptor))
    signals.pidfd_send_signal.side_effect = sent
    signals.SIGTERM = signal.SIGTERM
    launch.token.side_effect = observed
    monkeypatch.setattr(rust_proxy, "os", operations)
    monkeypatch.setattr(rust_proxy, "signal", signals)
    if outcome in ("unknown", "signal_error"):
        with pytest.raises(RuntimeError if outcome == "unknown" else PermissionError):
            launch.terminate_original(process)
    else:
        launch.terminate_original(process)
    assert events[:2] == [("open", PID), ("identity", PID)]
    assert events[-1] == ("close", 91)
    operations.close.assert_called_once_with(91)
    operations.kill.assert_not_called()
    if outcome in ("same", "signal_error"):
        signals.pidfd_send_signal.assert_called_once_with(91, signal.SIGTERM)
    else:
        signals.pidfd_send_signal.assert_not_called()


def test_failed_start_cleanup_preserves_original_error_and_ownership(launch, monkeypatch):
    monkeypatch.setattr(
        rust_proxy,
        "_wait_ready",
        create_autospec(rust_proxy._wait_ready, spec_set=True, side_effect=RuntimeError("owned primary startup failure")),
    )
    launch.terminate.side_effect = PermissionError("owned cleanup failure")
    with pytest.raises(RuntimeError, match="owned primary startup failure") as error:
        rust_proxy.start(launch.config)
    assert "owned console evidence" in str(error.value)
    assert any("owned cleanup failure" in note for note in error.value.__notes__)
    assert rust_proxy.read_process().pid == PID
    launch.end.assert_not_called()
    launch.python_start.assert_not_called()


@pytest.mark.parametrize(
    "field",
    ["policy_file", "agent_map_file", "tls_ca_file", "upstream_ca_file", "admin_api_token_file",
     "circuit_state_file", "flow_store_db_path", "audit_log_path", "event_log", "inspection.policy_file"],
)
def test_readiness_collision_preserves_native_input_and_state_files(launch, field):
    launch.ready.write_text("owned input must survive a rejected launch")
    if field == "inspection.policy_file":
        launch.native["inspection"] = {"policy_file": str(launch.ready)}
    else:
        launch.native[field] = str(launch.ready)
    launch.path.write_text(json.dumps(launch.native))
    with pytest.raises(ValueError, match="must not overlap"):
        proxy.start_proxy()
    assert launch.ready.read_text() == "owned input must survive a rejected launch"
    launch.begin.assert_not_called()
    launch.python_start.assert_not_called()


def test_health_rejects_readiness_removed_during_successful_http_response(launch):
    receipt(launch, admin_port=19321)
    launch.ready.write_text(json.dumps(marker(admin_port=19321)))

    class HealthResponse:
        status = 200

        def __enter__(self):
            launch.ready.unlink()
            return self

        def __exit__(self, *_args):
            return False

    launch.http.side_effect = None
    launch.http.return_value = HealthResponse()
    assert not proxy.wait_for_healthy()
    assert proxy.is_proxy_running()


def test_stale_native_receipt_does_not_hide_a_different_live_python_pid(launch):
    receipt(launch)
    launch.token.return_value = "old PID has been reused"
    launch.config["proxy"]["backend"] = "python"
    (rust_proxy.get_data_dir() / "proxy.pid").write_text(f"{PID + 1}\n")
    proxy.start_proxy()
    launch.python_start.assert_not_called()
    launch.begin.assert_not_called()
    assert not rust_proxy.state_file().exists()
    assert (rust_proxy.get_data_dir() / "proxy.pid").read_text() == f"{PID + 1}\n"


def test_failed_atomic_legacy_pid_publication_cannot_leave_a_partial_pid(launch, monkeypatch):
    def started(*_args, **_kwargs):
        launch.ready.write_text(json.dumps(marker()))
        return PID

    launch.begin.side_effect = started
    original_replace = Path.replace

    def interrupted_replace(path, target):
        if Path(target).name == "proxy.pid":
            raise OSError("owned publication failure")
        return original_replace(path, target)

    monkeypatch.setattr(Path, "replace", interrupted_replace)
    launch.kill.side_effect = lambda _pid, _signal: setattr(launch.alive, "return_value", False)
    with pytest.raises(OSError, match="owned publication failure"):
        proxy.start_proxy()
    assert not (rust_proxy.get_data_dir() / "proxy.pid").exists()
    assert not rust_proxy.state_file().exists()
    assert not list(rust_proxy.get_data_dir().glob(".proxy.pid.*.tmp"))
    launch.kill.assert_called_once_with(PID, signal.SIGTERM)


def test_explicit_stop_then_python_selection_uses_only_the_requested_backend(launch):
    def started(*_args, **_kwargs):
        launch.ready.write_text(json.dumps(marker()))
        return PID

    launch.begin.side_effect = started
    proxy.start_proxy()
    launch.config["proxy"]["backend"] = "python"
    with pytest.raises(RuntimeError, match="rust proxy is still running"):
        proxy.start_proxy()
    launch.python_start.assert_not_called()
    launch.kill.side_effect = lambda _pid, _signal: setattr(launch.alive, "return_value", False)
    proxy.stop_proxy()
    proxy.start_proxy()
    launch.python_start.assert_called_once_with(8080, 9090, None, None, False)
    launch.begin.assert_called_once()
    launch.kill.assert_called_once_with(PID, signal.SIGTERM)
    assert not rust_proxy.state_file().exists()


@pytest.mark.parametrize("token", [TOKEN, "different-process"])
def test_posix_signal_fallback_rechecks_identity_without_pidfd(launch, monkeypatch, token):
    process = receipt(launch)
    launch.token.return_value = token
    monkeypatch.setattr(rust_proxy, "os", SimpleNamespace(kill=launch.kill))
    monkeypatch.setattr(rust_proxy, "signal", SimpleNamespace(SIGTERM=signal.SIGTERM))
    launch.terminate_original(process)
    if token == TOKEN:
        launch.kill.assert_called_once_with(PID, signal.SIGTERM)
    else:
        launch.kill.assert_not_called()
