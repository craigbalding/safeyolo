"""Focused checks for installed-host Rust proxy discovery."""

from __future__ import annotations

import ctypes
import importlib.util
import json
import os
import shutil
import socket
import socketserver
import stat
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tests" / "blackbox" / "installed_host_smoke.py"


@pytest.fixture
def smoke_module(monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    spec = importlib.util.spec_from_file_location("installed_host_smoke", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _executable(path: Path, output: str, *, doctor: dict | None = None, run: bool = False) -> Path:
    # Controlled native identity, never a real runtime witness.
    source = path.with_suffix('.c')
    source.write_text(
        '#include <stdio.h>\n#include <string.h>\n#include <unistd.h>\nint main(int argc,char **argv){'
        + (f'if(argc>1 && !strcmp(argv[argc-1],"doctor")){{puts({json.dumps(json.dumps(doctor))});return 0;}}'
           if doctor is not None else '')
        + ('if(argc>1 && !strcmp(argv[1],"--config")){for(;;)pause();}' if run else '')
        + 'puts(' + json.dumps(output) + ');return 0;}\n'
    )
    subprocess.run(['cc', str(source), '-o', str(path)], check=True, timeout=15)
    source.unlink()
    return path


def _python_cli(path: Path, output: str, interpreter: str | None = None) -> Path:
    selected = interpreter or sys.executable
    path.write_text(f"#!{selected}\nprint({output!r})\n")
    path.chmod(0o755)
    return path


def _native_config(path: Path, socket_path: Path, readiness: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "listeners": [{"agent_id": "alice", "socket_path": str(socket_path)}],
                "policy_file": str(path.parent / "policy.toml"),
                "readiness_file": str(readiness),
                "event_log": str(path.parent / "events.jsonl"),
            }
        )
    )


def test_native_smoke_uses_assigned_coord_ports_and_stops_its_owned_listeners(tmp_path, smoke_module, monkeypatch):
    bundle = os.environ.get("SAFEYOLO_NATIVE_BUNDLE")
    nats = os.environ.get("SAFEYOLO_COORD_NATS_BINARY")
    if not bundle or not nats:
        pytest.skip("requires a verified native bundle and pinned NATS binary")
    from tests.blackbox.installed_sections import prepare_native_instance

    root = tmp_path / "h"
    prepare_native_instance(Path(bundle), root)
    nats_dir = root / "data/coord/nats/bin/2.14.5"
    nats_dir.mkdir(parents=True)
    shutil.copy2(nats, nats_dir / "nats-server")
    (root / ".safeyolo-platform-smoke").touch()
    import tomlkit
    path = root / "config.toml"
    config = tomlkit.parse(path.read_text())
    config.update(admin_port=0, parent_proxy="")
    config["listeners"] = [{"agent_id": "bbpackage", "socket_path": "data/bbpackage.sock"}]
    path.write_text(tomlkit.dumps(config))
    for name, value in {"SAFEYOLO_CONFIG_DIR": str(root), "SAFEYOLO_LOGS_DIR": str(root / "logs"),
                        "SAFEYOLO_COORD_DATA_DIR": str(root / "data/coord"),
                        "SAFEYOLO_NATS_TEST_INSTANCE": "assigned-smoke"}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("SAFEYOLO_NATIVE_CONFIG_PATH", raising=False)
    sockets = [socket.socket() for _ in range(3)]
    try:
        for listener in sockets:
            listener.bind(("127.0.0.1", 0))
        client, monitor, http_port = [listener.getsockname()[1] for listener in sockets]
    finally:
        for listener in sockets:
            listener.close()
    observed = []
    observe_runtime = smoke_module._runtime_observation

    def observe(*args, **kwargs):
        record = json.loads((root / "data/coord/nats/process.json").read_text())
        observed.append((record["client_port"], record["monitor_port"]))
        return observe_runtime(*args, **kwargs)

    monkeypatch.setattr(smoke_module, "_runtime_observation", observe)
    cli = root / "bin/safeyolo"
    binary, identity = smoke_module._installed_rust_binary(cli)
    report, code = smoke_module._native_smoke(SimpleNamespace(
        config_dir=str(root), rust_config=str(path), working_directory=str(tmp_path),
        cli=str(cli), rust_bin=str(binary), install_commit=identity["source_revision"],
        agent="bbpackage", http_port=http_port, nats_client_port=client, nats_monitor_port=monitor,
    ))
    assert code == 0, report
    assert observed == [(client, monitor)]
    assert report["cleanup"]["status"] == "stopped"
    assert not (root / "data/coord/nats/process.json").exists()
    for port in (client, monitor, http_port):
        with socket.socket() as listener:
            # Match the servers' restart behavior while prior HTTP connections
            # can still be in TIME_WAIT. A live listener still prevents this bind.
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))


def test_discovery_records_selected_cli_and_native_identity(tmp_path: Path, smoke_module, monkeypatch) -> None:
    monkeypatch.setattr(smoke_module, "_substrate_identity", lambda _config: {"status": "discovered", "kind": "gvisor"})
    package = tmp_path / "package"
    (package / "bin").mkdir(parents=True)
    revision = 'a' * 40
    (package / "package-info").write_text(f"source_commit={revision}\nprofile=debug\n")
    real_cli = _executable(package / "bin/safeyolo", f"safeyolo 0.1.0 commit={revision} profile=debug")
    cli = tmp_path / "safeyolo"
    cli.symlink_to(real_cli)
    rust = _executable(tmp_path / "safeyolo-proxy", "safeyolo-proxy 0.1.0 (development)")
    config_dir = tmp_path / "config"
    (config_dir / "data").mkdir(parents=True)
    native = config_dir / "proxy.json"
    _native_config(native, config_dir / "alice.sock", config_dir / "ready.json")
    output = tmp_path / "evidence.json"

    result = smoke_module.main(
        [
            "--cli",
            str(cli),
            "--rust-bin",
            str(rust),
            "--rust-config",
            str(native),
            "--config-dir",
            str(config_dir),
            "--output",
            str(output),
        ]
    )

    assert result == 0
    report = json.loads(output.read_text())
    assert report["status"] == "discovered"
    assert report["cli"]["path"] == str(cli)
    assert report["cli"]["package_root"] == str(package)
    assert report["cli"]["source_revision"] == revision
    assert report["candidate"]["path"] == str(rust)
    assert report["candidate"]["sha256"]
    assert report["native"]["listeners"][0]["agent_id"] == "alice"
    assert report["runtime"]["status"] == "stopped"


@pytest.mark.parametrize("entry", ["cli", "proxy"])
def test_native_identity_refuses_a_hidden_python_fallback_before_execution(tmp_path, smoke_module, entry):
    canary = tmp_path / "fallback-ran"
    script = tmp_path / "safeyolo"
    script.write_text(f"#!{sys.executable}\nfrom pathlib import Path\nPath({str(canary)!r}).touch()\n")
    script.chmod(0o755)
    check = smoke_module._cli_identity if entry == "cli" else smoke_module._rust_identity
    with pytest.raises(smoke_module.SmokeError, match="fallback is refused"):
        check(script)
    assert not canary.exists()


def test_installed_binary_comes_from_the_selected_native_layout(tmp_path, smoke_module, monkeypatch):
    package = tmp_path / "package"
    (package / "bin").mkdir(parents=True)
    revision = "a" * 40
    binary = _executable(package / "bin/safeyolo-proxy", f"safeyolo-proxy commit={revision} profile=debug")
    monkeypatch.setattr(smoke_module, "_cli_identity", lambda _cli: {
        "package_root": str(package), "source_revision": revision, "profile": "debug",
    })
    selected, _ = smoke_module._installed_rust_binary(tmp_path / "safeyolo")
    assert selected == binary.resolve()
    _executable(binary, "safeyolo-proxy commit=" + "b" * 40 + " profile=debug")
    with pytest.raises(smoke_module.SmokeError, match="source/profile differs"):
        smoke_module._installed_rust_binary(tmp_path / "safeyolo")
    binary.unlink()
    with pytest.raises(smoke_module.SmokeError, match="Rust proxy executable"):
        smoke_module._installed_rust_binary(tmp_path / "safeyolo")


def test_rust_identity_rejects_a_different_program(tmp_path: Path, smoke_module) -> None:
    binary = _executable(tmp_path / "other", "other-program 1")

    with pytest.raises(smoke_module.SmokeError, match="unexpected identity"):
        smoke_module._rust_identity(binary)


@pytest.mark.parametrize(
    "marker",
    [
        {"ready": False},
        {"ready": True, "pid": 7, "backend": "python", "instance_id": "x", "listeners": 1},
        {"ready": True, "pid": 7, "backend": "rust-m2", "instance_id": "", "listeners": 1},
        {"ready": True, "pid": 7, "backend": "rust-m2", "instance_id": "x", "listeners": -1},
    ],
)
def test_readiness_marker_is_bound_to_process_and_listener_count(marker, smoke_module) -> None:
    with pytest.raises(smoke_module.SmokeError):
        smoke_module._validate_marker(marker, 7, 1)


def test_agent_map_uses_derived_socket_and_rejects_forged_path(tmp_path: Path, smoke_module) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / "agent_map.json").write_text(
        json.dumps(
            {
                "alice": {
                    "ip": "10.0.0.2",
                    "socket": str(data / "sockets" / "10.0.0.2_alice" / "proxy.sock"),
                }
            }
        )
    )
    listeners = smoke_module._agent_map(tmp_path)
    assert listeners == [
        {
            "agent_id": "alice",
            "ip": "10.0.0.2",
            "path": str(data / "sockets" / "10.0.0.2_alice" / "proxy.sock"),
        }
    ]

    (data / "agent_map.json").write_text(
        json.dumps({"alice": {"ip": "10.0.0.2", "socket": "/tmp/other.sock"}})
    )
    with pytest.raises(smoke_module.SmokeError, match="disagrees with derived identity"):
        smoke_module._agent_map(tmp_path)


def test_smoke_requires_an_owned_disposable_marker(tmp_path: Path, smoke_module) -> None:
    with pytest.raises(smoke_module.SmokeError, match="disposable marker missing"):
        smoke_module._require_disposable(tmp_path)

    marker = tmp_path / ".safeyolo-platform-smoke"
    marker.touch()
    assert marker.stat().st_uid == os.getuid()
    smoke_module._require_disposable(tmp_path)


def test_process_identity_is_bound_to_a_live_pid(smoke_module) -> None:
    from safeyolo.runtime_identity import process_start_token

    token = smoke_module._process_start_token(os.getpid())

    assert smoke_module._pid_alive(os.getpid())
    assert token == process_start_token(os.getpid())


def test_json_inspection_has_a_size_bound(tmp_path: Path, smoke_module) -> None:
    path = tmp_path / "large.json"
    path.write_text("{}")
    original_limit = smoke_module.JSON_LIMIT
    smoke_module.JSON_LIMIT = 1
    try:
        with pytest.raises(smoke_module.SmokeError, match="too large"):
            smoke_module._read_json(path, "test JSON")
    finally:
        smoke_module.JSON_LIMIT = original_limit


def test_native_receipt_is_bound_to_the_live_process_and_actual_config(tmp_path, smoke_module, monkeypatch):
    (tmp_path / "data").mkdir()
    config = tmp_path / "config.toml"
    candidate = tmp_path / "safeyolo-proxy"
    candidate.touch()
    ready = tmp_path / "data/ready.json"
    ready.write_text(json.dumps({"ready": True, "pid": os.getpid(), "backend": "rust-m2",
                                 "instance_id": "owned", "listeners": 0}))
    receipt = tmp_path / "data/proxy-process.json"
    receipt.write_text(json.dumps({"pid": os.getpid(), "token": "owned-start"}))
    native = {"readiness_file": str(ready), "listeners": []}
    monkeypatch.setattr(smoke_module, "_process_start_token", lambda pid: "owned-start")
    monkeypatch.setattr(smoke_module, "_process_executable", lambda pid: candidate.resolve())
    monkeypatch.setattr(smoke_module, "_process_command_line", lambda pid: [b"proxy", b"--config", os.fsencode(config)])
    def observe():
        return smoke_module._runtime_observation(tmp_path, native, candidate, config_path=config,
                                                  working_directory=tmp_path, require_running=True)
    assert observe()["status"] == "ready"
    receipt.write_text(json.dumps({"pid": os.getpid(), "token": "reused-pid"}))
    with pytest.raises(smoke_module.SmokeError, match="does not own"):
        observe()
    receipt.write_text(json.dumps({"pid": os.getpid(), "token": "owned-start"}))
    for argv in ([b"proxy", b"--config", b"/other/config.toml"], [b"proxy", b"--config"]):
        monkeypatch.setattr(smoke_module, "_process_command_line", lambda pid: argv)
        with pytest.raises(smoke_module.SmokeError, match="selected native configuration"):
            observe()


@pytest.mark.parametrize("ca_path", ["certs/signing.pem", "/configured/signing.pem", None])
def test_native_toml_inspection_uses_instance_relative_paths_and_runtime_defaults(
    tmp_path, smoke_module, ca_path,
):
    root = tmp_path / "instance"
    root.mkdir()
    config = root / "config.toml"
    config.write_text('readiness_file="data/selected-ready.json"\n' + (
        f'tls_ca_file={json.dumps(ca_path)}\n' if ca_path is not None else ""
    ))
    # Runtime paths belong to config.toml, even when the consumer's cwd differs.
    observed = smoke_module._native_config(config, tmp_path)["raw"]
    assert observed["readiness_file"] == str(root / "data/selected-ready.json")
    assert observed["audit_log_path"] == str(root / "logs/audit.jsonl")
    assert observed["event_log"] == str(root / "logs/events.jsonl")
    if ca_path is None:
        assert "tls_ca_file" not in observed
    else:
        assert observed["tls_ca_file"] == str((root / ca_path).resolve())
    assert config.read_text().count("tls_ca_file") == int(ca_path is not None)


def test_authenticated_runtime_identity_matches_readiness_and_process(tmp_path: Path, smoke_module, monkeypatch) -> None:
    token_file = tmp_path / "admin_token"
    token_file.write_text("synthetic-operator-token\n")
    observed = []

    class Identity(BaseHTTPRequestHandler):
        def do_GET(self):
            observed.append((self.path, self.headers.get("Authorization")))
            body = json.dumps({"schema_version": 1, "state": "active", "instance_id": "owned"}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Identity)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        monkeypatch.setattr(smoke_module, "_process_start_token", lambda _pid: "owned-start")
        native = {"raw": {"admin_api_token_file": str(token_file)}}
        marker = {"admin_port": server.server_address[1], "instance_id": "owned"}
        result = smoke_module._authenticated_runtime_identity(native, marker, os.getpid(), "owned-start")
        assert result == {"status": "authenticated", "instance_id": "owned", "schema_version": 1}
        assert observed == [("/admin/runtime-identity", "Bearer synthetic-operator-token")]
        with pytest.raises(smoke_module.SmokeError, match="disagrees"):
            smoke_module._authenticated_runtime_identity(
                native, {**marker, "instance_id": "different"}, os.getpid(), "owned-start"
            )
        with pytest.raises(smoke_module.SmokeError, match="changed"):
            smoke_module._authenticated_runtime_identity(native, marker, os.getpid(), "stale-start")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def test_smoke_logs_are_created_inside_disposable_state(tmp_path: Path, smoke_module) -> None:
    logs_dir = smoke_module._smoke_logs_dir(tmp_path)
    assert logs_dir == tmp_path / "logs"
    assert logs_dir.is_dir()

    outside = tmp_path / "outside"
    outside.mkdir()
    logs_dir.rmdir()
    logs_dir.symlink_to(outside, target_is_directory=True)
    with pytest.raises(smoke_module.SmokeError, match="must not be a symlink"):
        smoke_module._smoke_logs_dir(tmp_path)


def test_missing_required_substrate_is_not_a_discovery_pass(smoke_module) -> None:
    with pytest.raises(smoke_module.SmokeError, match="required host substrate unavailable"):
        smoke_module._require_substrate({"status": "unavailable", "reason": "runsc missing"})


@pytest.fixture
def attached_instance(tmp_path, smoke_module):
    root = tmp_path / "i"
    (root / "bin").mkdir(parents=True)
    data = root / "data"
    uds = data / "sockets/10.0.0.2_alice/proxy.sock"
    uds.parent.mkdir(parents=True)
    revision = "a" * 40
    (root / "package-info").write_text(f"source_commit={revision}\nprofile=debug\n")
    candidate = _executable(root / "bin/safeyolo-proxy", "safeyolo-proxy 0.1.0", run=True)
    (data / "admin_token").write_text("synthetic-admin-token")
    (data / "agent_token").write_text("synthetic-agent-token")
    (data / "agent_map.json").write_text(json.dumps({"alice": {"ip": "10.0.0.2"}}))
    config = root / "config.toml"
    config.write_text('[[listeners]]\nagent_id="alice"\nsocket_path=' + json.dumps(str(uds)) + '\n')
    requests = []

    class Health(BaseHTTPRequestHandler):
        def do_GET(self):
            admin = self.path == "/admin/runtime-identity"
            token = "synthetic-admin-token" if admin else "synthetic-agent-token"
            authenticated = self.headers.get("Authorization") == f"Bearer {token}"
            requests.append((self.path, authenticated))
            body = json.dumps({"schema_version": 1, "state": "active", "instance_id": "owned"}
                              if admin else {"agent_api": "ok"}).encode()
            self.send_response(200 if authenticated else 401)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-SafeYolo-Agent-API", "true")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            pass

    admin = ThreadingHTTPServer(("127.0.0.1", 0), Health)
    health = socketserver.ThreadingUnixStreamServer(str(uds), Health)
    servers = [admin, health]
    threads = [threading.Thread(target=server.serve_forever) for server in servers]
    with subprocess.Popen([str(candidate), "--config", str(config)]) as child:
        receipt = {"pid": child.pid, "token": smoke_module._process_start_token(child.pid)}
        (data / "proxy-process.json").write_text(json.dumps(receipt))
        (data / "ready.json").write_text(json.dumps({
            "ready": True, "pid": child.pid, "backend": "rust-m2", "instance_id": "owned",
            "listeners": 1, "admin_port": admin.server_address[1],
        }))
        for thread in threads:
            thread.start()
        try:
            yield SimpleNamespace(root=root, data=data, candidate=candidate, config=config,
                                  revision=revision, requests=requests, receipt=receipt)
        finally:
            child.terminate()
            child.wait(timeout=5)
            for server, thread in zip(servers, threads, strict=True):
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
                assert not thread.is_alive()


@pytest.mark.parametrize("diagnosis", [
    {"state": "ready"},
    {"state": "unavailable", "error": "mapped root UID 100000 cannot read and write /dev/kvm"},
    {"state": "unavailable", "error": "host UID 1000 cannot read and write /dev/kvm"},
    {"state": "unavailable", "error": "required runtime companion is missing"},
    {"state": "unavailable", "error": "KVM device /dev/kvm is missing"},
])
def test_attached_checks_current_runtime_and_retains_future_launch_diagnosis(attached_instance, diagnosis):
    instance = attached_instance
    cli = _executable(instance.root / "bin/safeyolo",
                      f"safeyolo 0.1.0 commit={instance.revision} profile=debug", doctor={"linux": diagnosis})
    output = instance.root / "report.json"
    arguments = [sys.executable, str(SCRIPT), "--cli", str(cli), "--rust-bin", str(instance.candidate),
                 "--rust-config", str(instance.config), "--config-dir", str(instance.root),
                 "--output", str(output)]
    # The observer and controlled doctor both cross the real subprocess boundary.
    attached = subprocess.run([*arguments, "--mode", "attached"], capture_output=True, text=True, timeout=15)
    report = json.loads(output.read_text())
    assert attached.returncode == 0, report
    assert report["status"] == "attached_ready"
    assert report["runtime"]["authenticated_runtime_identity"]["status"] == "authenticated"
    assert report["runtime"]["listeners"][0]["accepting"] is True
    assert report["guest_ingress"]["health"]["agent_api"] == "ok"
    ready = diagnosis["state"] == "ready"
    assert report["substrate"]["status"] == ("discovered" if ready else "unavailable")
    if not ready:
        assert report["substrate"]["reason"] == diagnosis["error"]
    assert instance.requests == [("/admin/runtime-identity", True), ("/health", True)]

    discovery = subprocess.run(arguments, capture_output=True, text=True, timeout=15)
    assert discovery.returncode == (0 if ready else 2)
    if not ready:
        assert "required host substrate unavailable" in json.loads(output.read_text())["error"]


@pytest.mark.parametrize("defect,expected", [
    ("stale-receipt", "does not own"),
    ("wrong-executable", "expected selected Rust binary"),
    ("admin-token", "HTTP 401"),
    ("agent-token", "HTTP 401"),
    ("missing-listener", "listener is unavailable"),
])
def test_attached_refuses_invalid_current_runtime_despite_future_launch_failure(attached_instance, defect, expected):
    instance = attached_instance
    cli = _executable(instance.root / "bin/safeyolo",
                      f"safeyolo 0.1.0 commit={instance.revision} profile=debug",
                      doctor={"linux": {"state": "unavailable", "error": "mapped root access denied"}})
    candidate = instance.candidate
    if defect == "stale-receipt":
        (instance.data / "proxy-process.json").write_text(json.dumps({**instance.receipt, "token": "stale"}))
    elif defect == "wrong-executable":
        candidate = _executable(instance.root / "bin/other-proxy", "safeyolo-proxy 0.1.0")
    elif defect in {"admin-token", "agent-token"}:
        (instance.data / ("admin_token" if defect == "admin-token" else "agent_token")).write_text("wrong-token")
    else:
        (instance.data / "sockets/10.0.0.2_alice/proxy.sock").unlink()
    output = instance.root / "report.json"
    result = subprocess.run([
        sys.executable, str(SCRIPT), "--mode", "attached", "--cli", str(cli), "--rust-bin", str(candidate),
        "--rust-config", str(instance.config), "--config-dir", str(instance.root), "--output", str(output),
    ], capture_output=True, text=True, timeout=15)
    report = json.loads(output.read_text())
    assert result.returncode == 2, report
    assert expected in report["error"]
    assert report["substrate"]["status"] == "unavailable"


@pytest.mark.parametrize("ready", [True, False])
def test_substrate_uses_installed_runtime_diagnosis_without_path_fallback(tmp_path, smoke_module, monkeypatch, ready):
    cli = tmp_path / "bin/safeyolo"
    cli.parent.mkdir()
    cli.touch()
    selected = {"state": "ready" if ready else "unavailable", "path": "/owned/libexec/runsc",
                "version": "release-20261005.0", "origin": "bundled", "error": "missing companion"}
    monkeypatch.setattr(smoke_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(smoke_module, "_run", lambda argv, **kwargs: subprocess.CompletedProcess(
        argv, 0, json.dumps({"linux": selected}), ""))
    monkeypatch.setattr(smoke_module.shutil, "which", lambda name: pytest.fail("ambient runtime lookup"))
    observed = smoke_module._substrate_identity(tmp_path)
    assert observed["status"] == ("discovered" if ready else "unavailable")
    assert observed["path"] == selected["path"] and observed["origin"] == "bundled"
    if not ready:
        assert observed["reason"] == "missing companion"


def test_darwin_process_identity_is_observed_or_unavailable(tmp_path: Path, smoke_module, monkeypatch) -> None:
    candidate = tmp_path / "safeyolo-proxy"
    candidate.write_text("native")
    monkeypatch.setattr(smoke_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(smoke_module.sys, "platform", "darwin")

    def pid_path(_pid, buffer, size):
        value = os.fsencode(candidate) + b"\0"
        assert len(value) <= size
        ctypes.memmove(buffer, value, len(value))
        return len(value)

    library = type("Library", (), {"proc_pidpath": staticmethod(pid_path)})()
    monkeypatch.setattr(smoke_module.ctypes, "CDLL", lambda *_args, **_kwargs: library)
    monkeypatch.setattr(smoke_module, "_run", lambda *_args, **_kwargs: pytest.fail("ps should not run"))
    assert smoke_module._process_executable(42) == candidate.resolve()

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, str(candidate), "")

    library.proc_pidpath = lambda *_args: 0
    monkeypatch.setattr(smoke_module, "_run", fake_run)
    assert smoke_module._process_executable(42) == candidate.resolve()

    monkeypatch.setattr(smoke_module, "_run", lambda command, **kwargs: subprocess.CompletedProcess(command, 0, "proxy", ""))
    assert smoke_module._process_executable(42) is None


def test_socket_accepting_requires_a_real_socket(tmp_path: Path, smoke_module) -> None:
    regular = tmp_path / "regular"
    regular.write_text("not a socket")
    assert smoke_module._socket_accepting(regular) is False
    assert stat.S_ISREG(regular.stat().st_mode)
