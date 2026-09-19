"""Focused checks for installed-host Rust proxy discovery."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tests" / "blackbox" / "installed_host_smoke.py"


@pytest.fixture
def smoke_module():
    spec = importlib.util.spec_from_file_location("installed_host_smoke", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _executable(path: Path, output: str) -> Path:
    path.write_text(f"#!/bin/sh\nprintf '%s\\n' '{output}'\n")
    path.chmod(0o755)
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


def test_discovery_records_selected_cli_and_native_identity(tmp_path: Path, smoke_module) -> None:
    real_cli = _python_cli(tmp_path / "real-safeyolo", "safeyolo 0.1.0")
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
    assert report["cli"]["interpreter"] == sys.executable
    assert report["cli"]["package_location"].endswith("safeyolo/__init__.py")
    assert report["candidate"]["path"] == str(rust)
    assert report["candidate"]["sha256"]
    assert report["native"]["listeners"][0]["agent_id"] == "alice"
    assert report["runtime"]["status"] == "stopped"


def test_cli_identity_rejects_launcher_without_usable_interpreter(tmp_path: Path, smoke_module) -> None:
    cli = _executable(tmp_path / "safeyolo", "safeyolo 0.1.0")

    with pytest.raises(smoke_module.SmokeError, match="installed safeyolo package"):
        smoke_module._cli_identity(cli)


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
    token = smoke_module._process_start_token(os.getpid())

    assert smoke_module._pid_alive(os.getpid())
    assert token


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


def test_receipt_is_bound_to_supplied_native_paths(tmp_path: Path, smoke_module, monkeypatch) -> None:
    config_dir = tmp_path / "config"
    data_dir = config_dir / "data"
    data_dir.mkdir(parents=True)
    native_path = config_dir / "proxy.json"
    readiness = config_dir / "ready.json"
    working_directory = tmp_path / "work"
    working_directory.mkdir()
    candidate = tmp_path / "safeyolo-proxy"
    candidate.write_text("native")
    marker = {"ready": True, "pid": os.getpid(), "backend": "rust-m2", "instance_id": "x", "listeners": 0}
    readiness.write_text(json.dumps(marker))
    native = {
        "path": str(native_path),
        "readiness_file": str(readiness),
        "listeners": [],
    }
    token = "test-start-token"
    (data_dir / "proxy-rust.json").write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "start_token": token,
                "readiness_file": str(readiness),
                "admin_port": None,
                "admin_token_file": None,
                "config_file": str(native_path),
                "working_directory": str(working_directory),
            }
        )
    )
    monkeypatch.setattr(smoke_module, "_process_start_token", lambda pid: token)
    monkeypatch.setattr(smoke_module, "_process_executable", lambda pid: candidate.resolve())

    observed = smoke_module._runtime_observation(
        config_dir,
        native,
        candidate,
        config_path=native_path,
        working_directory=working_directory,
        require_running=True,
    )
    assert observed["status"] == "ready"

    base_receipt = {
        "pid": os.getpid(),
        "start_token": token,
        "readiness_file": str(readiness),
        "admin_port": None,
        "admin_token_file": None,
        "config_file": str(native_path),
        "working_directory": str(working_directory),
    }
    for field, value, message in (
        ("config_file", str(tmp_path / "other.json"), "config_file does not match"),
        ("readiness_file", str(tmp_path / "other-ready.json"), "readiness_file does not match"),
        ("working_directory", str(tmp_path / "other-work"), "working_directory does not match"),
    ):
        receipt = {**base_receipt, field: value}
        (data_dir / "proxy-rust.json").write_text(json.dumps(receipt))
        with pytest.raises(smoke_module.SmokeError, match=message):
            smoke_module._runtime_observation(
                config_dir,
                native,
                candidate,
                config_path=native_path,
                working_directory=working_directory,
                require_running=True,
            )


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


def test_backend_selection_changes_only_disposable_config_selector(tmp_path: Path, smoke_module) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config = config_dir / "config.yaml"
    original = "proxy:\n  backend: rust\n  rust_config: native.json\nother:\n  keep: true\n"
    config.write_text(original)
    config.chmod(0o640)

    returned = smoke_module._select_backend(config_dir, "python")

    assert returned == original.encode()
    assert config.stat().st_mode & 0o777 == 0o640
    assert smoke_module._read_cli_yaml(config_dir) == {
        "proxy": {"backend": "python", "rust_config": "native.json"},
        "other": {"keep": True},
    }
    assert not list(config_dir.glob("*.rollback.tmp"))


def test_darwin_process_identity_is_observed_or_unavailable(tmp_path: Path, smoke_module, monkeypatch) -> None:
    candidate = tmp_path / "safeyolo-proxy"
    candidate.write_text("native")
    monkeypatch.setattr(smoke_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(smoke_module.sys, "platform", "darwin")

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, str(candidate), "")

    monkeypatch.setattr(smoke_module, "_run", fake_run)
    assert smoke_module._process_executable(42) == candidate.resolve()

    monkeypatch.setattr(smoke_module, "_run", lambda command, **kwargs: subprocess.CompletedProcess(command, 0, "proxy", ""))
    assert smoke_module._process_executable(42) is None


def test_socket_accepting_requires_a_real_socket(tmp_path: Path, smoke_module) -> None:
    regular = tmp_path / "regular"
    regular.write_text("not a socket")
    assert smoke_module._socket_accepting(regular) is False
    assert stat.S_ISREG(regular.stat().st_mode)
