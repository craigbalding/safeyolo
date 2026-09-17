"""Focused checks for installed-host Rust proxy discovery."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
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
    cli = _executable(tmp_path / "safeyolo", "safeyolo 0.1.0")
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
    assert report["candidate"]["path"] == str(rust)
    assert report["candidate"]["sha256"]
    assert report["native"]["listeners"][0]["agent_id"] == "alice"
    assert report["runtime"]["status"] == "stopped"


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


def test_socket_accepting_requires_a_real_socket(tmp_path: Path, smoke_module) -> None:
    regular = tmp_path / "regular"
    regular.write_text("not a socket")
    assert smoke_module._socket_accepting(regular) is False
    assert stat.S_ISREG(regular.stat().st_mode)
