"""Listener synchronization with owned JSON files and mocked process boundaries."""

import json
import os
import signal
import stat
import subprocess
import tempfile
import time
import urllib.request
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import create_autospec
from uuid import UUID

import httpx
import pytest

from safeyolo import proxy, rust_proxy, sockets
from safeyolo.config import get_agent_map_path, get_bridge_sockets_dir

PID = 23456
TOKEN = "owned-listener-generation"
OLD_RELOAD = "00000000-0000-4000-8000-000000000001"


def marker(environment, reload_id=OLD_RELOAD, **changes):
    return {
        "ready": True,
        "pid": PID,
        "backend": "rust-m2",
        "instance_id": "owned-listener-instance",
        "listeners": len(environment.read_native()["listeners"]),
        "admin_port": None,
        "reload_id": reload_id,
        **changes,
    }


@pytest.fixture
def environment(monkeypatch):
    # Keep real conventional socket paths within the existing sun_path limit.
    with tempfile.TemporaryDirectory(prefix="sy-sync-") as directory:
        root = Path(directory)
        config_dir = root / "cli"
        config_dir.mkdir()
        working = root / "launch"
        working.mkdir()
        other = root / "elsewhere"
        other.mkdir()
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(root / "logs"))
        monkeypatch.chdir(working)
        path = working / "native.json"
        ready = working / "ready.json"
        native = {
            "listeners": [],
            "policy_file": "policy.toml",
            "readiness_file": "ready.json",
            "audit_log_path": "audit.jsonl",
            "event_log": "diagnostics.jsonl",
            "flow_store_db_path": "flows.sqlite3",
            "flow_store_enabled": False,
            "ignore_hosts": ["owned.invalid:443"],
            "reload_id": OLD_RELOAD,
        }
        path.write_text(json.dumps(native), encoding="utf-8")
        (config_dir / "config.yaml").write_text(
            "proxy:\n  backend: python\n  rust_config: nowhere.json\n", encoding="utf-8"
        )
        process = rust_proxy.RustProcess(
            PID,
            TOKEN,
            str(ready),
            None,
            None,
            config_file=str(path),
            working_directory=str(working),
        )
        rust_proxy.state_file().parent.mkdir(parents=True)
        rust_proxy.state_file().write_text(json.dumps(asdict(process)), encoding="utf-8")
        (rust_proxy.get_data_dir() / "proxy.pid").write_text(f"{PID}\n", encoding="utf-8")
        map_path = get_agent_map_path()
        map_path.write_text("{}", encoding="utf-8")
        alive = create_autospec(rust_proxy.process_is_alive, spec_set=True, return_value=True)
        token = create_autospec(rust_proxy.process_start_token, spec_set=True, return_value=TOKEN)
        monkeypatch.setattr(rust_proxy, "process_is_alive", alive)
        monkeypatch.setattr(rust_proxy, "process_start_token", token)
        signal_process = create_autospec(rust_proxy._signal_process, spec_set=True)
        monkeypatch.setattr(rust_proxy, "_signal_process", signal_process)
        kill = create_autospec(os.kill, spec_set=True, side_effect=AssertionError("unmocked signal"))
        monkeypatch.setattr(os, "kill", kill)
        run = create_autospec(subprocess.run, spec_set=True, side_effect=AssertionError("unmocked child process"))
        monkeypatch.setattr(subprocess, "run", run)
        put = create_autospec(httpx.put, spec_set=True, side_effect=AssertionError("Python HTTP must not run"))
        monkeypatch.setattr(httpx, "put", put)
        urlopen = create_autospec(
            urllib.request.urlopen, spec_set=True, side_effect=AssertionError("HTTP must not run")
        )
        monkeypatch.setattr(urllib.request, "urlopen", urlopen)
        clock = create_autospec(time, spec_set=True)
        elapsed = [0.0]
        clock.monotonic.side_effect = lambda: elapsed[0]

        def advance(delay):
            elapsed[0] += delay

        clock.sleep.side_effect = advance
        monkeypatch.setattr(rust_proxy, "time", clock)
        result = SimpleNamespace(
            root=root,
            config_dir=config_dir,
            working=working,
            other=other,
            path=path,
            ready=ready,
            process=process,
            map_path=map_path,
            alive=alive,
            token=token,
            signal=signal_process,
            kill=kill,
            run=run,
            put=put,
            urlopen=urlopen,
            clock=clock,
            elapsed=elapsed,
            advance=advance,
            read_native=lambda: json.loads(path.read_text(encoding="utf-8")),
        )

        def acknowledge(_process, signum):
            assert signum == signal.SIGHUP
            requested = result.read_native()["reload_id"]
            ready.write_text(json.dumps(marker(result, requested)), encoding="utf-8")

        signal_process.side_effect = acknowledge
        result.acknowledge = acknowledge
        ready.write_text(json.dumps(marker(result)), encoding="utf-8")
        yield result
        kill.assert_not_called()
        put.assert_not_called()
        urlopen.assert_not_called()


def write_native(environment, listeners):
    document = environment.read_native()
    document["listeners"] = listeners
    environment.path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return document


def managed(agent, ip):
    return {"agent_id": agent, "socket_path": str(sockets.path_for(agent, ip)), "source_id": ip}


def test_sync_uses_pinned_config_cwd_and_map_identity_preserving_custom_rows(environment, monkeypatch):
    env = environment
    base = get_bridge_sockets_dir()
    custom = [
        {
            "agent_id": "custom",
            "socket_path": "../elsewhere/192.0.2.20_custom/proxy.sock",
            "source_id": "custom-source",
        },
        {"agent_id": "other-name", "socket_path": str(base / "not-a-conventional-directory" / "proxy.sock")},
        {"agent_id": "other-file", "socket_path": str(base / "192.0.2.30_other-file" / "manual.sock")},
    ]
    # This row is CLI-managed only after interpreting its relative path at launch cwd.
    stale = managed("old", "192.0.2.2")
    stale["socket_path"] = os.path.relpath(stale["socket_path"], env.working)
    before = write_native(env, [custom[0], stale, *custom[1:]])
    env.path.chmod(0o640)
    old_inode = env.path.stat().st_ino
    env.map_path.write_text(
        json.dumps(
            {
                "alice": {"ip": "192.0.2.10", "socket": "/diagnostic/path/must-not-be-trusted.sock"},
                "bob": {"ip": "192.0.2.11"},
            }
        ),
        encoding="utf-8",
    )
    other_config = env.other / "native.json"
    other_config.write_text('{"listeners": []}', encoding="utf-8")
    wrong_bytes = other_config.read_bytes()
    monkeypatch.chdir(env.other)

    assert rust_proxy.sync_listeners(timeout=0.2)

    after = env.read_native()
    assert after["listeners"] == [*custom, managed("alice", "192.0.2.10"), managed("bob", "192.0.2.11")]
    assert {key: value for key, value in after.items() if key not in {"listeners", "reload_id"}} == {
        key: value for key, value in before.items() if key not in {"listeners", "reload_id"}
    }
    assert UUID(after["reload_id"]).version == 4
    assert UUID(after["reload_id"]) != UUID(OLD_RELOAD)
    assert stat.S_IMODE(env.path.stat().st_mode) == 0o640
    assert env.path.stat().st_ino != old_inode
    assert other_config.read_bytes() == wrong_bytes
    assert rust_proxy.read_process() == env.process
    env.signal.assert_called_once_with(env.process, signal.SIGHUP)


@pytest.mark.parametrize("missing", [True, False])
def test_missing_map_preserves_explicit_rows_but_empty_map_removes_managed(environment, missing):
    custom = {"agent_id": "manual", "socket_path": str(environment.root / "manual.sock")}
    rows = [managed("alice", "192.0.2.10"), custom]
    write_native(environment, rows)
    if missing:
        environment.map_path.unlink()
    assert rust_proxy.sync_listeners(timeout=0.2)
    assert environment.read_native()["listeners"] == (rows if missing else [custom])


def test_sync_preserves_native_json_number_and_custom_row_text(environment):
    env = environment
    custom_text = '{"agent_id":"ma\\u006eual","socket_path":"manual.sock"}'
    document = env.path.read_text(encoding="utf-8").replace('"listeners": []', f'"listeners": [{custom_text}]')
    document = document[:-1] + ', "test_context_declared_ttl":1e400}'
    env.path.write_text(document, encoding="utf-8")
    env.map_path.write_text(json.dumps({"alice": {"ip": "192.0.2.10"}}), encoding="utf-8")

    assert rust_proxy.sync_listeners(timeout=0.2)

    after = env.path.read_text(encoding="utf-8")
    assert json.loads(after, parse_float=str)["test_context_declared_ttl"] == "1e400"
    assert custom_text in after
    assert env.read_native()["listeners"] == [
        {"agent_id": "manual", "socket_path": "manual.sock"},
        managed("alice", "192.0.2.10"),
    ]


@pytest.mark.parametrize(
    "invalid",
    ["json", "nonmapping", "entry", "unreadable", "ip_zero", "ip_false", "ip_array", "ip_object", "ip_integer"],
)
def test_invalid_map_does_not_publish_an_empty_listener_set(environment, invalid, caplog):
    write_native(environment, [managed("alice", "192.0.2.10")])
    before = environment.path.read_bytes()
    if invalid == "unreadable":
        environment.map_path.unlink()
        environment.map_path.mkdir()
    else:
        contents = {
            "json": "{",
            "nonmapping": "[]",
            "entry": '{"alice": 42}',
            "ip_zero": '{"alice": {"ip": 0}}',
            "ip_false": '{"alice": {"ip": false}}',
            "ip_array": '{"alice": {"ip": []}}',
            "ip_object": '{"alice": {"ip": {}}}',
            "ip_integer": '{"alice": {"ip": 42}}',
        }[invalid]
        environment.map_path.write_text(contents, encoding="utf-8")
    assert not rust_proxy.sync_listeners(timeout=0.2)
    assert environment.path.read_bytes() == before
    environment.signal.assert_not_called()
    assert any(record.levelname == "WARNING" for record in caplog.records)


def test_missing_null_and_empty_ip_entries_are_skipped_alongside_valid_agent(environment):
    custom = {"agent_id": "manual", "socket_path": "manual.sock"}
    write_native(environment, [managed("old", "192.0.2.2"), custom])
    environment.map_path.write_text(
        json.dumps(
            {
                "missing": {},
                "null": {"ip": None},
                "empty": {"ip": ""},
                "alice": {"ip": "192.0.2.10"},
            }
        ),
        encoding="utf-8",
    )
    assert rust_proxy.sync_listeners(timeout=0.2)
    assert environment.read_native()["listeners"] == [custom, managed("alice", "192.0.2.10")]
    environment.signal.assert_called_once_with(environment.process, signal.SIGHUP)


def test_same_listener_count_with_old_nonce_waits_for_its_own_acknowledgment(environment):
    env = environment
    write_native(env, [managed("old", "192.0.2.2")])
    env.map_path.write_text(json.dumps({"new": {"ip": "192.0.2.3"}}), encoding="utf-8")
    env.ready.write_text(json.dumps(marker(env)), encoding="utf-8")
    env.signal.side_effect = None

    def publish_after_wait(delay):
        env.advance(delay)
        assert env.read_native()["reload_id"] != OLD_RELOAD
        env.acknowledge(env.process, signal.SIGHUP)

    env.clock.sleep.side_effect = publish_after_wait
    assert rust_proxy.sync_listeners(timeout=0.2)
    assert env.clock.sleep.call_count == 1
    env.signal.assert_called_once_with(env.process, signal.SIGHUP)


def test_timeout_keeps_requested_json_and_lifetime_receipt(environment):
    env = environment
    before = env.path.read_bytes()
    env.signal.side_effect = None
    assert not rust_proxy.sync_listeners(timeout=0.11)
    assert env.elapsed[0] >= 0.11
    assert env.path.read_bytes() != before
    assert env.read_native()["reload_id"] != OLD_RELOAD
    assert rust_proxy.read_process() == env.process
    env.signal.assert_called_once_with(env.process, signal.SIGHUP)


def test_fresh_nonce_from_wrong_pid_cannot_acknowledge(environment):
    env = environment

    def wrong_process(_process, _signum):
        env.ready.write_text(json.dumps(marker(env, env.read_native()["reload_id"], pid=PID + 1)), encoding="utf-8")

    env.signal.side_effect = wrong_process
    assert not rust_proxy.sync_listeners(timeout=0.11)
    assert env.elapsed[0] >= 0.11


@pytest.mark.parametrize("failure", ["dead", "reused"])
def test_post_signal_process_loss_cannot_acknowledge_requested_reload(environment, failure):
    env = environment

    def lose_owner(process, signum):
        env.acknowledge(process, signum)
        if failure == "dead":
            env.alive.return_value = False
        else:
            env.token.return_value = "different-owned-generation"

    env.signal.side_effect = lose_owner
    assert not rust_proxy.sync_listeners(timeout=0.2)
    assert env.read_native()["reload_id"] != OLD_RELOAD
    assert rust_proxy.read_process() == env.process


def test_stopped_process_does_not_change_native_config(environment):
    environment.alive.return_value = False
    before = environment.path.read_bytes()
    assert not rust_proxy.sync_listeners(timeout=0.2)
    assert environment.path.read_bytes() == before
    environment.signal.assert_not_called()


def test_older_receipt_is_readable_but_does_not_guess_current_config(environment, monkeypatch, caplog):
    old = asdict(environment.process)
    old.pop("config_file")
    old.pop("working_directory")
    rust_proxy.state_file().write_text(json.dumps(old), encoding="utf-8")
    before = environment.path.read_bytes()
    load = create_autospec(proxy.load_config, spec_set=True, side_effect=AssertionError("must not guess current YAML"))
    monkeypatch.setattr(proxy, "load_config", load)
    assert rust_proxy.read_process().config_file is None
    assert not rust_proxy.sync_listeners(timeout=0.2)
    assert environment.path.read_bytes() == before
    environment.signal.assert_not_called()
    load.assert_not_called()
    assert any(record.levelname == "WARNING" for record in caplog.records)


def test_proxy_mode_sync_routes_actual_rust_receipt_despite_python_selection(environment, monkeypatch):
    load = create_autospec(
        proxy.load_config, spec_set=True, side_effect=AssertionError("edited selection is irrelevant")
    )
    monkeypatch.setattr(proxy, "load_config", load)
    assert proxy.sync_proxy_modes(admin_port=12345, timeout=0.2)
    environment.signal.assert_called_once_with(environment.process, signal.SIGHUP)
    load.assert_not_called()


def test_wrapper_rechecks_receipt_after_acquiring_lifecycle_lock(environment, monkeypatch):
    before = environment.path.read_bytes()

    @contextmanager
    def acquired_after_stop():
        rust_proxy.state_file().unlink()
        yield

    lock = create_autospec(rust_proxy.lifecycle_lock, spec_set=True, return_value=acquired_after_stop())
    monkeypatch.setattr(rust_proxy, "lifecycle_lock", lock)
    assert not proxy.sync_proxy_modes(timeout=0.2)
    lock.assert_called_once_with()
    assert environment.path.read_bytes() == before
    environment.signal.assert_not_called()


def test_corrupt_receipt_never_routes_to_python_http(environment, caplog):
    rust_proxy.state_file().write_text("{", encoding="utf-8")
    before = environment.path.read_bytes()
    assert not proxy.sync_proxy_modes(timeout=0.2)
    assert environment.path.read_bytes() == before
    environment.signal.assert_not_called()
    assert any(record.levelname == "WARNING" for record in caplog.records)


def test_startup_reconciles_map_before_launch_and_pins_config_and_cwd(environment, monkeypatch):
    env = environment
    rust_proxy.state_file().unlink()
    (rust_proxy.get_data_dir() / "proxy.pid").unlink()
    custom = {"agent_id": "manual", "socket_path": "manual.sock"}
    write_native(env, [managed("old", "192.0.2.2"), custom])
    env.map_path.write_text(json.dumps({"alice": {"ip": "192.0.2.10"}}), encoding="utf-8")
    binary = env.root / "owned-binary"
    binary.write_text("never executed", encoding="utf-8")
    binary.chmod(0o700)
    monkeypatch.setenv("SAFEYOLO_RUST_PROXY", str(binary))
    env.run.side_effect = None
    env.run.return_value = subprocess.CompletedProcess([], 0, stdout="safeyolo-proxy 0.1.0\n", stderr="")
    pane = create_autospec(rust_proxy.session_process_id, spec_set=True, return_value=None)
    begin = create_autospec(rust_proxy.start_session, spec_set=True)
    monkeypatch.setattr(rust_proxy, "session_process_id", pane)
    monkeypatch.setattr(rust_proxy, "start_session", begin)

    def started(*_args, **kwargs):
        assert kwargs["cwd"] == env.working
        assert env.read_native()["listeners"] == [custom, managed("alice", "192.0.2.10")]
        env.ready.write_text(json.dumps(marker(env, env.read_native().get("reload_id"))), encoding="utf-8")
        return PID

    begin.side_effect = started
    rust_proxy.start({"proxy": {"backend": "rust", "rust_config": "native.json"}})
    process = rust_proxy.read_process()
    assert process.config_file == str(env.path)
    assert process.working_directory == str(env.working)
    begin.assert_called_once()
    env.signal.assert_not_called()
    env.run.assert_called_once_with([str(binary), "--version"], capture_output=True, text=True, timeout=5, check=False)
