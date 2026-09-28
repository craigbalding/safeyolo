"""Named failures in the native policy writer, observed through Admin and traffic."""

from __future__ import annotations

import concurrent.futures
import json
import os
import socket
import stat
import tempfile
import threading
import tomllib
import uuid
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from safeyolo.agents_store import save_agent
from safeyolo.api import AdminAPI, APIError
from safeyolo.cli import app
from safeyolo.policy import toml_roundtrip
from tests.proxy_migration.harness import ReadinessError, launch_proxy, read_events, request
from tests.proxy_migration.scenarios import origin_server
from tests.proxy_migration.test_native_policy_host_chaos import _converge

POLICY = '''# operator note survives policy mutations
version = "2.0"
description = "staged failure fixture"
budget = 1000
[hosts]
"*" = { egress = "deny" }
"target.invalid" = { egress = "deny" }
"unrelated.invalid" = { egress = "allow" }
'''
TARGET = "target.invalid"
CONTROL = "unrelated.invalid"


class StageControl:
    """Reply to one run's transaction checkpoints by name, never by syscall count."""

    def __init__(self, actions: dict[tuple[str, str], bytes], *, kind="mutation"):
        self.actions = actions
        self.kind = kind
        self.run = uuid.uuid4().hex
        self.reached = threading.Event()
        self.release = threading.Event()
        self.stop = threading.Event()
        self.events: list[dict] = []
        self.errors: list[Exception] = []
        self.transaction: str | None = None

    def __enter__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sy-stage-", dir="/tmp")
        self.path = Path(self.temporary.name) / "checkpoint.sock"
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.path))
        self.listener.listen(1)
        self.listener.settimeout(0.2)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.release.set()
        self.stop.set()
        self.thread.join(timeout=5)
        self.listener.close()
        self.temporary.cleanup()
        assert not self.thread.is_alive(), "checkpoint controller did not stop"
        assert not self.errors, self.errors

    def _serve(self):
        try:
            while not self.stop.is_set():
                try:
                    connection, _ = self.listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    connection.settimeout(10)
                    with connection.makefile("rb") as incoming:
                        for line in incoming:
                            event = json.loads(line)
                            assert event["run"] == self.run, event
                            self.events.append(event)
                            if event["kind"] == self.kind and event["stage"] == "begin":
                                assert self.transaction is None, "more than one selected transaction"
                                self.transaction = event["transaction"]
                            key = (event["phase"], event["stage"])
                            selected = (event["kind"] == self.kind
                                        and event["transaction"] == self.transaction)
                            action = self.actions.get(key, b"c") if selected else b"c"
                            if selected and key in self.actions:
                                self.reached.set()
                                assert self.release.wait(10), f"unreleased checkpoint: {key}"
                            connection.sendall(action)
        except Exception as error:
            self.errors.append(error)

    def environment(self):
        return {
            "SAFEYOLO_TEST_POLICY_STAGE_SOCKET": str(self.path),
            "SAFEYOLO_TEST_POLICY_RUN_ID": self.run,
        }

    def assert_transaction(self, expected_stages):
        assert not self.errors, self.errors
        assert self.reached.is_set()
        assert self.transaction is not None
        selected = [event for event in self.events
                    if event["transaction"] == self.transaction]
        assert {event["kind"] for event in selected} == {self.kind}
        observed = {(event["phase"], event["stage"]) for event in selected}
        assert set(expected_stages) <= observed, observed


def _admin(proxy, token_file):
    marker = json.loads(proxy.readiness_file.read_text())
    return AdminAPI(
        base_url=f"http://127.0.0.1:{marker['admin_port']}",
        token=token_file.read_text().strip(), timeout=15,
    )


def _effect(proxy, origin, host, expected):
    before = origin.accepts
    status, _, body = request(proxy.paths["alice"], f"http://{host}:8123/stage")
    assert status == expected, (host, status, body)
    assert origin.accepts == before + int(expected == 200)


def _snapshot(proxy, origin, target_status):
    _effect(proxy, origin, TARGET, target_status)
    _effect(proxy, origin, CONTROL, 200)


@contextmanager
def _proxy(directory, origin, *, initial=POLICY, admin=True):
    token_file = directory / "operator-token"
    token_file.write_text("staged-failure-operator\n")
    with launch_proxy(
        "rust", directory, initial,
        parent_proxy=f"http://127.0.0.1:{origin.server_address[1]}",
        network_guard_enabled=True, network_guard_block=True,
        admin_port=0 if admin else None,
        admin_api_token_file=token_file if admin else None,
    ) as proxy:
        yield proxy, _admin(proxy, token_file) if admin else None


@pytest.mark.parametrize("phase,stage,action,renamed", [
    ("mutation", "original_read", b"e", False),
    ("commit", "temp_create", b"e", False),
    ("commit", "temp_write", b"e", False),
    ("commit", "temp_write", b"p", False),
    ("commit", "file_sync", b"e", False),
    ("commit", "rename", b"e", False),
    ("commit", "directory_sync", b"e", True),
    ("commit", "activation", b"e", True),
], ids=["read", "create", "write", "partial-write", "file-sync", "rename",
        "directory-sync", "activation"])
def test_native_staged_failure_restores_original_and_never_reports_success(
    tmp_path, phase, stage, action, renamed,
):
    directory = tmp_path / stage / action.decode()
    directory.mkdir(parents=True)
    policy = directory / "policy.toml"
    with StageControl({(phase, stage): action}) as control, \
         patch.dict(os.environ, control.environment()), origin_server() as origin:
        with _proxy(directory, origin) as (proxy, api):
            original = policy.read_bytes()
            _snapshot(proxy, origin, 403)
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                result = pool.submit(api.allow_host, TARGET, rate=100)
                try:
                    assert control.reached.wait(10), control.events
                    assert not result.done(), "Admin replied before the named checkpoint was released"
                    paused = policy.read_bytes()
                    assert (paused != original) == renamed
                    if renamed:
                        assert tomllib.loads(paused.decode())["hosts"][TARGET]["egress"] == "allow"
                finally:
                    control.release.set()
                with pytest.raises(APIError) as raised:
                    result.result(timeout=15)
                assert raised.value.status_code == 500
            expected = {("transaction", "begin"), (phase, stage)}
            if renamed:
                expected.update(("rollback", name) for name in (
                    "temp_create", "temp_write", "file_sync", "rename",
                    "directory_sync", "activation",
                ))
            control.assert_transaction(expected)
            assert policy.read_bytes() == original
            assert not list(directory.glob(".policy-*.toml"))
            marker = proxy.readiness_file.stat()
            _converge(proxy, (marker.st_ino, marker.st_mtime_ns))
            _snapshot(proxy, origin, 403)
            assert not [event for event in read_events(directory / "audit.jsonl")
                        if event["event"] == "admin.host_allowed"]
        with _proxy(directory, origin, initial=None, admin=False) as (fresh, _):
            assert policy.read_bytes() == original
            _snapshot(fresh, origin, 403)


def test_failed_activation_and_failed_rollback_report_remaining_policy(tmp_path):
    directory = tmp_path / "failed-rollback"
    directory.mkdir()
    policy = directory / "policy.toml"
    actions = {("commit", "activation"): b"e", ("rollback", "temp_create"): b"e"}
    with StageControl(actions) as control, patch.dict(os.environ, control.environment()), \
         origin_server() as origin:
        with _proxy(directory, origin) as (proxy, api):
            original = policy.read_bytes()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                result = pool.submit(api.allow_host, TARGET, rate=100)
                assert control.reached.wait(10)
                control.release.set()
                with pytest.raises(APIError) as raised:
                    result.result(timeout=15)
                assert raised.value.status_code == 500
                assert "policy rollback failed; inspect policy state" in str(raised.value)
            control.assert_transaction({("transaction", "begin"), *actions})
            assert policy.read_bytes() != original
            source = tomllib.loads(policy.read_text())
            assert source["hosts"][TARGET]["egress"] == "allow"
            assert source["hosts"][CONTROL]["egress"] == "allow"
            assert "# operator note survives policy mutations" in policy.read_text()
            assert not list(directory.glob(".policy-*.toml"))
            marker = proxy.readiness_file.stat()
            _converge(proxy, (marker.st_ino, marker.st_mtime_ns))
            _snapshot(proxy, origin, 200)
            assert not [event for event in read_events(directory / "audit.jsonl")
                        if event["event"] == "admin.host_allowed"]
        with _proxy(directory, origin, initial=None, admin=False) as (fresh, _):
            _snapshot(fresh, origin, 200)


def test_parse_and_validation_fail_before_native_save(tmp_path):
    directory = tmp_path / "invalid"
    directory.mkdir()
    policy = directory / "policy.toml"
    with origin_server() as origin, _proxy(directory, origin) as (proxy, api):
        original = policy.read_bytes()
        for operation in (
            lambda: api.allow_host(TARGET, rate=0),
            lambda: api.allow_host("invalid:99999", rate=100),
        ):
            with pytest.raises(APIError) as raised:
                operation()
            assert raised.value.status_code == 400
            assert policy.read_bytes() == original
            _snapshot(proxy, origin, 403)
        policy.write_text("[hosts\n")
        malformed = policy.read_bytes()
        with pytest.raises(APIError) as raised:
            api.allow_host(TARGET, rate=100)
        assert raised.value.status_code == 400
        assert policy.read_bytes() == malformed
        _snapshot(proxy, origin, 403)  # last-known-good live state
        assert not list(directory.glob(".policy-*.toml"))
    with pytest.raises(ReadinessError):
        with origin_server() as origin, _proxy(directory, origin, initial=None, admin=False):
            pass  # Fresh startup must reject malformed persisted policy.
    assert policy.read_bytes() == malformed


def test_expiry_persistence_warns_on_save_failure_without_replacing_policy(tmp_path):
    directory = tmp_path / "expiry"
    directory.mkdir()
    policy = directory / "policy.toml"
    expired = POLICY + "\"expired.invalid\" = { egress = 'allow', expires = 2001-01-01T00:00:00Z }\n"
    with StageControl({("commit", "file_sync"): b"e"}, kind="expiry") as control, \
         patch.dict(os.environ, control.environment()), origin_server() as origin:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            def start_and_probe():
                with _proxy(directory, origin, initial=expired, admin=False) as (proxy, _):
                    _effect(proxy, origin, "expired.invalid", 403)
                    _effect(proxy, origin, CONTROL, 200)

            result = pool.submit(start_and_probe)
            try:
                assert control.reached.wait(10), control.events
                assert policy.read_text() == expired
            finally:
                control.release.set()
            result.result(timeout=15)
        control.assert_transaction({("transaction", "begin"), ("commit", "file_sync")})
        assert policy.read_text() == expired
        assert not list(directory.glob(".policy-*.toml"))
        assert "Failed to prune expired hosts from TOML" in (directory / "process.log").read_text()
    with origin_server() as origin, _proxy(directory, origin, initial=None, admin=False) as (fresh, _):
        _effect(fresh, origin, "expired.invalid", 403)
        _effect(fresh, origin, CONTROL, 200)
    assert "expired.invalid" not in policy.read_text()


def test_retained_python_callers_share_save_but_report_distinct_errors(tmp_path):
    directory = tmp_path / "retained-python"
    directory.mkdir()
    policy = directory / "policy.toml"
    original_fsync = os.fsync

    def fail_directory_sync(descriptor):
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("injected Python directory sync failure")
        return original_fsync(descriptor)

    def fail_file_sync(descriptor):
        if stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("injected Python file sync failure")
        return original_fsync(descriptor)

    with origin_server() as origin, _proxy(directory, origin) as (proxy, _), \
         patch.dict(os.environ, {"SAFEYOLO_CONFIG_DIR": str(directory)}):
        original = policy.read_bytes()
        with patch.object(toml_roundtrip.os, "fsync", autospec=True, side_effect=fail_directory_sync):
            result = CliRunner().invoke(
                app, ["policy", "host", "add", TARGET, "--rate", "100"],
                env={"SAFEYOLO_CONFIG_DIR": str(directory)},
            )
        assert result.exit_code == 1, result.output
        assert "directory sync failure" in result.output
        assert policy.read_bytes() != original
        assert tomllib.loads(policy.read_text())["hosts"][TARGET]["egress"] == "allow"
        assert not list(directory.glob("tmp*.toml"))
        marker = proxy.readiness_file.stat()
        _converge(proxy, (marker.st_ino, marker.st_mtime_ns))
        _snapshot(proxy, origin, 200)

        after_cli = policy.read_bytes()
        with patch.object(toml_roundtrip.os, "fsync", autospec=True, side_effect=fail_file_sync):
            with pytest.raises(OSError, match="file sync failure"):
                save_agent("charlie", {"folder": "/fixture/charlie", "egress": "deny"})
        assert policy.read_bytes() == after_cli
        assert "charlie" not in tomllib.loads(policy.read_text()).get("agents", {})
        assert not list(directory.glob("tmp*.toml"))
        _snapshot(proxy, origin, 200)
    with origin_server() as origin, _proxy(directory, origin, initial=None, admin=False) as (fresh, _):
        _snapshot(fresh, origin, 200)


@pytest.mark.skipif("SAFEYOLO_RUST_RELEASE_PROXY" not in os.environ,
                    reason="select an independently built default release proxy")
def test_default_release_build_cannot_activate_stage_control(tmp_path):
    directory = tmp_path / "release"
    directory.mkdir()
    policy = directory / "policy.toml"
    with StageControl({("commit", "temp_write"): b"e"}) as control, \
         patch.dict(os.environ, {
             **control.environment(),
             "SAFEYOLO_RUST_PROXY": os.environ["SAFEYOLO_RUST_RELEASE_PROXY"],
         }), origin_server() as origin:
        with _proxy(directory, origin) as (proxy, api):
            assert api.allow_host(TARGET, rate=100)["status"] == "added"
            marker = proxy.readiness_file.stat()
            _converge(proxy, (marker.st_ino, marker.st_mtime_ns))
            _snapshot(proxy, origin, 200)
            assert tomllib.loads(policy.read_text())["hosts"][TARGET]["egress"] == "allow"
        with _proxy(directory, origin, initial=None, admin=False) as (fresh, _):
            _snapshot(fresh, origin, 200)
        assert control.events == [], "release binary connected to a debug-only checkpoint"
