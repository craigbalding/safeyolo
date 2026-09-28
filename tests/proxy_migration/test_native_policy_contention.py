"""Deterministic contention at the retained Python and native policy lock."""

from __future__ import annotations

import concurrent.futures
import fcntl
import json
import multiprocessing
import os
import shutil
import socket
import subprocess
import tempfile
import tomllib
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest

from safeyolo.api import AdminAPI
from tests.proxy_migration.harness import REPO, launch_proxy, request, wait_ready
from tests.proxy_migration.test_gateway_redirect import (
    AGENT_API,
    AGENT_TOKEN,
    VAULT_NAME,
    _fixture_state,
    _origin,
)
from tests.proxy_migration.test_native_policy_host_chaos import _converge
from tests.proxy_migration.test_native_policy_state_chaos import (
    RISKY_CONTRACT_SERVICE,
    _admin,
    _gateway_policy,
)

LIMIT = 10


def _recv_exact(connection, size):
    data = bytearray()
    while len(data) < size:
        part = connection.recv(size - len(data))
        assert part, "policy lock barrier closed before its event"
        data.extend(part)
    return bytes(data)


def _python_write(kind: str, key: str, directory: str, control) -> None:
    """Report the actual flock attempt and post-lock policy read."""
    from safeyolo.policy import toml_roundtrip

    os.environ["SAFEYOLO_CONFIG_DIR"] = directory
    flock = fcntl.flock
    load = toml_roundtrip.load_roundtrip

    def observed_flock(descriptor, operation):
        if operation == fcntl.LOCK_EX:
            control.send(("attempt", key))
        return flock(descriptor, operation)

    def observed_load(path):
        document = load(path)
        control.send(("locked", key))
        if not control.poll(LIMIT) or control.recv() != "release":
            raise TimeoutError("policy lock release barrier timed out")
        return document

    try:
        with patch.object(toml_roundtrip.fcntl, "flock", autospec=True, side_effect=observed_flock), \
             patch.object(toml_roundtrip, "load_roundtrip", autospec=True, side_effect=observed_load):
            control.send(("ready", key))
            if not control.poll(LIMIT) or control.recv() != "start":
                raise TimeoutError("policy writer start barrier timed out")
            if kind == "cli":
                from safeyolo.commands.policy_host import host_add

                host_add(key, port=None, rate=100, service=None, agent=None, expires=None)
            elif kind == "locked":
                from safeyolo.policy.toml_roundtrip import update_host_field

                def mutate(document):
                    update_host_field(document, key, "egress", "allow")
                    update_host_field(document, key, "rate", 100)

                toml_roundtrip.locked_policy_mutate(Path(directory) / "policy.toml", mutate)
            elif kind == "agents":
                from safeyolo.agents_store import save_agent

                save_agent(key, {"folder": f"/fixture/{key}", "egress": "deny"})
            else:
                raise ValueError(kind)
        control.send(("done", key))
    except Exception as error:
        control.send(("error", f"{type(error).__name__}: {error}"))


def _native_write(api: AdminAPI, kind: str, key: str, grant_id: str | None):
    if kind == "host":
        return api.allow_host(key, rate=100)
    if kind == "deny":
        return api.deny_host(key)
    if kind == "service":
        return api.authorize_service(key, "redirect", "reader", VAULT_NAME)
    if kind == "binding":
        return api.approve_contract_binding(
            key, "redirect", "reader", "redirect.reader.v1",
            {"account": "alpha" if key == "alice" else "beta"}, ["list_items"],
        )
    if kind == "revoke":
        assert grant_id is not None
        return api.revoke_gateway_grant(grant_id)
    raise ValueError(kind)


class _Writer:
    def __init__(self, kind, key, *, process=None, control=None,
                 future=None, connection=None):
        self.kind, self.key = kind, key
        self.process, self.control = process, control
        self.future, self.connection = future, connection
        self.released = False

    def locked(self):
        if self.connection:
            assert _recv_exact(self.connection, 6) == b"locked", (self.kind, self.key)
        else:
            assert self.control.poll(LIMIT)
            assert self.control.recv() == ("locked", self.key)

    def waiting(self):
        """An attempted writer cannot pass the read/acquisition boundary."""
        if self.connection:
            self.connection.settimeout(0.2)
            with pytest.raises(socket.timeout):
                self.connection.recv(1)
            self.connection.settimeout(LIMIT)
        else:
            assert not self.control.poll(0.2)

    def finish(self):
        self.release_lock()
        if self.connection:
            result = self.future.result(timeout=LIMIT)
            assert result["status"] in {"added", "denied", "authorized", "bound", "revoked", "ok"}
            self.connection.close()
        else:
            assert self.control.poll(LIMIT)
            assert self.control.recv() == ("done", self.key)
            self.process.join(timeout=LIMIT)
            assert self.process.exitcode == 0
            self.control.close()

    def release_lock(self):
        if self.released:
            return
        self.released = True
        if self.connection:
            self.connection.sendall(b"r")
        else:
            self.control.send("release")


def _start(spec, directory, api, listener, pool, grant_id=None):
    kind, key = spec
    if kind in {"cli", "locked", "agents"}:
        context = multiprocessing.get_context("spawn")
        control, child = context.Pipe()
        process = context.Process(
            target=_python_write,
            args=(kind, key, str(directory), child),
        )
        process.start()
        child.close()
        assert control.poll(LIMIT)
        assert control.recv() == ("ready", key)
        control.send("start")
        assert control.poll(LIMIT)
        assert control.recv() == ("attempt", key)
        return _Writer(kind, key, process=process, control=control)
    future = pool.submit(_native_write, api, kind, key, grant_id)
    connection, _ = listener.accept()
    connection.settimeout(LIMIT)
    assert _recv_exact(connection, 7) == b"attempt", (kind, key)
    return _Writer(kind, key, future=future, connection=connection)


def _policy(port):
    return _gateway_policy(port).replace(
        "[agents.bob]",
        '[hosts."blocked.invalid"]\negress = "deny"\n'
        '[agents.alice]\nfolder = "/fixture/alice"\n[agents.bob]',
    )


def _host_effect(proxy, origin, host, allowed):
    before = origin.accepts
    status, _, body = request(proxy.paths["alice"], f"http://{host}:8123/contention")
    assert status == (200 if allowed else 403), (host, status, body)
    assert origin.accepts == before + int(allowed)


def _gateway_effect(proxy, origin, agent, account, expected_status):
    status, _, body = request(
        proxy.paths[agent], AGENT_API + "/gateway/services",
        headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
    )
    assert status == 200, body
    authorized = json.loads(body)["authorized"]
    assert "redirect" in authorized
    token = authorized["redirect"]["token"]
    before = origin.accepts
    status, _, body = request(
        proxy.paths[agent],
        f"http://127.0.0.1:{origin.server_address[1]}/v1/items?account={account}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert status == expected_status, (agent, account, status, body)
    assert origin.accepts == before + int(expected_status == 200)


@contextmanager
def _second_admin(directory, token_file):
    """A second native process contends at the same policy path and lock."""
    second = directory / "second-native"
    second.mkdir()
    data = second / "data"
    data.mkdir()
    for name in ("vault.key", "vault.yaml.enc", "agent_token"):
        shutil.copy2(directory / "data" / name, data / name)
    config = json.loads((directory / "proxy.json").read_text())
    config.update({
        "listeners": [], "data_dir": str(data),
        "readiness_file": str(second / "ready"),
        "event_log": str(second / "events.jsonl"),
        "audit_log_path": str(second / "audit.jsonl"),
        "flow_store_db_path": str(second / "flows.sqlite3"),
    })
    config_path = second / "proxy.json"
    config_path.write_text(json.dumps(config))
    binary = os.environ.get("SAFEYOLO_RUST_PROXY", str(REPO / "proxy/target/debug/safeyolo-proxy"))
    with (second / "process.log").open("w") as log:
        process = subprocess.Popen(
            [binary, "--config", str(config_path)], cwd=second,
            env=os.environ.copy(), stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            wait_ready(
                process, [], second / "process.log", readiness_file=second / "ready",
                expected_backend="rust-m2",
            )
            marker = json.loads((second / "ready").read_text())
            yield AdminAPI(
                base_url=f"http://127.0.0.1:{marker['admin_port']}",
                token=token_file.read_text().strip(), timeout=LIMIT,
            )
        finally:
            process.terminate()
            try:
                process.wait(timeout=LIMIT)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=LIMIT)


@contextmanager
def _fixture(directory):
    directory.mkdir()
    _fixture_state(directory)
    (directory / "services/redirect.yaml").write_text(RISKY_CONTRACT_SERVICE)
    token_file = directory / "operator-token"
    token_file.write_text("contention-operator\n")
    with tempfile.TemporaryDirectory(prefix="sy-lock-", dir="/tmp") as socket_dir:
        socket_path = Path(socket_dir) / "policy.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(socket_path))
            listener.listen(2)
            listener.settimeout(LIMIT)
            with patch.dict(os.environ, {"SAFEYOLO_TEST_POLICY_LOCK_SOCKET": str(socket_path)}):
                with _origin("127.0.0.1") as origin:
                    (directory / "policy.toml").write_text(_policy(origin.server_address[1]))
                    with launch_proxy(
                        "rust", directory, None,
                        parent_proxy=f"http://127.0.0.1:{origin.server_address[1]}",
                        agent_api=True, admin_port=0, admin_api_token_file=token_file,
                        gateway_services_dir=directory / "services",
                        gateway_builtin_services_dir=directory / "builtin",
                        network_guard_enabled=True, network_guard_block=True,
                    ) as proxy:
                        yield proxy, _admin(proxy, token_file), origin, listener, socket_path, token_file


def _contend(directory, api, listener, socket_path, token_file, left, right, order="left",
             grant_id=None):
    first_spec, second_spec = (left, right) if order == "left" else (right, left)
    with ExitStack() as stack:
        second_api = (
            stack.enter_context(_second_admin(directory, token_file))
            if first_spec[0] not in {"cli", "locked", "agents"}
            and second_spec[0] not in {"cli", "locked", "agents"}
            else api
        )
        armed = socket_path.with_suffix(".arm")
        armed.touch()
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                first = second = None
                try:
                    first = _start(first_spec, directory, api, listener, pool, grant_id)
                    first.locked()
                    second = _start(second_spec, directory, second_api, listener, pool, grant_id)
                    second.waiting()
                    armed.unlink()
                    first.finish()
                    second.locked()
                    second.finish()
                finally:
                    for writer in (first, second):
                        if writer is not None and not writer.released:
                            writer.release_lock()
        finally:
            armed.unlink(missing_ok=True)


MATRIX = (
    ("cli-same", ("cli", "cli-one.invalid"), ("cli", "cli-two.invalid"), "left"),
    ("engine-same", ("host", "engine-one.invalid"), ("host", "engine-two.invalid"), "left"),
    ("agents-same", ("agents", "delta-one"), ("agents", "delta-two"), "right"),
    ("admin-same", ("service", "alice"), ("service", "bob"), "left"),
    ("gateway-same", ("binding", "alice"), ("binding", "bob"), "left"),
    ("cli-locked", ("locked", "locked.invalid"), ("cli", "cli-mixed.invalid"), "left"),
    ("locked-control-left", ("locked", "lock-one.invalid"),
     ("locked", "lock-two.invalid"), "left"),
    ("locked-control-right", ("locked", "lock-one.invalid"),
     ("locked", "lock-two.invalid"), "right"),
    ("engine-agents", ("host", "engine-mixed.invalid"), ("agents", "delta-mixed"), "left"),
    ("engine-agents-reverse", ("host", "engine-mixed.invalid"),
     ("agents", "delta-mixed"), "right"),
    ("admin-gateway", ("service", "alice"), ("binding", "alice"), "left"),
    ("cli-native", ("cli", "cli-native.invalid"), ("host", "native-cli.invalid"), "left"),
    ("cli-native-reverse", ("cli", "cli-native.invalid"),
     ("host", "native-cli.invalid"), "right"),
)


@pytest.mark.parametrize("name,left,right,order", MATRIX, ids=[row[0] for row in MATRIX])
def test_writer_matrix_has_real_lock_overlap_and_live_effect(
    tmp_path, name, left, right, order,
):
    directory = tmp_path / name
    with _fixture(directory) as (proxy, api, origin, listener, socket_path, token_file):
        if name == "gateway-same":
            assert api.authorize_service("alice", "redirect", "reader", VAULT_NAME)["status"] == "authorized"
            assert api.authorize_service("bob", "redirect", "reader", VAULT_NAME)["status"] == "authorized"
            marker = proxy.readiness_file.stat()
            _converge(proxy, (marker.st_ino, marker.st_mtime_ns))
        _contend(directory, api, listener, socket_path, token_file, left, right, order)
        marker = proxy.readiness_file.stat()
        _converge(proxy, (marker.st_ino, marker.st_mtime_ns))
        source = (directory / "policy.toml").read_text()
        document = tomllib.loads(source)
        assert "# retain unrelated gateway note" in source
        assert document["description"] == "service binding history fixture"
        assert document["hosts"]["*"]["egress"] == "deny"
        assert document["hosts"]["blocked.invalid"]["egress"] == "deny"
        assert document["agents"]["bob"]["folder"] == "/fixture/bob"
        for kind, key in (left, right):
            if kind in {"cli", "locked", "host"}:
                assert document["hosts"][key]["egress"] == "allow"
                _host_effect(proxy, origin, key, True)
            elif kind == "agents":
                assert document["agents"][key]["folder"] == f"/fixture/{key}"
            elif kind == "service":
                assert document["agents"][key]["services"]["redirect"]["capability"] == "reader"
            elif kind == "binding":
                assert any(row["service"] == "redirect" for row in document["agents"][key]["contract_bindings"])
        _host_effect(proxy, origin, "blocked.invalid", False)
        if name in {"admin-same", "gateway-same", "admin-gateway"}:
            agents = ("alice", "bob") if name != "admin-gateway" else ("alice",)
            marker = proxy.readiness_file.stat()
            for agent in agents:
                if name == "admin-same":
                    api.approve_contract_binding(
                        agent, "redirect", "reader", "redirect.reader.v1",
                        {"account": "alpha" if agent == "alice" else "beta"}, ["list_items"],
                    )
                api.add_gateway_grant(agent, "redirect", "GET", "/v1/items", "remembered")
            _converge(proxy, (marker.st_ino, marker.st_mtime_ns))
            for agent in agents:
                _gateway_effect(proxy, origin, agent, "alpha" if agent == "alice" else "beta", 200)
                _gateway_effect(proxy, origin, agent, "wrong", 403)
        assert not list(directory.glob(".policy-*.toml"))


@pytest.mark.parametrize("order,expected", (("left", "deny"), ("right", "allow")))
def test_conflicting_native_edits_follow_the_observed_lock_order(tmp_path, order, expected):
    directory = tmp_path / order
    with _fixture(directory) as (proxy, api, origin, listener, socket_path, token_file):
        _contend(
            directory, api, listener, socket_path, token_file,
            ("host", "conflict.invalid"), ("deny", "conflict.invalid"), order,
        )
        marker = proxy.readiness_file.stat()
        _converge(proxy, (marker.st_ino, marker.st_mtime_ns))
        document = tomllib.loads((directory / "policy.toml").read_text())
        assert document["hosts"]["conflict.invalid"]["egress"] == expected
        assert document["hosts"]["blocked.invalid"]["egress"] == "deny"
        _host_effect(proxy, origin, "conflict.invalid", expected == "allow")
        _host_effect(proxy, origin, "blocked.invalid", False)


def test_revocation_and_unrelated_approval_survive_contention(tmp_path):
    directory = tmp_path / "revocation"
    with _fixture(directory) as (proxy, api, origin, listener, socket_path, token_file):
        assert api.authorize_service("alice", "redirect", "reader", VAULT_NAME)["status"] == "authorized"
        assert api.approve_contract_binding(
            "alice", "redirect", "reader", "redirect.reader.v1",
            {"account": "alpha"}, ["list_items"],
        )["status"] == "bound"
        grant_id = api.add_gateway_grant(
            "alice", "redirect", "GET", "/v1/items", "remembered",
        )["grant_id"]
        marker = proxy.readiness_file.stat()
        _converge(proxy, (marker.st_ino, marker.st_mtime_ns))
        _gateway_effect(proxy, origin, "alice", "alpha", 200)
        _contend(
            directory, api, listener, socket_path, token_file,
            ("revoke", grant_id), ("host", "unrelated-approved.invalid"),
            grant_id=grant_id,
        )
        marker = proxy.readiness_file.stat()
        _converge(proxy, (marker.st_ino, marker.st_mtime_ns))
        document = tomllib.loads((directory / "policy.toml").read_text())
        assert not any(row["grant_id"] == grant_id for row in document["agents"]["alice"].get("grants", []))
        assert document["hosts"]["unrelated-approved.invalid"]["egress"] == "allow"
        assert document["hosts"]["blocked.invalid"]["egress"] == "deny"
        _gateway_effect(proxy, origin, "alice", "alpha", 428)
        _host_effect(proxy, origin, "unrelated-approved.invalid", True)
        _host_effect(proxy, origin, "blocked.invalid", False)
