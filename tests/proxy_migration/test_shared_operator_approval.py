"""Shared operator approval acceptance for both proxy backends.

The request and the operator decision travel through the selected proxy
process and its owned admin listener.  This closes the #621 dual-backend
acceptance gap around a real network approval without reaching into either
implementation's internal policy evaluator.
"""

from __future__ import annotations

import os
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path

from safeyolo.operator_approvals import approve
from tests.proxy_migration.harness import connection, read_events
from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.scenarios import origin_server
from tests.proxy_migration.test_native_network_policy import policy_proxy, replace_policy
from tests.proxy_migration.test_operator_consumer_approval import (
    PROMPT_POLICY,
    _admin_client,
    _compiled_permission,
    _pending,
)
from tests.proxy_migration.test_tunnel_contract import read_all, tunnel
from tests.proxy_migration.test_websocket_contract import exact, read_head


class _EchoOrigin(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(self):
        self.accepts = 0
        self.received = []
        super().__init__(("127.0.0.1", 0), _EchoHandler)

    def get_request(self):
        result = super().get_request()
        self.accepts += 1
        return result


class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(20)
        while payload := self.request.recv(4096):
            self.server.received.append(payload)
            self.request.sendall(payload)


def _connect_response(path, authority, claimed_agent):
    stream = socket.socket(socket.AF_UNIX)
    stream.settimeout(5)
    try:
        stream.connect(path)
        stream.sendall(
            f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
            f"X-SafeYolo-Agent: {claimed_agent}\r\n\r\n".encode()
        )
        return stream, *read_head(stream)
    except Exception:
        stream.close()
        raise


def _wait_for_grant(api, request_id: str, port: int) -> None:
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        baseline = api.get_policy("baseline")
        if (
            not any(row.get("request_id") == request_id for row in api.pending_approvals())
            and _compiled_permission(
                baseline,
                action="network:request",
                resource="127.0.0.1/*",
                effect="budget",
                budget=600,
                agent="alice",
                port=port,
            )
        ):
            return
        time.sleep(0.02)
    raise AssertionError(f"operator approval was not compiled: {request_id}")


def _persistent_request(client, target, claimed_agent):
    client.request("GET", target, headers={
        "Connection": "keep-alive",
        "X-Agent-Id": claimed_agent,
        "X-SafeYolo-Agent": claimed_agent,
        "X-Forwarded-For": "10.0.0.2",
        "X-Fixture-Canary": target.rsplit("/", 1)[-1],
        "Authorization": "Bearer fixture-approval",
    })
    response = client.getresponse()
    try:
        return response.status, {name.lower(): value for name, value in response.getheaders()}, response.read()
    finally:
        response.close()


def _wait_for_removed_grant(api, port):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        baseline = api.get_policy("baseline")
        if not _compiled_permission(
            baseline, action="network:request", resource="127.0.0.1/*",
            effect="budget", budget=600, agent="alice", port=port,
        ):
            return
        time.sleep(0.02)
    raise AssertionError("removed Alice endpoint approval was not reloaded")


def test_shared_operator_approval_is_scoped_and_retried(proxy_backend, tmp_path):
    """A typed operator approval is durable, agent-scoped, and retriable."""
    token_file = tmp_path / "operator-token"
    token_file.write_text("shared-operator-approval\n")
    directory = tmp_path / proxy_backend

    with origin_server(keep_alive=True, capture_heads=True) as origin, origin_server() as other_origin:
        with policy_proxy(
            proxy_backend,
            directory,
            PROMPT_POLICY,
            admin_port=0,
            admin_api_token_file=token_file,
        ) as proxy:
            api = _admin_client(proxy, token_file)
            instance = api.instance()
            assert instance["capabilities"]["approvals"] is True

            port = origin.server_address[1]
            target = f"http://127.0.0.1:{port}/shared-operator-approval"
            status, _, body = send_request(proxy.paths["alice"], target)
            assert status == 428, body
            assert origin.accepts == 0

            event = next(row for row in _pending(api) if row.get("agent") == "alice")
            assert event["event"] == "security.network_guard"
            assert event["decision"] == "require_approval"
            assert event["approval"]["approval_type"] == "network_egress"
            assert event["host"] == "127.0.0.1"
            assert event["approval"]["scope_hint"]["port"] == port

            assert approve(event, api) == "added"
            _wait_for_grant(api, event["request_id"], port)

            status, _, body = send_request(proxy.paths["alice"], target)
            assert status == 200 and body == b"hello"
            assert origin.accepts == 1

            # The operator grant remains scoped to Alice and this exact port.
            status, _, body = send_request(proxy.paths["bob"], target)
            assert status == 428, body
            assert origin.accepts == 1

            other_target = f"http://127.0.0.1:{other_origin.server_address[1]}/other-port"
            status, _, body = send_request(proxy.paths["alice"], other_target)
            assert status == 428, body
            assert other_origin.accepts == 0

            other_host = f"http://localhost:{port}/other-host"
            status, _, body = send_request(proxy.paths["alice"], other_host)
            assert status == 428, body
            assert len(origin.requests) == 1

            # A live UDS connection must consult the current policy on each
            # request. Removing the grant uses the documented host CLI, then
            # the file watcher (Python) or SIGHUP reload (Rust).
            alice = connection(proxy.paths["alice"])
            try:
                alice_socket = alice.sock
                status, headers, body = _persistent_request(alice, target + "/before-remove", "bob")
                assert (status, body) == (200, b"hello")
                assert alice.sock is alice_socket
                reuse_ids = [headers["x-safeyolo-request-id"]]
                removed = subprocess.run(
                    [str(Path(sys.executable).with_name("safeyolo")), "policy", "host", "remove",
                     "127.0.0.1", "--port", str(port), "--agent", "alice"],
                    env={**os.environ, "SAFEYOLO_CONFIG_DIR": str(directory)},
                    capture_output=True, text=True, timeout=10, check=False,
                )
                assert removed.returncode == 0, (removed.stdout, removed.stderr)
                if proxy_backend == "rust":
                    proxy.process.send_signal(signal.SIGHUP)
                _wait_for_removed_grant(api, port)

                before = len(origin.requests)
                accepts_before = origin.accepts
                heads_before = len(origin.request_heads)
                status, headers, body = _persistent_request(alice, target + "/after-remove", "bob")
                assert status == 428, body
                assert headers["x-blocked-by"] == "network-guard"
                assert alice.sock is alice_socket
                assert (origin.accepts, len(origin.requests), len(origin.request_heads)) == (
                    accepts_before, before, heads_before,
                )
                reuse_ids.append(headers["x-safeyolo-request-id"])

                denied_policy = PROMPT_POLICY + (
                    f'\n[agents.alice.hosts]\n"127.0.0.1:{port}" = {{ egress = "deny" }}\n'
                )
                replace_policy(proxy, proxy_backend, directory, denied_policy)
                status, headers, body = _persistent_request(alice, target + "/after-reload", "bob")
                assert status == 403, body
                assert headers["x-blocked-by"] == "network-guard"
                assert (origin.accepts, len(origin.requests), len(origin.request_heads)) == (
                    accepts_before, before, heads_before,
                )
                reuse_ids.append(headers["x-safeyolo-request-id"])

                allowed_policy = PROMPT_POLICY + (
                    f'\n[agents.alice.hosts]\n"127.0.0.1:{port}" = {{ egress = "allow" }}\n'
                )
                replace_policy(proxy, proxy_backend, directory, allowed_policy)
                status, headers, body = _persistent_request(alice, target + "/after-allow", "bob")
                assert (status, body) == (200, b"hello")
                assert alice.sock is alice_socket
                assert len(origin.requests) == before + 1
                reuse_ids.append(headers["x-safeyolo-request-id"])

                # A fresh socket sees the same current rule; the other agent,
                # host spelling and destination port do not inherit it.
                status, _, body = send_request(proxy.paths["alice"], target + "/fresh-allow")
                assert (status, body) == (200, b"hello")
                for path, url, rejected_origin in (
                    (proxy.paths["bob"], target + "/bob-neighbor", origin),
                    (proxy.paths["alice"], other_target, other_origin),
                    (proxy.paths["alice"], other_host, origin),
                ):
                    old_accepts, old_requests = rejected_origin.accepts, len(rejected_origin.requests)
                    status, rejection_headers, body = send_request(path, url)
                    assert status == 428, body
                    assert {name.lower(): value for name, value in rejection_headers.items()}[
                        "x-blocked-by"
                    ] == "network-guard"
                    assert (rejected_origin.accepts, len(rejected_origin.requests)) == (
                        old_accepts, old_requests,
                    )

                replace_policy(proxy, proxy_backend, directory, PROMPT_POLICY)
                before_restore = (origin.accepts, len(origin.requests), len(origin.request_heads))
                status, headers, body = _persistent_request(alice, target + "/after-restore", "bob")
                assert status == 428, body
                assert headers["x-blocked-by"] == "network-guard"
                assert alice.sock is alice_socket
                assert (origin.accepts, len(origin.requests), len(origin.request_heads)) == before_restore
                reuse_ids.append(headers["x-safeyolo-request-id"])
                status, _, body = send_request(proxy.paths["alice"], target + "/fresh-restore")
                assert status == 428, body
                assert (origin.accepts, len(origin.requests), len(origin.request_heads)) == before_restore

                events = {row["request_id"]: row for row in proxy.events("proxy.request")}
                assert [events[identifier]["status"] for identifier in reuse_ids] == [
                    200, 428, 403, 200, 428,
                ]
                assert all(events[identifier]["agent"] == "alice" for identifier in reuse_ids)
                assert len({events[identifier]["connection_id"] for identifier in reuse_ids}) == 1
                heads = b"\n".join(origin.request_heads)
                assert b"X-Fixture-Canary: before-remove" in heads
                assert b"X-Fixture-Canary: after-allow" in heads
                assert heads.count(b"Authorization: Bearer fixture-approval") == 2
                for blocked in (b"after-remove", b"after-reload", b"after-restore"):
                    assert b"X-Fixture-Canary: " + blocked not in heads
                guards = {row["request_id"]: row for row in read_events(directory / "audit.jsonl")
                          if row["event"] == "security.network_guard"}
                assert [guards[identifier]["decision"] for identifier in (
                    reuse_ids[1], reuse_ids[2], reuse_ids[4],
                )] == ["require_approval", "deny", "require_approval"]
            finally:
                alice.close()


def test_connect_approval_requires_a_new_admission(proxy_backend, tmp_path):
    """Approving a rejected CONNECT never replays its completed 428 request."""
    directory = tmp_path / proxy_backend
    token_file = tmp_path / "operator-token"
    token_file.write_text("connect-operator-approval\n")
    with origin_server() as origin:
        port = origin.server_address[1]
        authority = f"127.0.0.1:{port}"
        with policy_proxy(
            proxy_backend, directory, PROMPT_POLICY,
            ignore_hosts=[authority], eager_connect=True,
            admin_port=0, admin_api_token_file=token_file,
        ) as proxy:
            api = _admin_client(proxy, token_file)
            status, headers, body = send_request(
                proxy.paths["alice"], authority, method="CONNECT",
                headers={"Host": authority, "X-SafeYolo-Agent": "bob"},
            )
            assert status == 428, body
            assert {name.lower(): value for name, value in headers.items()}[
                "x-blocked-by"
            ] == "network-guard"
            assert origin.accepts == 0 and origin.requests == []
            event = next(row for row in _pending(api) if row.get("agent") == "alice")
            assert event["event"] == "security.network_guard"
            assert event["request_id"] == {name.lower(): value for name, value in headers.items()}[
                "x-safeyolo-request-id"
            ]
            assert event["approval"]["scope_hint"]["port"] == port
            assert event["details"]["method"] == "CONNECT"
            assert event["details"].get("path") in (None, "")
            assert approve(event, api) == "added"
            _wait_for_grant(api, event["request_id"], port)
            assert origin.accepts == 0 and origin.requests == []

            with tunnel(proxy.paths["alice"], authority) as stream:
                stream.sendall(
                    f"GET /approved-inner HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n".encode()
                )
                response = read_all(stream)
                assert response.startswith(b"HTTP/1.1 200 "), response
                assert response.endswith(b"hello"), response
            assert origin.accepts == 1
            assert origin.requests == [{"method": "GET", "target": "/approved-inner"}]

            status, _, body = send_request(
                proxy.paths["bob"], authority, method="CONNECT",
                headers={"Host": authority, "X-SafeYolo-Agent": "alice"},
            )
            assert status == 428, body
            assert origin.accepts == 1 and len(origin.requests) == 1


def test_live_connect_keeps_its_admission_after_policy_reload(proxy_backend, tmp_path):
    """A new CONNECT uses the reloaded rule; an admitted opaque tunnel stays live."""
    directory = tmp_path / proxy_backend
    with _EchoOrigin() as origin:
        thread = threading.Thread(target=origin.serve_forever, daemon=True)
        thread.start()
        try:
            port = origin.server_address[1]
            authority = f"127.0.0.1:{port}"
            rule = '\n[agents.alice.hosts]\n"{}" = {{ egress = "{}" }}\n'
            allowed_policy = PROMPT_POLICY + rule.format(authority, "allow")
            denied_policy = PROMPT_POLICY + rule.format(authority, "deny")
            with policy_proxy(
                proxy_backend, directory, allowed_policy,
                ignore_hosts=[authority], eager_connect=True,
            ) as proxy:
                live, status, headers = _connect_response(proxy.paths["alice"], authority, "bob")
                try:
                    assert status.startswith("HTTP/1.1 200 "), status
                    live_id = headers["x-safeyolo-request-id"][0]
                    assert origin.accepts == 1
                    live.sendall(b"before-reload")
                    assert exact(live, len(b"before-reload")) == b"before-reload"

                    replace_policy(proxy, proxy_backend, directory, denied_policy)
                    live.sendall(b"after-reload")
                    assert exact(live, len(b"after-reload")) == b"after-reload"
                    assert origin.accepts == 1

                    denied, status, headers = _connect_response(
                        proxy.paths["alice"], authority, "bob",
                    )
                    with denied:
                        assert status.startswith("HTTP/1.1 403 "), status
                        assert headers["x-blocked-by"] == ["network-guard"]
                        denied_id = headers["x-safeyolo-request-id"][0]
                    assert origin.accepts == 1
                    assert b"".join(origin.received) == b"before-reloadafter-reload"

                    bob, status, headers = _connect_response(
                        proxy.paths["bob"], authority, "alice",
                    )
                    with bob:
                        assert status.startswith("HTTP/1.1 428 "), status
                        assert headers["x-blocked-by"] == ["network-guard"]
                        bob_id = headers["x-safeyolo-request-id"][0]
                    assert origin.accepts == 1

                    replace_policy(proxy, proxy_backend, directory, allowed_policy)
                    restored, status, headers = _connect_response(
                        proxy.paths["alice"], authority, "bob",
                    )
                    with restored:
                        assert status.startswith("HTTP/1.1 200 "), status
                        restored_id = headers["x-safeyolo-request-id"][0]
                        restored.sendall(b"restored")
                        assert exact(restored, len(b"restored")) == b"restored"
                    assert origin.accepts == 2
                    assert b"".join(origin.received) == b"before-reloadafter-reloadrestored"

                    audits = {row["request_id"]: row for row in read_events(directory / "audit.jsonl")
                              if row["event"] == "security.network_guard"
                              and row.get("details", {}).get("method") == "CONNECT"}
                    assert [(audits[identifier]["agent"], audits[identifier]["decision"])
                            for identifier in (live_id, denied_id, bob_id, restored_id)] == [
                        ("alice", "allow"), ("alice", "deny"),
                        ("bob", "require_approval"), ("alice", "allow"),
                    ]
                    assert all(audits[identifier]["details"]["port"] == port for identifier in (
                        live_id, denied_id, bob_id, restored_id,
                    ))
                finally:
                    live.close()
        finally:
            origin.shutdown()
            thread.join(timeout=5)
            assert not thread.is_alive()


def test_expiring_host_allowance_changes_only_at_reload(proxy_backend, tmp_path):
    """Time alone retains loaded rules; reload prunes the supported host scope."""
    directory = tmp_path / proxy_backend
    with origin_server(keep_alive=True, capture_heads=True) as origin:
        port = origin.server_address[1]
        expiry = datetime.now(UTC) + timedelta(seconds=10)
        expires = expiry.isoformat(timespec="seconds").replace("+00:00", "Z")
        expiring_policy = f'''budget = 12000
[hosts]
"*" = {{ egress = "prompt" }}
"localhost:{port}" = {{ egress = "allow", expires = {expires} }}
[agents.alice]
egress = "prompt"
[agents.alice.hosts]
"127.0.0.1:{port}" = {{ egress = "allow", expires = {expires} }}
'''
        with policy_proxy(proxy_backend, directory, PROMPT_POLICY) as proxy:
            alice = connection(proxy.paths["alice"])
            try:
                alice_socket = alice.sock
                target = f"http://127.0.0.1:{port}"
                global_target = f"http://localhost:{port}"
                status, _, body = _persistent_request(alice, target + "/before-allow", "bob")
                assert status == 428, body
                assert origin.accepts == 0

                replace_policy(proxy, proxy_backend, directory, expiring_policy)
                status, _, body = _persistent_request(alice, target + "/agent-before-expiry", "bob")
                assert (status, body) == (200, b"hello")
                status, _, body = send_request(proxy.paths["bob"], global_target + "/global-before-expiry")
                assert (status, body) == (200, b"hello")
                assert alice.sock is alice_socket
                assert len(origin.requests) == 2

                # No loader runs just because wall time passes. Stay more than
                # one second beyond the timestamp before checking either path.
                time.sleep(max(0, (expiry - datetime.now(UTC)).total_seconds() + 1.5))
                status, _, body = _persistent_request(alice, target + "/agent-before-reload", "bob")
                assert (status, body) == (200, b"hello")
                status, _, body = send_request(proxy.paths["bob"], global_target + "/global-before-reload")
                assert (status, body) == (200, b"hello")
                assert len(origin.requests) == 4

                replace_policy(proxy, proxy_backend, directory, expiring_policy)
                before = (origin.accepts, len(origin.requests), len(origin.request_heads))
                status, headers, body = send_request(
                    proxy.paths["bob"], global_target + "/global-after-reload",
                )
                assert status == 428, body
                global_id = {name.lower(): value for name, value in headers.items()}[
                    "x-safeyolo-request-id"
                ]
                assert (origin.accepts, len(origin.requests), len(origin.request_heads)) == before

                status, headers, body = _persistent_request(
                    alice, target + "/agent-after-reload", "bob",
                )
                agent_id = headers["x-safeyolo-request-id"]
                # D15: the Python loader prunes global hosts only. Rust also
                # prunes expired agent-scoped hosts at this reload boundary.
                expected_agent_status = 200 if proxy_backend == "python" else 428
                assert status == expected_agent_status, body
                assert alice.sock is alice_socket
                if proxy_backend == "python":
                    assert body == b"hello"
                    assert len(origin.requests) == before[1] + 1
                else:
                    assert (origin.accepts, len(origin.requests), len(origin.request_heads)) == before

                saved = tomllib.loads((directory / "policy.toml").read_text())
                assert f"localhost:{port}" not in saved["hosts"]
                assert (f"127.0.0.1:{port}" in saved["agents"]["alice"].get("hosts", {})) == (
                    proxy_backend == "python"
                )

                runtime = {row["request_id"]: row for row in proxy.events("proxy.request")}
                assert (runtime[global_id]["agent"], runtime[global_id]["status"]) == ("bob", 428)
                assert (runtime[agent_id]["agent"], runtime[agent_id]["status"]) == (
                    "alice", expected_agent_status,
                )
                guards = {row["request_id"]: row for row in read_events(directory / "audit.jsonl")
                          if row["event"] == "security.network_guard"}
                assert guards[global_id]["decision"] == "require_approval"
                if proxy_backend == "rust":
                    assert guards[agent_id]["decision"] == "require_approval"

                replace_policy(proxy, proxy_backend, directory, PROMPT_POLICY)
                before = (origin.accepts, len(origin.requests), len(origin.request_heads))
                status, headers, body = _persistent_request(alice, target + "/restored-prompt", "bob")
                assert status == 428, body
                assert headers["x-blocked-by"] == "network-guard"
                assert alice.sock is alice_socket
                assert (origin.accepts, len(origin.requests), len(origin.request_heads)) == before
            finally:
                alice.close()
