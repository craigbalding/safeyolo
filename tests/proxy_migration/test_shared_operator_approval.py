"""Shared operator approval acceptance for both proxy backends.

The request and the operator decision travel through the selected proxy
process and its owned admin listener.  This closes the #621 dual-backend
acceptance gap around a real network approval without reaching into either
implementation's internal policy evaluator.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from safeyolo.operator_approvals import approve
from tests.proxy_migration.harness import connection
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

    with origin_server(keep_alive=True) as origin, origin_server() as other_origin:
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
                status, headers, body = _persistent_request(alice, target + "/after-remove", "bob")
                assert status == 428, body
                assert headers["x-blocked-by"] == "network-guard"
                assert alice.sock is alice_socket
                assert len(origin.requests) == before
                reuse_ids.append(headers["x-safeyolo-request-id"])

                denied_policy = PROMPT_POLICY + (
                    f'\n[agents.alice.hosts]\n"127.0.0.1:{port}" = {{ egress = "deny" }}\n'
                )
                replace_policy(proxy, proxy_backend, directory, denied_policy)
                status, headers, body = _persistent_request(alice, target + "/after-reload", "bob")
                assert status == 403, body
                assert headers["x-blocked-by"] == "network-guard"
                assert len(origin.requests) == before
                reuse_ids.append(headers["x-safeyolo-request-id"])
                events = {row["request_id"]: row for row in proxy.events("proxy.request")}
                assert [events[identifier]["status"] for identifier in reuse_ids] == [200, 428, 403]
                assert all(events[identifier]["agent"] == "alice" for identifier in reuse_ids)
                assert len({events[identifier]["connection_id"] for identifier in reuse_ids}) == 1
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
