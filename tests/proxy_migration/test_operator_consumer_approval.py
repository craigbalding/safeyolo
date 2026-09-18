"""Retained operator-client approval workflow against the native Rust proxy.

The request travels through the selected Rust executable and a real trusted
agent Unix socket.  The operator side uses the existing Python ``AdminAPI``
and ``operator_approvals`` client code; the test does not call the Rust
handler directly or manufacture a pending approval event.
"""

from __future__ import annotations

import json
import time

from safeyolo.api import AdminAPI
from safeyolo.operator_approvals import approve
from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.scenarios import origin_server
from tests.proxy_migration.test_native_network_policy import policy_proxy


PROMPT_POLICY = """
budget = 12000
[hosts]
"*" = { egress = "prompt" }
[agents.alice]
egress = "prompt"
[agents.bob]
egress = "prompt"
"""


def _pending(api: AdminAPI, request_id: str | None = None) -> list[dict]:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        rows = api.pending_approvals()
        if rows and (request_id is None or any(row.get("request_id") == request_id for row in rows)):
            return rows
        time.sleep(0.02)
    raise AssertionError(f"native proxy did not publish a pending approval: {request_id!r}")


def _admin_client(proxy, token_file) -> AdminAPI:
    marker = json.loads(proxy.readiness_file.read_text())
    return AdminAPI(
        base_url=f"http://127.0.0.1:{marker['admin_port']}",
        token=token_file.read_text().strip(),
        timeout=5,
    )


def test_retained_operator_client_approves_exact_native_network_scope(tmp_path):
    """An existing operator client can approve one real request safely."""
    token_file = tmp_path / "operator-token"
    token_file.write_text("operator-client-workflow\n")
    directory = tmp_path / "native"

    with origin_server() as origin, origin_server() as other_origin:
        with policy_proxy(
            "rust",
            directory,
            PROMPT_POLICY,
            admin_port=0,
            admin_api_token_file=token_file,
        ) as proxy:
            api = _admin_client(proxy, token_file)

            # These are the retained operator reads used before a decision.
            instance = api.instance()
            assert instance["safeyolo_instance_id"]
            assert instance["capabilities"]["approvals"] is True
            baseline = api.get_policy("baseline")
            assert isinstance(baseline["baseline"], dict)

            target = f"http://127.0.0.1:{origin.server_address[1]}/operator-approval"
            status, _, body = send_request(proxy.paths["alice"], target)
            assert status == 428, body
            assert origin.accepts == 0

            pending = _pending(api)
            event = next(row for row in pending if row.get("agent") == "alice")
            assert event["event"] == "security.network_guard"
            assert event["decision"] == "require_approval"
            assert event["approval"]["approval_type"] == "network_egress"
            assert event["host"] == "127.0.0.1"
            port = origin.server_address[1]
            assert event["approval"]["target"] == f"127.0.0.1:{port}"
            assert event["approval"]["scope_hint"]["port"] == port

            # This is the same typed operator action used by ``safeyolo watch``.
            assert approve(event, api) == "added"
            changed = api.get_policy("baseline")
            assert "127.0.0.1" in json.dumps(changed["baseline"], sort_keys=True)

            status, _, body = send_request(proxy.paths["alice"], target)
            assert status == 200 and body == b"hello"
            assert origin.accepts == 1

            # The approval is scoped to Alice, this host, and this port.
            status, _, body = send_request(proxy.paths["bob"], target)
            assert status == 428, body
            assert origin.accepts == 1

            other_host = f"http://localhost:{other_origin.server_address[1]}/other-host"
            status, _, body = send_request(proxy.paths["alice"], other_host)
            assert status == 428, body
            assert other_origin.accepts == 0

            other_port = f"http://127.0.0.1:{other_origin.server_address[1]}/other-port"
            status, _, body = send_request(proxy.paths["alice"], other_port)
            assert status == 428, body
            assert other_origin.accepts == 0
