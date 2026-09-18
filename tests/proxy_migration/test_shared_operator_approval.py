"""Shared operator approval acceptance for both proxy backends.

The request and the operator decision travel through the selected proxy
process and its owned admin listener.  This closes the #621 dual-backend
acceptance gap around a real network approval without reaching into either
implementation's internal policy evaluator.
"""

from __future__ import annotations

import time

from safeyolo.operator_approvals import approve
from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.scenarios import origin_server
from tests.proxy_migration.test_native_network_policy import policy_proxy
from tests.proxy_migration.test_operator_consumer_approval import (
    PROMPT_POLICY,
    _admin_client,
    _compiled_permission,
    _pending,
)


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


def test_shared_operator_approval_is_scoped_and_retried(proxy_backend, tmp_path):
    """A typed operator approval is durable, agent-scoped, and retriable."""
    token_file = tmp_path / "operator-token"
    token_file.write_text("shared-operator-approval\n")
    directory = tmp_path / proxy_backend

    with origin_server() as origin, origin_server() as other_origin:
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
