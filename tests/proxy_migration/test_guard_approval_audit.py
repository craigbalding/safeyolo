"""Approval prompts from both guards require an operator-visible audit append."""

from __future__ import annotations

import json

import pytest

from safeyolo.api import AdminAPI
from safeyolo.commands.watch import scan_pending_approvals
from tests.proxy_migration.harness import read_events, request
from tests.proxy_migration.scenarios import origin_server
from tests.proxy_migration.test_native_network_policy import policy_proxy
from tests.proxy_migration.test_operator_consumer_approval import (
    CREDENTIAL_POLICY,
)

NETWORK_POLICY = """
budget = 12000
[hosts]
"*" = { egress = "prompt" }
[agents.alice]
egress = "prompt"
[agents.bob]
egress = "allow"
[agents.carol]
egress = "deny"
"""


@pytest.mark.parametrize(
    ("guard", "policy", "event"),
    [
        ("network", NETWORK_POLICY, "security.network_guard"),
        ("credential", CREDENTIAL_POLICY, "security.credential_guard"),
    ],
    ids=["network", "credential"],
)
def test_guard_prompt_waits_for_audit_append(proxy_backend, tmp_path, guard, policy, event):
    directory = tmp_path / f"{proxy_backend}-{guard}"
    token_file = tmp_path / "operator-token"
    token_file.write_text("guard-approval-audit-fixture\n")

    with origin_server() as origin:
        target = f"http://127.0.0.1:{origin.server_address[1]}/guard-approval"
        with policy_proxy(
            proxy_backend,
            directory,
            policy,
            admin_port=0,
            admin_api_token_file=token_file,
            credential_head_decision=guard == "credential",
            agents=("alice", "bob", "carol") if guard == "network" else ("alice", "bob"),
        ) as proxy:
            marker = json.loads(proxy.readiness_file.read_text())
            api = AdminAPI(
                base_url=f"http://127.0.0.1:{marker['admin_port']}",
                token=token_file.read_text().strip(),
            )
            audit = directory / "audit.jsonl"

            def send_prompt():
                headers = {"Authorization": "Bearer key-approve"} if guard == "credential" else {}
                status, response_headers, body = request(proxy.paths["alice"], target, headers=headers)
                request_id = next(value for name, value in response_headers.items()
                                  if name.lower() == "x-safeyolo-request-id")
                assert b"key-approve" not in body
                return status, request_id, body

            def pending_ids():
                admin = {row["request_id"] for row in api.pending_approvals()
                         if row["event"] == event}
                watch, _ = scan_pending_approvals(audit)
                watched = {row["request_id"] for row in watch if row["event"] == event}
                return admin, watched

            healthy_status, healthy_id, healthy_body = send_prompt()
            assert healthy_status == 428, healthy_body
            if guard == "network":
                assert b"wait_for_approval" in healthy_body
            assert origin.accepts == 0
            assert all(healthy_id in ids for ids in pending_ids())
            assert any(row.get("event") == event and row.get("request_id") == healthy_id
                       and row.get("decision") == "require_approval"
                       for row in read_events(audit))
            assert b"key-approve" not in audit.read_bytes()

            audit.chmod(0o444)
            before = audit.read_bytes()
            try:
                assert not audit.stat().st_mode & 0o222
                failed_status, failed_id, failed_body = send_prompt()
                assert failed_id != healthy_id
                assert failed_status == (503 if proxy_backend == "python" else 502), failed_body
                assert b"wait_for_approval" not in failed_body
                assert audit.read_bytes() == before
                assert not any(row.get("request_id") == failed_id for row in read_events(audit))
                assert all(failed_id not in ids for ids in pending_ids())
                assert origin.accepts == 0

                # Ordinary forwarding does not depend on an approval append.
                control_agent = "bob" if guard == "network" else "alice"
                status, _, body = request(proxy.paths[control_agent], target)
                assert (status, body) == (200, b"hello")
                assert origin.accepts == 1
                if guard == "network":
                    # An unrelated deny remains local while its ordinary audit
                    # write is unavailable.
                    status, _, body = request(proxy.paths["carol"], target)
                    assert status == 403, body
                    assert origin.accepts == 1
            finally:
                audit.chmod(0o644)

            recovered_status, recovered_id, recovered_body = send_prompt()
            assert recovered_status == 428, recovered_body
            assert recovered_id not in (healthy_id, failed_id)
            assert all(recovered_id in ids for ids in pending_ids())
            assert any(row.get("event") == event and row.get("request_id") == recovered_id
                       and row.get("decision") == "require_approval"
                       for row in read_events(audit))
            assert origin.accepts == 1
