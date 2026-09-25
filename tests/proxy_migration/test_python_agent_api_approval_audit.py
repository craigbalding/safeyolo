"""Real retained-Python Agent API approval submission versus operator evidence."""

from __future__ import annotations

import json

from safeyolo.api import AdminAPI
from safeyolo.core.audit_stream import scan_pending_approvals
from tests.proxy_migration.harness import launch_proxy, request
from tests.proxy_migration.scenarios import POLICY

HOST = "_safeyolo.proxy.internal"
TOKEN = "fixture-agent-api-token-one"
APPROVAL_EVENTS = {
    "gateway.request_access",
    "gateway.submit_binding",
    "agent.desktop_present_requested",
    "plumb.requested",
}


def _send(proxy, agent, path, body=None):
    headers = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
    status, response_headers, raw = request(
        proxy.paths[agent],
        f"http://{HOST}{path}",
        method="POST",
        headers=headers,
        body=json.dumps(body).encode() if body is not None else b"",
    )
    headers = {key.lower(): value for key, value in response_headers.items()}
    decoded = json.loads(raw)
    return status, headers, decoded


def _submit_all(proxy, agent, expected_status):
    challenge = _send(
        proxy,
        agent,
        "/gateway/request-access",
        {
            "service": "contractsvc",
            "capability": "read",
        },
    )
    assert challenge[0] == 200 and challenge[2]["decision"] == "needs_contract_binding"

    outcomes = {
        "gateway.request_access": _send(
            proxy,
            agent,
            "/gateway/request-access",
            {
                "service": "simple",
                "capability": "read",
                "reason": "owned fixture",
            },
        ),
        "gateway.submit_binding": _send(
            proxy,
            agent,
            "/gateway/submit-binding",
            {
                "service": "contractsvc",
                "capability": "read",
                "bindings": {"approved": "alpha"},
            },
        ),
        "agent.desktop_present_requested": _send(proxy, agent, "/desktop/present"),
        "plumb.requested": _send(
            proxy,
            agent,
            "/plumb/request-chat",
            {
                "participants": ["dave" if agent == "bob" else "bob"],
                "topic": "owned fixture collaboration",
            },
        ),
    }
    for event, (status, headers, body) in outcomes.items():
        assert status == expected_status, (event, body)
        assert headers["x-safeyolo-agent-api"] == "true"
        if expected_status == 202:
            if event == "plumb.requested":
                assert body["state"] == "pending" and agent in body["participants"]
                assert body["request_id"].startswith("req_")
            else:
                assert body["status"] == "pending" and body["agent"] == agent
                assert "submitted" in body["message"].lower()
            if event == "agent.desktop_present_requested":
                assert body["request_id"] == headers["x-safeyolo-request-id"]
        else:
            assert body["error"].startswith("Internal error:")
            assert "pending" not in body and "message" not in body
    return outcomes


def _operator_rows(api, log_path):
    admin_rows = [row for row in api.pending_approvals() if row["event"] in APPROVAL_EVENTS]
    watch_rows, _ = scan_pending_approvals(log_path)
    watch_rows = [row for row in watch_rows if row["event"] in APPROVAL_EVENTS]
    assert {(row["event"], row["agent"], row.get("request_id")) for row in admin_rows} == {
        (row["event"], row["agent"], row.get("request_id")) for row in watch_rows
    }
    return admin_rows


def test_python_agent_api_only_claims_review_after_audit_append(tmp_path):
    services = tmp_path / "services"
    services.mkdir()
    (services / "simple.yaml").write_text("""
schema_version: 1
name: simple
description: Simple fixture service
capabilities:
  read:
    description: Read fixture records
    routes:
      - methods: [GET]
        path: /records
""")
    (services / "contractsvc.yaml").write_text("""
schema_version: 1
name: contractsvc
description: Contract fixture service
capabilities:
  read:
    description: Read bound fixture records
    contract:
      template: demo.read.v1
      bindings:
        approved: {source: agent, type: enum, options: [alpha]}
      operations:
        - name: read
          request: {method: GET, path: /records}
      enforcement: {request_shape: enforced}
""")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "policy.toml").write_text(
        '[agents.bob]\nagent_id = "ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"\n'
        '[agents.carol]\nagent_id = "ag-cccccccccccccccccccccccccccccccc"\n'
        '[agents.dave]\nagent_id = "ag-dddddddddddddddddddddddddddddddd"\n'
    )
    token_file = tmp_path / "operator-token"
    token_file.write_text("fixture-operator-token\n")
    directory = tmp_path / "python"

    with launch_proxy(
        "python",
        directory,
        POLICY,
        agent_api=True,
        admin_port=0,
        admin_api_token_file=token_file,
        agents=("bob", "carol", "dave"),
        services_dir=services,
        python_config_dir=config_dir,
    ) as proxy:
        marker = json.loads(proxy.readiness_file.read_text())
        api = AdminAPI(
            base_url=f"http://127.0.0.1:{marker['admin_port']}",
            token=token_file.read_text().strip(),
            timeout=5,
        )
        audit = directory / "audit.jsonl"
        bob = _submit_all(proxy, "bob", 202)
        rows = _operator_rows(api, audit)
        assert {(row["event"], row["agent"]) for row in rows} == {(event, "bob") for event in APPROVAL_EVENTS}
        desktop_id = bob["agent.desktop_present_requested"][2]["request_id"]
        assert (
            next(row for row in rows if row["event"] == "agent.desktop_present_requested")["request_id"] == desktop_id
        )

        before = audit.read_bytes()
        audit.chmod(0o444)
        try:
            assert not audit.stat().st_mode & 0o222
            _submit_all(proxy, "carol", 500)
            # A non-approval Agent API operation remains available while the
            # canonical approval destination is broken.
            status, _, body = request(
                proxy.paths["carol"],
                f"http://{HOST}/health",
                headers={"Authorization": f"Bearer {TOKEN}"},
            )
            assert status == 200 and json.loads(body)["agent_api"] == "ok"
            assert audit.read_bytes() == before
            rows = _operator_rows(api, audit)
            assert {(row["event"], row["agent"]) for row in rows} == {(event, "bob") for event in APPROVAL_EVENTS}
        finally:
            audit.chmod(0o644)

        dave = _submit_all(proxy, "dave", 202)
        rows = _operator_rows(api, audit)
        assert {(row["event"], row["agent"]) for row in rows} == {
            (event, agent) for event in APPROVAL_EVENTS for agent in ("bob", "dave")
        }
        dave_desktop_id = dave["agent.desktop_present_requested"][2]["request_id"]
        assert (
            next(row for row in rows if row["agent"] == "dave" and row["event"] == "agent.desktop_present_requested")[
                "request_id"
            ]
            == dave_desktop_id
        )
        assert "audit writer flush failed" in (directory / "process.log").read_text()
