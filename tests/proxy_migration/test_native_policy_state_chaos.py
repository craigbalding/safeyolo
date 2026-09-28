"""Bounded state histories through the native proxy and retained public writers."""

from __future__ import annotations

import json
import os
import shlex
import sys
import tempfile
import time
import tomllib
import uuid
from pathlib import Path
from unittest.mock import patch

from hypothesis import HealthCheck, Phase, given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from safeyolo.agents_store import load_agent, mutate_agent, remove_agent, save_agent
from safeyolo.api import AdminAPI
from safeyolo.cli import app
from safeyolo.operator_approvals import approve, deny
from tests.proxy_migration.harness import request
from tests.proxy_migration.test_gateway_redirect import (
    AGENT_API,
    AGENT_TOKEN,
    VAULT_CREDENTIAL,
    VAULT_NAME,
    _authorization,
    _fixture_state,
    _origin,
    _wire,
)
from tests.proxy_migration.test_gateway_scope import SERVICE as CONTRACT_SERVICE
from tests.proxy_migration.test_native_network_policy import policy_proxy
from tests.proxy_migration.test_native_policy_host_chaos import _converge
from tests.proxy_migration.test_operator_consumer_approval import _credential_origin

SEQUENCE_SETTINGS = settings(
    max_examples=8, deadline=None, phases=(Phase.generate,),
    suppress_health_check=(HealthCheck.too_slow,),
)
CLI = CliRunner()
HOSTS = ("cred-one.invalid", "cred-two.invalid")
KEYS = ("key-alpha", "key-beta", "key-gamma")
RISKY_CONTRACT_SERVICE = CONTRACT_SERVICE + '''risky_routes:
  - path: /v1/items
    methods: [GET]
    tactics: [impact]
    description: Read one synthetic account
'''


def _admin(proxy, token_file: Path) -> AdminAPI:
    marker = json.loads(proxy.readiness_file.read_text())
    return AdminAPI(
        base_url=f"http://127.0.0.1:{marker['admin_port']}",
        token=token_file.read_text().strip(), timeout=5,
    )


def _request_id(headers: dict[str, str]) -> str:
    return next(value for key, value in headers.items() if key.lower() == "x-safeyolo-request-id")


def _pending(api: AdminAPI, request_id: str) -> dict:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        for row in api.pending_approvals():
            if row.get("request_id") == request_id:
                return row
        time.sleep(0.025)
    raise AssertionError(f"Pending approval missing for request {request_id}")


def _audit(directory: Path) -> list[dict]:
    path = directory / "audit.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line] if path.exists() else []


def _wait_for_audit(directory: Path, prior_count: int, event: str,
                    host: str | None = None) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if any(
            row.get("event") == event
            and (host is None or row.get("details", {}).get("destination") == host)
            for row in _audit(directory)[prior_count:]
        ):
            return
        time.sleep(0.025)
    raise AssertionError(f"Native audit missing {event} for {host or 'this mutation'}")


def _residue(directory: Path) -> list[str]:
    return sorted(path.name for path in directory.glob(".policy-*.toml"))


def _credential_policy() -> str:
    return '''# retain this unrelated operator note
version = "2.0"
description = "credential history fixture"
budget = 12000
[hosts]
"*" = { egress = "allow" }
"unrelated.invalid" = { egress = "deny" }
[agents.alice]
[agents.bob]
[[permissions]]
action = "credential:use"
resource = "*"
effect = "prompt"
[[credential_rules]]
name = "synthetic"
patterns = ["key-[a-z]+"]
allowed_hosts = ["cred-one.invalid", "cred-two.invalid"]
header_names = ["authorization"]
[addons.credential_guard]
enabled = true
[addons.credential_guard.settings]
use_default_credential_rules = false
'''


def _credential_probe(proxy, origin, approved: set[tuple[str, str]], step: int) -> dict:
    statuses = {}
    for agent in ("alice", "bob"):
        for host in HOSTS:
            for key in KEYS:
                before = origin.accepts
                status, _, body = request(
                    proxy.paths[agent], f"http://{host}:8123/state-{step}",
                    headers={"Authorization": f"Bearer {key}"},
                )
                expected = 200 if (host, key) in approved else 428
                assert status == expected, (agent, host, key, expected, status, body)
                assert origin.accepts == before + int(expected == 200)
                if expected == 200:
                    assert body == b"hello"
                    assert origin.authorization[-1] == f"Bearer {key}"
                statuses[f"{agent}:{host}:{key}"] = status
        for neighbour in ("child.cred-one.invalid", "evilcred-one.invalid"):
            before = origin.accepts
            status, _, _ = request(
                proxy.paths[agent], f"http://{neighbour}:8123/state-{step}",
                headers={"Authorization": "Bearer key-alpha"},
            )
            assert status == 428 and origin.accepts == before
            statuses[f"{agent}:{neighbour}:key-alpha"] = status
        before = origin.accepts
        status, _, body = request(proxy.paths[agent], f"http://{HOSTS[0]}:8123/plain-{step}")
        assert (status, body) == (200, b"hello")
        assert origin.accepts == before + 1
    return statuses


def _credential_prompt(proxy, api, host: str, key: str) -> dict:
    status, headers, body = request(
        proxy.paths["alice"], f"http://{host}:8123/operator",
        headers={"Authorization": f"Bearer {key}"},
    )
    assert status == 428, (host, key, status, body)
    event = _pending(api, _request_id(headers))
    assert event["approval"]["approval_type"] == "credential"
    assert event["host"] == host
    return event


def execute_credential_trace(directory: Path, trace: dict) -> dict:
    """Replay credential decisions against the actual Admin and CLI writers."""
    operations = trace.get("operations")
    if not isinstance(operations, list) or not 1 <= len(operations) <= 6:
        raise ValueError("Credential trace requires one to six operations")
    directory.mkdir(parents=True)
    policy = directory / "policy.toml"
    policy.write_text(_credential_policy())
    token_file = directory / "operator-token"
    token_file.write_text("credential-history-operator\n")
    approved: set[tuple[str, str]] = set()
    fingerprints: dict[tuple[str, str], str] = {}
    steps = []
    trace["observed_steps"] = steps
    with _credential_origin() as origin:
        parent = f"http://127.0.0.1:{origin.server_address[1]}"
        with policy_proxy("rust", directory, None, parent_proxy=parent,
                          admin_port=0, admin_api_token_file=token_file) as proxy:
            api = _admin(proxy, token_file)
            _credential_probe(proxy, origin, approved, 0)
            for index, operation in enumerate(operations, 1):
                before = proxy.readiness_file.stat()
                marker = before.st_ino, before.st_mtime_ns
                action = operation["action"]
                host = operation.get("host")
                key = operation.get("key")
                audit_count = len(_audit(directory))
                if action in {"approve", "deny"}:
                    assert host in HOSTS and key in KEYS
                    event = _credential_prompt(proxy, api, host, key)
                    fingerprints[(host, key)] = event["approval"]["key"]
                    result = approve(event, api) if action == "approve" else deny(event, api)
                    if action == "approve":
                        approved.add((host, key))
                    _wait_for_audit(
                        directory, audit_count,
                        "admin.approval_added" if action == "approve" else "admin.denial", host,
                    )
                elif action == "reapprove":
                    assert (host, key) in fingerprints
                    result = api.add_approval(host, fingerprints[(host, key)])
                    assert result["status"] in {"added", "ok"}
                    approved.add((host, key))
                    _wait_for_audit(directory, audit_count, "admin.approval_added", host)
                elif action == "revoke":
                    assert host in HOSTS
                    command = ["policy", "host", "remove", host]
                    with patch.dict(os.environ, {"SAFEYOLO_CONFIG_DIR": str(directory)}):
                        response = CLI.invoke(app, command)
                    assert response.exit_code == 0, (command, response.output, response.exception)
                    result = response.output.strip()
                    approved = {pair for pair in approved if pair[0] != host}
                elif action == "reload":
                    result = "reload"
                else:
                    raise ValueError(f"Unsupported credential operation: {action}")
                step = {"operation": operation, "result": result}
                steps.append(step)
                _converge(proxy, marker)
                statuses = _credential_probe(proxy, origin, approved, index)
                source = policy.read_text()
                document = tomllib.loads(source)
                assert "# retain this unrelated operator note" in source
                assert document["description"] == "credential history fixture"
                assert document["hosts"]["unrelated.invalid"] == {"egress": "deny"}
                for named_host in HOSTS:
                    assert bool(document["hosts"].get(named_host)) == any(
                        item[0] == named_host for item in approved
                    )
                assert not _residue(directory)
                step.update({
                    "statuses": statuses,
                    "hosts": {host: document["hosts"].get(host) for host in HOSTS},
                    "audit_events": [row["event"] for row in _audit(directory)
                                     if row["event"].startswith("admin.")],
                    "temporary_residue": _residue(directory),
                })
        final = policy.read_bytes()
        with policy_proxy("rust", directory, None, parent_proxy=parent,
                          admin_port=0, admin_api_token_file=token_file) as fresh:
            assert policy.read_bytes() == final
            _credential_probe(fresh, origin, approved, len(steps) + 1)
    return {"operations": len(steps), "steps": steps, "fresh_matches": True}


def _gateway_policy(port: int) -> str:
    return f'''# retain unrelated gateway note
version = "2.0"
description = "service binding history fixture"
budget = 12000
[hosts."127.0.0.1"]
service = "redirect"
[hosts."127.0.0.1:{port}"]
egress = "allow"
[hosts."*"]
egress = "deny"
[agents.bob]
folder = "/fixture/bob"
[agents.bob.services.redirect]
capability = "writer"
token = "{VAULT_NAME}"
[[risk]]
account = "agent"
tactics = ["impact"]
decision = "require_approval"
approval_default = "once"
'''


def _gateway_view(proxy, agent: str) -> dict:
    status, _, body = request(
        proxy.paths[agent], AGENT_API + "/gateway/services",
        headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
    )
    assert status == 200, (agent, status, body)
    return json.loads(body)["authorized"]


def _gateway_probe(proxy, origin, *, service: bool, binding: str | None,
                   grant: bool, prior_token: str | None, step: int) -> dict:
    alice = _gateway_view(proxy, "alice")
    assert ("redirect" in alice) == service
    bob = _gateway_view(proxy, "bob")
    assert bob["redirect"]["capability"] == "writer"
    port = origin.server_address[1]
    before = origin.accepts
    plain = request(proxy.paths["bob"], f"http://127.0.0.1:{port}/plain-{step}")
    assert plain[0] == 200
    assert origin.accepts == before + 1
    statuses = {"bob:plain": plain[0]}
    before = origin.accepts
    status, _, body = request(
        proxy.paths["bob"], f"http://127.0.0.1:{port}/v1/private",
        headers={"Authorization": f"Bearer {bob['redirect']['token']}"},
    )
    assert status == 200, body
    assert origin.accepts == before + 1
    assert _authorization(_wire(origin.requests[-1])) == [
        f"Bearer {VAULT_CREDENTIAL}".encode()
    ]
    statuses["bob:service"] = status
    if not service and prior_token:
        before = origin.accepts
        status, _, _ = request(
            proxy.paths["alice"], f"http://127.0.0.1:{port}/v1/items?account=alpha",
            headers={"Authorization": f"Bearer {prior_token}"},
        )
        assert status == 403 and origin.accepts == before
        statuses["alice:revoked-token"] = status
    if service:
        token = alice["redirect"]["token"]
        assert token.startswith("sgw_")
        for account in ("alpha", "beta"):
            before = origin.accepts
            status, _, body = request(
                proxy.paths["alice"], f"http://127.0.0.1:{port}/v1/items?account={account}",
                headers={"Authorization": f"Bearer {token}"},
            )
            expected = (200 if grant else 428) if binding == account else 403
            assert status == expected, (account, binding, status, body)
            assert origin.accepts == before + int(expected == 200)
            if expected == 200:
                assert _authorization(_wire(origin.requests[-1])) == [
                    f"Bearer {VAULT_CREDENTIAL}".encode()
                ]
            statuses[f"alice:{account}"] = status
        before = origin.accepts
        status, _, _ = request(
            proxy.paths["bob"], f"http://127.0.0.1:{port}/v1/items?account=alpha",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert status == 403 and origin.accepts == before
        statuses["bob:gateway"] = status
    return statuses


def execute_gateway_trace(directory: Path, trace: dict) -> dict:
    """Replay agent-store, service and binding writes against one native state."""
    operations = trace.get("operations")
    if not isinstance(operations, list) or not 1 <= len(operations) <= 8:
        raise ValueError("Gateway trace requires one to eight operations")
    directory.mkdir(parents=True)
    _fixture_state(directory)
    (directory / "services/redirect.yaml").write_text(RISKY_CONTRACT_SERVICE)
    token_file = directory / "operator-token"
    token_file.write_text("gateway-history-operator\n")
    policy = directory / "policy.toml"
    steps = []
    trace["observed_steps"] = steps
    service = False
    binding = None
    grant_id = None
    prior_token = None
    with _origin("127.0.0.1") as origin:
        port = origin.server_address[1]
        policy.write_text(_gateway_policy(port))
        with policy_proxy(
            "rust", directory, None, agent_api=True, admin_port=0,
            admin_api_token_file=token_file,
            gateway_services_dir=directory / "services",
            gateway_builtin_services_dir=directory / "builtin",
            network_guard_enabled=True, network_guard_block=True,
        ) as proxy:
            api = _admin(proxy, token_file)
            _gateway_probe(
                proxy, origin, service=False, binding=None,
                grant=False, prior_token=None, step=0,
            )
            for index, operation in enumerate(operations, 1):
                before = proxy.readiness_file.stat()
                marker = before.st_ino, before.st_mtime_ns
                action = operation["action"]
                audit_count = len(_audit(directory))
                with patch.dict(os.environ, {"SAFEYOLO_CONFIG_DIR": str(directory)}):
                    if action == "save-agent":
                        save_agent("alice", {"folder": "/fixture/alice", "agent_id": "ag-fixture-alice"})
                        result = "saved"
                    elif action == "remove-agent":
                        assert remove_agent("alice")
                        result = "removed"
                        service = False
                        binding = None
                    elif action == "authorize-service":
                        result = api.authorize_service("alice", "redirect", "reader", VAULT_NAME)
                        assert result["status"] in {"authorized", "ok"}
                        service = True
                    elif action == "revoke-service":
                        result = api.revoke_service("alice", "redirect")
                        assert result["status"] == "revoked"
                        service = False
                    elif action == "add-binding":
                        value = operation["account"]
                        result = api.approve_contract_binding(
                            "alice", "redirect", "reader", "redirect.reader.v1",
                            {"account": value}, ["list_items"],
                        )
                        assert result["status"] == "bound"
                        binding = value
                    elif action == "remove-binding":
                        changed, _ = mutate_agent(
                            "alice", lambda metadata: metadata.pop("contract_bindings")
                        )
                        assert changed
                        result = "removed"
                        binding = None
                    elif action == "add-grant":
                        result = api.add_gateway_grant(
                            "alice", "redirect", "GET", "/v1/items", "session"
                        )
                        assert result["status"] == "granted"
                        grant_id = result["grant_id"]
                    elif action == "revoke-grant":
                        assert grant_id is not None
                        result = api.revoke_gateway_grant(grant_id)
                        assert result["status"] == "revoked"
                        grant_id = None
                    elif action == "reload":
                        result = "reload"
                    else:
                        raise ValueError(f"Unsupported gateway operation: {action}")
                    metadata = load_agent("alice")
                audit_event = {
                    "authorize-service": "admin.agent_service_authorized",
                    "revoke-service": "admin.agent_service_revoked",
                    "add-binding": "admin.contract_binding_approved",
                    "add-grant": "admin.gateway_grant",
                    "revoke-grant": "admin.gateway_grant_revoked",
                }.get(action)
                if audit_event:
                    _wait_for_audit(directory, audit_count, audit_event)
                step = {"operation": operation, "result": result}
                steps.append(step)
                _converge(proxy, marker)
                statuses = _gateway_probe(
                    proxy, origin, service=service, binding=binding,
                    grant=grant_id is not None, prior_token=prior_token, step=index,
                )
                if service:
                    prior_token = _gateway_view(proxy, "alice")["redirect"]["token"]
                source = policy.read_text()
                document = tomllib.loads(source)
                assert "# retain unrelated gateway note" in source
                assert document["description"] == "service binding history fixture"
                assert document["agents"]["bob"] == {
                    "folder": "/fixture/bob",
                    "services": {"redirect": {"capability": "writer", "token": VAULT_NAME}},
                }
                assert ("alice" in document["agents"]) == bool(metadata)
                if metadata:
                    assert metadata["folder"] == "/fixture/alice"
                    assert metadata["agent_id"] == "ag-fixture-alice"
                if service:
                    assert metadata["services"]["redirect"]["capability"] == "reader"
                grants = api.list_gateway_grants()["grants"]
                assert (grant_id in {row["grant_id"] for row in grants}) == (grant_id is not None)
                assert not _residue(directory)
                step.update({
                    "statuses": statuses,
                    "alice_services": sorted(metadata.get("services", {})),
                    "alice_bindings": [item.get("bound_values") for item in metadata.get("contract_bindings", [])],
                    "active_grant": grant_id is not None,
                    "audit_events": [row["event"] for row in _audit(directory)
                                     if row["event"].startswith("admin.")],
                    "temporary_residue": _residue(directory),
                })
        final = policy.read_bytes()
        with policy_proxy(
            "rust", directory, None, agent_api=True, admin_port=0,
            admin_api_token_file=token_file,
            gateway_services_dir=directory / "services",
            gateway_builtin_services_dir=directory / "builtin",
            network_guard_enabled=True, network_guard_block=True,
        ) as fresh:
            assert policy.read_bytes() == final
            _gateway_probe(
                fresh, origin, service=service, binding=binding,
                grant=grant_id is not None, prior_token=prior_token, step=len(steps) + 1,
            )
    return {"operations": len(steps), "steps": steps, "fresh_matches": True}


def _generated_run(trace: dict, execute) -> None:
    try:
        with tempfile.TemporaryDirectory(prefix="sy-state-chaos-", dir=Path.home()) as temporary:
            execute(Path(temporary) / "state-chaos", trace)
    except Exception as error:
        trace["failure"] = {"type": type(error).__name__, "message": str(error)}
        trace_dir = Path(os.environ.get(
            "SAFEYOLO_CHAOS_TRACE_DIR", str(Path.home() / ".local/state/safeyolo/state-chaos-traces")
        ))
        trace_dir.mkdir(parents=True, exist_ok=True)
        trace_file = trace_dir / f"failing-{trace['family']}-{uuid.uuid4().hex}.json"
        trace_file.write_text(json.dumps(trace, ensure_ascii=False, indent=2) + "\n")
        binary = Path(os.environ.get(
            "SAFEYOLO_RUST_PROXY", "proxy/target/debug/safeyolo-proxy"
        )).resolve()
        print(f"Replay: {shlex.quote(sys.executable)} -m tools.policy_chaos replay "
              f"{shlex.quote(str(trace_file))} --binary {shlex.quote(str(binary))}")
        raise


@SEQUENCE_SETTINGS
@given(secondary=st.sampled_from(((HOSTS[1], KEYS[0]), (HOSTS[0], KEYS[1]))),
       order=st.permutations(("secondary", "deny", "reload")))
def test_credential_approval_histories(secondary, order) -> None:
    """Approval, denial, reload and revocation preserve exact host/credential scope."""
    named = {
        "secondary": {"action": "approve", "host": secondary[0], "key": secondary[1]},
        "deny": {"action": "deny", "host": HOSTS[1], "key": KEYS[2]},
        "reload": {"action": "reload"},
    }
    _generated_run({
        "family": "credential", "operations": [
            {"action": "approve", "host": HOSTS[0], "key": KEYS[0]},
            *(named[name] for name in order),
            {"action": "revoke", "host": HOSTS[0]},
            {"action": "reapprove", "host": HOSTS[0], "key": KEYS[0]},
        ],
    }, execute_credential_trace)


@SEQUENCE_SETTINGS
@given(account=st.sampled_from(("alpha", "beta")),
       add_order=st.permutations(("authorize-service", "add-binding")),
       remove_order=st.permutations(("revoke-service", "remove-binding")))
def test_agent_service_binding_histories(account, add_order, remove_order) -> None:
    """Retained agent-store and Admin writers compose through live and fresh Rust."""
    operations = [{"action": "save-agent"}]
    operations += [{"action": action, "account": account} for action in add_order]
    operations.append({"action": "add-grant"})
    operations.append({"action": "revoke-grant"})
    operations += [{"action": action} for action in remove_order]
    operations.append({"action": "remove-agent"})
    _generated_run({"family": "gateway", "operations": operations}, execute_gateway_trace)
