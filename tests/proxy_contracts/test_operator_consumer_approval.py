"""Retained operator-client approval workflow against the native Rust proxy.

The request travels through the selected Rust executable and a real trusted
agent Unix socket.  The operator side uses the existing Python ``AdminAPI``
and ``operator_approvals`` client code; the test does not call the Rust
handler directly or manufacture a pending approval event.
"""

from __future__ import annotations

import json
import os
import threading
import time
import tomllib
from contextlib import contextmanager
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from safeyolo.api import AdminAPI, APIError
from safeyolo.operator_approvals import ApprovalActionError, approve, deny
from tests.blackbox import access_setup, installed_access
from tests.blackbox.native_credentials import native_cli, store_credential
from tests.proxy_contracts.harness import REPO
from tests.proxy_contracts.harness import request as send_request
from tests.proxy_contracts.scenarios import origin_server
from tests.proxy_contracts.test_native_network_policy import policy_proxy
from tests.proxy_contracts.test_native_policy_cli import AGENT_TOKEN

PROMPT_POLICY = """
budget = 12000
[hosts]
"*" = { egress = "prompt" }
[agents.alice]
egress = "prompt"
[agents.bob]
egress = "prompt"
"""


CREDENTIAL_POLICY = """
budget = 12000
[hosts]
"*" = { egress = "allow" }
[[permissions]]
action = "credential:use"
resource = "*"
effect = "prompt"
[[credential_rules]]
name = "synthetic"
patterns = ["key-[a-z]+"]
allowed_hosts = ["127.0.0.1", "localhost"]
header_names = ["authorization"]
[addons.credential_guard]
enabled = true
[addons.credential_guard.settings]
use_default_credential_rules = false
"""


class _CredentialOrigin(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        self.accepts = 0
        self.authorization = []
        self.bodies = []
        super().__init__(("127.0.0.1", 0), _CredentialOriginHandler)

    def get_request(self):
        result = super().get_request()
        self.accepts += 1
        return result


class _CredentialOriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.server.authorization.append(self.headers.get("Authorization"))
        self.send_response(200)
        self.send_header("Content-Length", "5")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"hello")

    def do_POST(self):
        self.server.bodies.append(self.rfile.read(int(self.headers["Content-Length"])))
        self.do_GET()


@contextmanager
def _credential_origin():
    origin = _CredentialOrigin()
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    try:
        yield origin
    finally:
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


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


def _compiled_permission(document: dict, *, action: str, resource: str, effect: str | None = None,
                         budget: int | None = None, agent: str | None = None,
                         port: int | None = None, credential: str | None = None) -> bool:
    for permission in document["baseline"]["permissions"]:
        if permission.get("action") != action or permission.get("resource") != resource:
            continue
        if effect is not None and permission.get("effect") != effect:
            continue
        if budget is not None and permission.get("budget") != budget:
            continue
        condition = permission.get("condition") or {}
        if agent is not None and condition.get("agent") != agent:
            continue
        if port is not None and condition.get("port") != port:
            continue
        if credential is not None and credential not in condition.get("credential", []):
            continue
        return True
    return False


def _wait_for_native_state(api: AdminAPI, request_id: str, predicate) -> dict:
    """Wait until the watcher has published policy and resolved this prompt."""
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        pending = api.pending_approvals()
        baseline = api.get_policy("baseline")
        if not any(row.get("request_id") == request_id for row in pending) and predicate(baseline):
            return baseline
        time.sleep(0.02)
    raise AssertionError(f"native watcher did not publish/resolved request {request_id}")


def _audit_rows(directory):
    audit = directory / "audit.jsonl"
    return [json.loads(line) for line in audit.read_text().splitlines() if line]


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

            # This standalone proxy has no installed Command Centre host
            # identity. Approval reads and decisions remain available here.
            with pytest.raises(APIError) as error:
                api.instance()
            assert error.value.status_code == 503
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
            changed = _wait_for_native_state(
                api,
                event["request_id"],
                lambda document: _compiled_permission(
                    document,
                    action="network:request",
                    resource="127.0.0.1/*",
                    effect="budget",
                    budget=600,
                    agent="alice",
                    port=port,
                ),
            )
            assert _compiled_permission(
                changed,
                action="network:request",
                resource="127.0.0.1/*",
                effect="budget",
                budget=600,
                agent="alice",
                port=port,
            )
            audit = _audit_rows(directory)
            allowed = [row for row in audit if row.get("event") == "admin.host_allowed"]
            assert any(
                row.get("details", {}).get("host") == "127.0.0.1"
                and row["details"].get("agent") == "alice"
                and row["details"].get("port") == port
                for row in allowed
            )

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


def test_retained_operator_client_approves_and_denies_native_credentials(tmp_path):
    """The retained client can resolve both credential approval outcomes."""
    token_file = tmp_path / "operator-token"
    token_file.write_text("operator-credential-workflow\n")
    directory = tmp_path / "native-credential"

    with _credential_origin() as origin:
        with policy_proxy(
            "rust",
            directory,
            CREDENTIAL_POLICY,
            admin_port=0,
            admin_api_token_file=token_file,
        ) as proxy:
            api = _admin_client(proxy, token_file)
            port = origin.server_address[1]
            target = f"http://127.0.0.1:{port}/credential-approval"

            status, _, body = send_request(
                proxy.paths["alice"],
                target,
                headers={"Authorization": "Bearer key-approve"},
            )
            assert status == 428, body
            assert origin.accepts == 0
            pending = _pending(api)
            approved_event = next(row for row in pending if row.get("agent") == "alice")
            assert approved_event["event"] == "security.credential_guard"
            assert approved_event["decision"] == "require_approval"
            assert approved_event["approval"]["approval_type"] == "credential"
            fingerprint = approved_event["approval"]["key"]
            assert fingerprint.startswith("hmac:")
            assert approved_event["host"] == "127.0.0.1"

            assert approve(approved_event, api) == "added"
            changed = _wait_for_native_state(
                api,
                approved_event["request_id"],
                lambda document: _compiled_permission(
                    document,
                    action="credential:use",
                    resource="127.0.0.1/*",
                    credential=fingerprint,
                ),
            )
            assert _compiled_permission(
                changed,
                action="credential:use",
                resource="127.0.0.1/*",
                credential=fingerprint,
            )
            audit = _audit_rows(directory)
            added = [row for row in audit if row.get("event") == "admin.approval_added"]
            assert any(
                row.get("details", {}).get("destination") == "127.0.0.1"
                and fingerprint in (
                    [row["details"].get("cred_id")]
                    if isinstance(row["details"].get("cred_id"), str)
                    else row["details"].get("cred_id", [])
                )
                for row in added
            )

            status, _, body = send_request(
                proxy.paths["alice"],
                target,
                headers={"Authorization": "Bearer key-approve"},
            )
            assert status == 200 and body == b"hello"
            assert origin.authorization == ["Bearer key-approve"]

            # The durable approval is destination and fingerprint specific.
            status, _, body = send_request(
                proxy.paths["alice"],
                f"http://localhost:{port}/different-host",
                headers={"Authorization": "Bearer key-approve"},
            )
            assert status == 428, body
            assert origin.accepts == 1
            status, _, body = send_request(
                proxy.paths["alice"],
                target,
                headers={"Authorization": "Bearer key-other"},
            )
            assert status == 428, body
            assert origin.accepts == 1

            existing_pending_ids = {row.get("request_id") for row in api.pending_approvals()}
            status, _, body = send_request(
                proxy.paths["alice"],
                target,
                headers={"Authorization": "Bearer key-deny"},
            )
            assert status == 428, body
            denied_event = next(
                row
                for row in _pending(api)
                if row.get("request_id") not in existing_pending_ids
            )
            assert denied_event["approval"]["approval_type"] == "credential"
            denied_fingerprint = denied_event["approval"]["key"]
            deny(denied_event, api)
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline:
                if not any(row.get("request_id") == denied_event["request_id"] for row in api.pending_approvals()):
                    break
                time.sleep(0.02)
            else:
                raise AssertionError("native watcher retained a denied credential approval")
            audit = _audit_rows(directory)
            denials = [row for row in audit if row.get("event") == "admin.denial"]
            assert any(
                row.get("details", {}).get("approval_request_id") == denied_event["request_id"]
                and row["details"].get("destination") == "127.0.0.1"
                and row["details"].get("cred_id") == denied_fingerprint
                for row in denials
            )

            # A denied retry remains blocked and does not reach the origin.
            status, _, body = send_request(
                proxy.paths["alice"],
                target,
                headers={"Authorization": "Bearer key-deny"},
            )
            assert status == 428, body
            assert origin.accepts == 1
            assert not any(row.get("request_id") == denied_event["request_id"] for row in api.pending_approvals())


@pytest.fixture
def native_access(tmp_path):
    """Use the installed access definitions with local origins and native state."""
    services = {
        "basic.yaml": access_setup.BASIC.replace("legitimate-api.com", "127.0.0.1"),
        "contract.yaml": access_setup.CONTRACT.replace("httpbin.org", "localhost"),
        "other.yaml": access_setup.BASIC.replace("legitimate-api.com", "127.0.0.1").replace("p3_basic", "p3_other"),
    }
    policy = '''budget = 12000
[hosts."127.0.0.1"]
egress = "allow"
service = "p3_basic"
allow = ["unknown:*"]
[hosts.localhost]
egress = "allow"
service = "p3_contract"
allow = ["unknown:*"]
[hosts."*"]
egress = "deny"
[agents.alice]
agent_id = "ag-11111111111111111111111111111111"
[agents.bob]
agent_id = "ag-22222222222222222222222222222222"
[[risk]]
account = "agent"
tactics = ["impact"]
decision = "require_approval"
approval_default = "once"
'''
    directory = tmp_path / "native"
    service_dir, builtin = directory / "services", directory / "builtin-services"
    for path in (service_dir, builtin):
        path.mkdir(parents=True)
    for name, source in services.items():
        (service_dir / name).write_text(source)
    proxy_binary = Path(os.environ.get("SAFEYOLO_RUST_PROXY", REPO / "proxy/target/release/safeyolo-proxy"))
    binary = native_cli(Path(os.environ.get("SAFEYOLO_NATIVE_CLI", proxy_binary.with_name("safeyolo"))), proxy=proxy_binary)
    for name, value in (("p3-owned", "synthetic-selected-secret"), ("p3-other", "synthetic-other-secret")):
        store_credential(directory / "data", name, value, binary=binary)
    operator_token = directory / "operator-token"
    operator_token.write_text("synthetic-access-admin-token")
    with _credential_origin() as origin, policy_proxy(
        "rust", directory, policy, native_product=True,
        gateway_services_dir=service_dir, gateway_builtin_services_dir=builtin,
        target_ip_mappings=[{"host": "localhost", "ip": "127.0.0.1"}],
        agent_api=True, agent_api_token=AGENT_TOKEN.encode(), admin_port=0, admin_api_token_file=operator_token,
    ) as instance:
        api = _admin_client(instance, operator_token)
        yield instance, api, origin


def _access_request(instance, agent, service, *, bindings=None):
    """Retain the actual request ID from the native Agent API response."""
    payload = {"service": service, "capability": "writer" if bindings else "reader"}
    route = "/gateway/request-access"
    if bindings:
        route = "/gateway/submit-binding"
        payload.update(bindings=bindings, purpose_code="write")
    status, headers, body = send_request(
        instance.paths[agent], "http://_safeyolo.proxy.internal" + route,
        method="POST", body=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {AGENT_TOKEN}", "Content-Type": "application/json"},
    )
    assert status == 202, body
    return headers["x-safeyolo-request-id"]


def _refuse_changed_gateway_scope(instance, api, event):
    """A stale or incomplete selected row cannot authorize a different scope."""
    changes = [((), key, None) for key in ("approval_id", "action")]
    changes += [((), "agent", value) for value in (None, "bob")]
    changes += [((), "request_id", value) for value in (None, "req-" + "0" * 32)]
    changes += [(("action",), key, value)
                for key in ("agent", "agent_id", "service", "capability")
                for value in (None, "other")]
    changes += [(("action",), key, "changed")
                for key in ("host", "template", "bindings", "grantable_operations", "credential", "binding_id", "method", "path")
                if key in event["action"]]
    policy = instance.audit_log.parent / "policy.toml"
    before = policy.read_bytes()
    for path, key, value in changes:
        changed = deepcopy(event)
        selected = changed
        for part in path:
            selected = selected[part]
        if value is None:
            selected.pop(key)
        else:
            selected[key] = value
        with pytest.raises(ApprovalActionError):
            approve(changed, api, service_credential="p3-owned")
        assert api.approval(event["approval_id"])["status"] == "pending"
        assert policy.read_bytes() == before


def _access_token(instance, service):
    status, _, raw = send_request(instance.paths["alice"], "http://_safeyolo.proxy.internal/gateway/services",
                                  headers={"Authorization": f"Bearer {AGENT_TOKEN}"})
    assert status == 200
    return json.loads(raw)["authorized"][service]["token"]


def test_installed_access_approves_exact_canonical_service(native_access, monkeypatch):
    """Discovery, credential choice and effect retain service/agent/request scope."""
    instance, api, origin = native_access
    peer_id = _access_request(instance, "bob", "p3_basic")
    other_id = _access_request(instance, "alice", "p3_other")
    request_id = _access_request(instance, "alice", "p3_basic")
    event = installed_access.wait_for_approval(api, "service", agent="alice", service="p3_basic", request_id=request_id)
    assert event["approval"]["target"] == "127.0.0.1"
    assert "capability" not in event["approval"]["scope_hint"]
    assert event["action"]["capability"] == "reader"
    _refuse_changed_gateway_scope(instance, api, event)
    for credential in (None, "missing-credential"):
        with pytest.raises(ApprovalActionError, match="does not offer"):
            approve(event, api, service_credential=credential)
    for scope in ({"agent": "missing"}, {"service": "missing"}, {"request_id": "missing"}):
        with monkeypatch.context() as patch:
            ticks = iter((0, 0, 8))
            patch.setattr(installed_access, "time", SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda _: None))
            with pytest.raises(AssertionError, match="observed="):
                installed_access.wait_for_approval(api, "service", **({"agent": "alice", "service": "p3_basic", "request_id": request_id} | scope))
    peer = installed_access.wait_for_approval(api, "service", agent="bob", service="p3_basic", request_id=peer_id)
    changed = event | {"approval_id": peer["approval_id"]}
    with pytest.raises(ApprovalActionError, match="no longer matches"):
        approve(changed, api, service_credential="p3-owned")
    assert origin.accepts == 0
    installed_access.approve_service(api, "alice", "p3_basic", "p3-owned", request_id=request_id)
    resolved = api.approval(event["approval_id"])
    assert resolved["status"] == "approved" and resolved["option"] == "credential:p3-owned"
    saved = tomllib.loads((instance.audit_log.parent / "policy.toml").read_text())
    assert saved["agents"]["alice"]["services"]["p3_basic"]["token"] == "p3-owned"
    assert set(saved["agents"]["alice"]["services"]) == {"p3_basic"}
    assert "services" not in saved["agents"]["bob"]
    assert api.approval(peer_id)["status"] == "pending"
    assert api.approval(other_id)["status"] != "approved"
    token = _access_token(instance, "p3_basic")
    target = f"http://127.0.0.1:{origin.server_address[1]}/p3/read"
    for agent, path, expected in (("bob", target, 403), ("alice", target + "/outside", 403), ("alice", target, 200)):
        status, _, _ = send_request(instance.paths[agent], path, headers={"Authorization": f"Bearer {token}"})
        assert status == expected
    assert origin.authorization == ["Bearer synthetic-selected-secret"]
    assert origin.accepts == 1
    with pytest.raises((ApprovalActionError, APIError)):
        approve(event, api, service_credential="p3-other")
    assert tomllib.loads((instance.audit_log.parent / "policy.toml").read_text()) == saved


def test_installed_access_approves_canonical_binding_and_once_effect(native_access):
    """The native binding values and one risky operation survive the caller path."""
    instance, api, origin = native_access
    for agent, project in (("bob", "alpha"), ("alice", "beta")):
        _access_request(instance, agent, "p3_contract", bindings={"project": project, "ticket": "T-1"})
    request_id = _access_request(instance, "alice", "p3_contract", bindings={"project": "alpha", "ticket": "T-1"})
    event = installed_access.wait_for_approval(api, "contract_binding", agent="alice", service="p3_contract", request_id=request_id)
    assert event["approval"]["target"] == "localhost"
    assert event["action"]["bindings"] == {"project": "alpha", "ticket": "T-1"}
    assert event["action"]["template"] == "p3.write.v1" and event["action"]["grantable_operations"] == ["write"]
    _refuse_changed_gateway_scope(instance, api, event)
    assert approve(event, api) == "bound"
    saved = tomllib.loads((instance.audit_log.parent / "policy.toml").read_text())
    binding, = saved["agents"]["alice"]["contract_bindings"]
    assert binding["bound_values"] == {"project": "alpha", "ticket": "T-1"}
    assert binding["capability"] == "writer" and binding["grantable_operations"] == ["write"]
    assert "contract_bindings" not in saved["agents"]["bob"]
    assert api.authorize_service("alice", "p3_contract", "writer", "p3-owned")["status"] == "authorized"
    token = _access_token(instance, "p3_contract")
    target = f"http://localhost:{origin.server_address[1]}/p3/write?ticket=T-1"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = json.dumps({"project": "alpha"}).encode()
    status, response_headers, _ = send_request(instance.paths["alice"], target, method="POST", headers=headers, body=payload)
    assert status == 428 and origin.accepts == 0
    risk = installed_access.wait_for_approval(api, "gateway_risky_route", agent="alice", service="p3_contract",
                                             request_id=response_headers["x-safeyolo-request-id"])
    assert risk["action"]["binding_id"] == binding["binding_id"] and risk["action"]["credential"] == "p3-owned"
    _refuse_changed_gateway_scope(instance, api, risk)
    grant_id = approve(risk, api)
    # The installed guest also reads its token after the operator's policy edit.
    headers["Authorization"] = f"Bearer {_access_token(instance, 'p3_contract')}"
    for agent, url, body in (("bob", target, payload), ("alice", target.replace("T-1", "T-2"), payload),
                             ("alice", target, json.dumps({"project": "beta"}).encode())):
        status, _, _ = send_request(instance.paths[agent], url, method="POST", headers=headers, body=body)
        assert status == 403
    assert origin.accepts == 0
    status, _, body = send_request(instance.paths["alice"], target, method="POST", headers=headers, body=payload)
    assert status == 200 and body == b"hello", (status, body)
    assert origin.authorization == ["Bearer synthetic-selected-secret"]
    assert [json.loads(body) for body in origin.bodies] == [{"project": "alpha"}]
    assert all(row.get("grant_id") != grant_id for row in api.list_gateway_grants()["grants"])
    status, _, _ = send_request(instance.paths["alice"], target, method="POST", headers=headers, body=payload)
    assert status == 428 and origin.accepts == 1


@pytest.mark.parametrize("approval_type", ["service", "contract_binding"])
def test_installed_access_rejects_exact_canonical_request(native_access, approval_type):
    """Rejection ends the selected approval without authorizing or binding it."""
    instance, api, origin = native_access
    service = "p3_basic" if approval_type == "service" else "p3_contract"
    bindings = None if approval_type == "service" else {"project": "alpha", "ticket": "T-1"}
    request_id = _access_request(instance, "alice", service, bindings=bindings)
    event = installed_access.wait_for_approval(api, approval_type, agent="alice", service=service, request_id=request_id)
    policy = instance.audit_log.parent / "policy.toml"
    before = policy.read_bytes()
    deny(event, api)
    assert api.approval(event["approval_id"])["status"] == "rejected"
    assert policy.read_bytes() == before and origin.accepts == 0
