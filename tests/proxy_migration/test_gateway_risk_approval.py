"""Running service-gateway approval and once-grant contract on both proxies."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from safeyolo.api import AdminAPI
from safeyolo.core.vault import Vault, VaultCredential
from safeyolo.operator_approvals import approve
from tests.proxy_migration.harness import read_events, request
from tests.proxy_migration.test_native_network_policy import policy_proxy

AGENT_TOKEN = "fixture-gateway-agent-token"
VAULT_VALUE = "fixture-vault-credential"
VAULT_NAME = "fixture-gateway-secret"
SERVICE = "fixture_gateway"
RISK_PATH = "/v1/operate"
_WIRE_LOG_LOCK = threading.Lock()
SERVICE_YAML = f"""\
schema_version: 1
name: {SERVICE}
default_host: 127.0.0.1
auth:
  type: bearer
  header: Authorization
  scheme: Bearer
  allow_http: true
capabilities:
  operator:
    description: Read status and run one approved operation
    routes:
      - methods: [GET]
        path: /v1/status
      - methods: [POST]
        path: {RISK_PATH}
risky_routes:
  - path: {RISK_PATH}
    methods: [POST]
    tactics: [impact]
    description: Runs the synthetic operation
"""


class _Origin(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        self.deliveries = []
        self.accepts = 0
        self.first_post = threading.Event()
        self.release_post = threading.Event()
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), _OriginHandler)

    def get_request(self):
        result = super().get_request()
        with self.lock:
            self.accepts += 1
        return result


class _OriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def do_GET(self):
        self._reply()

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self._reply()

    def _reply(self):
        raw_head = self.raw_requestline + self.headers.as_bytes()
        with self.server.lock:
            self.server.deliveries.append({
                "method": self.command,
                "path": self.path,
                "wire_head_sha256": hashlib.sha256(raw_head).hexdigest(),
                "wire_head_redacted": self.raw_requestline.decode("ascii").strip(),
                "authorization_is_vaulted": self.headers.get("Authorization") == f"Bearer {VAULT_VALUE}",
                "gateway_token_absent": all(
                    "sgw_" not in value
                    for value in self.headers.values()
                ),
            })
        if self.command == "POST":
            self.server.first_post.set()
            assert self.server.release_post.wait(5), "held origin was not released"
        body = b"done" if self.command == "POST" else b"status"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


@contextmanager
def _origin():
    server = _Origin()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.release_post.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def _agent_request(proxy, agent, path, token, *, method="GET"):
    result = request(
        proxy.paths[agent],
        f"http://127.0.0.1:{path[0]}{path[1]}",
        method=method,
        headers={"Authorization": f"Bearer {token}"},
        body=b"operation" if method == "POST" else None,
    )
    status, headers, body = result
    assert b"sgw_" not in body
    assert all("sgw_" not in value for value in headers.values())
    with _WIRE_LOG_LOCK, (proxy.event_log.parent / "gateway-wire.jsonl").open("a") as output:
        output.write(json.dumps({
            "trusted_agent": agent, "method": method,
            "logical_host": "127.0.0.1", "logical_port": path[0], "path": path[1],
            "gateway_token_sha256": hashlib.sha256(token.encode()).hexdigest(),
            "request_body_hex": "6f7065726174696f6e" if method == "POST" else "",
            "response_status": status, "response_headers": headers,
            "response_body_hex": body.hex(),
        }) + "\n")
    return result


def _wait_for(predicate, description):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.025)
    raise AssertionError(f"Timed out waiting for {description}")


def _gateway_token(proxy):
    def read():
        status, _, body = request(
            proxy.paths["alice"],
            "http://_safeyolo.proxy.internal/gateway/services",
            headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
        )
        if status != 200:
            return None
        return json.loads(body).get("authorized", {}).get(SERVICE, {}).get("token")

    token = _wait_for(read, "authorized gateway token")
    assert token.startswith("sgw_")
    return token


def test_running_gateway_risk_approval_and_once_grant(proxy_backend, tmp_path):
    """A real operator approval allows one effect, even with an overlapping retry."""
    directory = tmp_path / proxy_backend
    directory.mkdir()
    services = directory / "services"
    builtin = directory / "builtin"
    services.mkdir()
    builtin.mkdir()
    (services / "fixture.yaml").write_text(SERVICE_YAML)
    data = directory / "data"
    data.mkdir()
    (data / "vault.key").write_text("fixture-vault-passphrase")
    vault = Vault(data / "vault.yaml.enc")
    vault.unlock("fixture-vault-passphrase")
    vault.store(VaultCredential(name=VAULT_NAME, type="bearer", value=VAULT_VALUE))
    operator_token_file = directory / "operator-token"
    operator_token_file.write_text("fixture-operator-token\n")

    with _origin() as origin:
        port = origin.server_address[1]
        policy = f"""\
budget = 12000
[hosts."127.0.0.1"]
service = "{SERVICE}"
[hosts."127.0.0.1:{port}"]
egress = "allow"
[hosts."*"]
egress = "deny"
[agents.alice]
[agents.bob]
[addons.credential_guard]
enabled = true
detection_level = "none"
[addons.credential_guard.settings]
use_default_credential_rules = false
[addons.credential_guard.settings.entropy]
min_length = 1000
[[risk]]
account = "agent"
tactics = ["impact"]
decision = "require_approval"
approval_default = "once"
"""
        with policy_proxy(
            proxy_backend, directory, policy, agent_api=True,
            agent_api_token=AGENT_TOKEN.encode(), admin_port=0,
            admin_api_token_file=operator_token_file,
            gateway_services_dir=services,
            gateway_builtin_services_dir=builtin,
        ) as proxy:
            marker = json.loads(proxy.readiness_file.read_text())
            api = AdminAPI(base_url=f"http://127.0.0.1:{marker['admin_port']}",
                           token=operator_token_file.read_text().strip())
            assert api.authorize_service("alice", SERVICE, "operator", VAULT_NAME)["status"] in {
                "authorized", "ok",
            }
            gateway_token = _gateway_token(proxy)
            destination = (port, RISK_PATH)
            status_path = (port, "/v1/status")

            # A permitted read stays available while the risky operation waits.
            status, _, body = _agent_request(proxy, "alice", status_path, gateway_token)
            assert (status, body) == (200, b"status")
            assert origin.deliveries[-1]["authorization_is_vaulted"]
            assert origin.deliveries[-1]["gateway_token_absent"]

            before = len(origin.deliveries)
            status, _, _ = _agent_request(proxy, "alice", destination, gateway_token, method="POST")
            assert status == 428
            assert len(origin.deliveries) == before
            event = _wait_for(
                lambda: next((row for row in api.pending_approvals()
                              if row.get("approval", {}).get("approval_type") == "gateway_route"
                              and row.get("agent") == "alice"), None),
                "owned risky-route approval request",
            )
            assert event["details"]["service"] == SERVICE
            assert event["details"]["method"] == "POST"
            assert event["details"]["path"] == RISK_PATH
            grant_id = approve(event, api)
            assert isinstance(grant_id, str) and grant_id
            assert any(g["grant_id"] == grant_id and g["scope"] == "once"
                       for g in api.list_gateway_grants()["grants"])

            # Wrong identity and capability path cannot spend Alice's grant.
            status, _, _ = _agent_request(proxy, "bob", destination, gateway_token, method="POST")
            assert status == 403
            status, _, _ = _agent_request(proxy, "alice", (port, "/v1/other"), gateway_token)
            assert status == 403
            assert len(origin.deliveries) == before
            denied_accepts = origin.accepts

            first = {}
            second = {}
            t1 = threading.Thread(target=lambda: first.setdefault(
                "response", _agent_request(proxy, "alice", destination, gateway_token, method="POST")))
            t1.start()
            try:
                assert origin.first_post.wait(5), "approved request never reached owned origin"
                t2 = threading.Thread(target=lambda: second.setdefault(
                    "response", _agent_request(proxy, "alice", destination, gateway_token, method="POST")))
                t2.start()
                try:
                    _wait_for(lambda: second or len(origin.deliveries) > before + 1,
                              "second request decision or second origin delivery")
                finally:
                    origin.release_post.set()
                    t2.join(timeout=5)
                    assert not t2.is_alive()
            finally:
                origin.release_post.set()
                t1.join(timeout=5)
                assert not t1.is_alive()

            assert first["response"][0] == 200
            assert second["response"][0] == 428
            assert len(origin.deliveries) == before + 1
            delivered = origin.deliveries[-1]
            assert delivered["method"] == "POST" and delivered["path"] == RISK_PATH
            assert delivered["wire_head_redacted"] == f"POST {RISK_PATH} HTTP/1.1"
            assert len(delivered["wire_head_sha256"]) == 64
            assert delivered["authorization_is_vaulted"] and delivered["gateway_token_absent"]
            assert all(g["grant_id"] != grant_id for g in api.list_gateway_grants()["grants"])
            status, _, _ = _agent_request(proxy, "alice", destination, gateway_token, method="POST")
            assert status == 428 and len(origin.deliveries) == before + 1
            audit = _wait_for(
                lambda: read_events(directory / "audit.jsonl")
                if any(row.get("event") == "admin.gateway_grant"
                       for row in read_events(directory / "audit.jsonl")) else None,
                "operator grant audit",
            )
            prompts = [row for row in audit if row.get("event") == "gateway.risky_route"]
            assert any(
                row.get("request_id") == event["request_id"]
                and row.get("agent") == "alice"
                and row.get("decision") == "require_approval"
                and (proxy_backend == "python" or row.get("details", {}).get(
                    "attribution", {}).get("evidence_owner") == "alice")
                for row in prompts
            )
            assert any(row.get("event") == "admin.gateway_grant"
                       and row.get("details", {}).get("grant_id") == grant_id for row in audit)
            if proxy_backend == "rust":
                assert any(row.get("event") == "proxy.gateway"
                           and row.get("outcome") == "grant_consumed"
                           and row.get("grant_id") == grant_id
                           for row in read_events(proxy.event_log))
            else:
                assert any(row.get("event") == "gateway.grant_consumed"
                           and row.get("details", {}).get("grant_id") == grant_id for row in audit)
            (directory / "gateway-approval-observations.json").write_text(json.dumps({
                "backend": proxy_backend, "logical_host": "127.0.0.1",
                "dial_host": origin.server_address[0], "dial_port": port,
                "origin_accepts": origin.accepts,
                "denied_stage_origin_accepts": denied_accepts,
                "denied_stage_origin_deliveries": 0,
                "origin_deliveries": origin.deliveries,
                "approval_request_id": event["request_id"], "grant_id": grant_id,
                "first_status": first["response"][0], "second_status": second["response"][0],
                "grant_consumed": True, "post_consumption_status": status,
            }, indent=2) + "\n")
