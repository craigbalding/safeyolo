"""Retained operator-client approval workflow against the native Rust proxy.

The request travels through the selected Rust executable and a real trusted
agent Unix socket.  The operator side uses the existing Python ``AdminAPI``
and ``operator_approvals`` client code; the test does not call the Rust
handler directly or manufacture a pending approval event.
"""

from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from safeyolo.api import AdminAPI
from safeyolo.operator_approvals import approve, deny
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
                         agent: str | None = None, port: int | None = None,
                         credential: str | None = None) -> bool:
    for permission in document["baseline"]["permissions"]:
        if permission.get("action") != action or permission.get("resource") != resource:
            continue
        if effect is not None and permission.get("effect") != effect:
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
            changed = _wait_for_native_state(
                api,
                event["request_id"],
                lambda document: _compiled_permission(
                    document,
                    action="network:request",
                    resource="127.0.0.1/*",
                    effect="allow",
                    agent="alice",
                    port=port,
                ),
            )
            assert _compiled_permission(
                changed,
                action="network:request",
                resource="127.0.0.1/*",
                effect="allow",
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
