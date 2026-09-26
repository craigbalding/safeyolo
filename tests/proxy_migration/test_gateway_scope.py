"""Running service-gateway token, route, and bound-query scope on both backends."""

import base64
import json
import time

import pytest

from tests.proxy_migration.harness import launch_proxy, request
from tests.proxy_migration.scenarios import scoped_api
from tests.proxy_migration.test_gateway_redirect import (
    AGENT_API,
    AGENT_TOKEN,
    VAULT_CREDENTIAL,
    VAULT_NAME,
    _authorization,
    _fixture_state,
    _gateway_token,
    _origin,
    _wire,
)

SERVICE = """\
schema_version: 1
name: redirect
default_host: 127.0.0.1
auth:
  type: bearer
  header: Authorization
  scheme: Bearer
  allow_http: true
capabilities:
  reader:
    routes:
      - methods: [GET]
        path: /v1/items
    contract:
      template: redirect.reader.v1
      bindings:
        account:
          source: operator
          type: string
      operations:
        - name: list_items
          request:
            method: GET
            path: /v1/items
            query:
              allow:
                account:
                  equals_var: account
              deny_unknown: true
      enforcement:
        request_shape: enforced
        transport_hygiene: enforced
  writer:
    routes:
      - methods: [GET]
        path: /v1/private
"""


def _policy(port):
    return f'''budget = 12000
[hosts."127.0.0.1"]
service = "redirect"
[hosts."127.0.0.1:{port}"]
egress = "allow"
[hosts."*"]
egress = "deny"
[agents.alice]
[agents.alice.services.redirect]
capability = "reader"
token = "{VAULT_NAME}"
[[agents.alice.contract_bindings]]
service = "redirect"
capability = "reader"
template = "redirect.reader.v1"
bound_values = {{ account = "alpha" }}
grantable_operations = ["list_items"]
[agents.bob]
'''


def test_running_gateway_scope_blocks_unbound_requests_before_origin(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _fixture_state(directory)
    (directory / "services/redirect.yaml").write_text(SERVICE)

    with _origin("127.0.0.1") as origin:
        port = origin.server_address[1]
        base = f"http://127.0.0.1:{port}"
        with launch_proxy(
            proxy_backend, directory, _policy(port), native_policy=True,
            agent_api=True, gateway_services_dir=directory / "services",
            gateway_builtin_services_dir=directory / "builtin",
            network_guard_enabled=True, network_guard_block=True,
        ) as proxy:
            token = _gateway_token(proxy)
            assert token.startswith("sgw_")
            assert len(token) > 12
            valid_headers = {"Authorization": f"Bearer {token}"}

            status, _, body = request(
                proxy.paths["bob"], AGENT_API + "/gateway/services",
                headers={"Authorization": f"Bearer {AGENT_TOKEN}", "X-Agent-Id": "alice"},
            )
            assert status == 200, body
            assert json.loads(body)["authorized"] == {}
            assert token.encode() not in body and VAULT_CREDENTIAL.encode() not in body
            status, _, body = request(
                proxy.paths["alice"], AGENT_API + "/gateway/services",
                headers={"Authorization": "Bearer invalid-agent-token"},
            )
            assert status == 401, body
            assert token.encode() not in body and VAULT_CREDENTIAL.encode() not in body
            assert origin.accepts == 0

            status, _, body = request(
                proxy.paths["alice"], base + "/v1/items?account=alpha",
                headers=valid_headers,
            )
            assert status == 200, body
            assert origin.accepts == len(origin.requests) == 1
            authorized = _wire(origin.requests[0])
            assert _authorization(authorized) == [f"Bearer {VAULT_CREDENTIAL}".encode()]
            assert token.encode() not in authorized

            status, _, body = request(proxy.paths["alice"], base + "/plain")
            assert status == 200, body
            assert origin.accepts == len(origin.requests) == 2
            assert _authorization(_wire(origin.requests[1])) == []

            wrong_token = token[:-1] + ("0" if token[-1] != "0" else "1")
            cases = [
                ("wrong token", "alice", "/v1/items?account=alpha", "GET", wrong_token, {}, "INVALID_TOKEN"),
                ("wrong agent", "bob", "/v1/items?account=alpha", "GET", token,
                 {"X-Agent-Id": "alice", "X-Forwarded-For": "10.0.0.2"}, "AGENT_MISMATCH"),
                ("wrong capability", "alice", "/v1/private?account=alpha", "GET", token, {}, "ROUTE_DENIED"),
                ("wrong method", "alice", "/v1/items?account=alpha", "POST", token, {}, "ROUTE_DENIED"),
                ("wrong path", "alice", "/v1/item?account=alpha", "GET", token, {}, "ROUTE_DENIED"),
                ("path case", "alice", "/V1/items?account=alpha", "GET", token, {}, "ROUTE_DENIED"),
                ("encoded path", "alice", "/v1/%69tems?account=alpha", "GET", token, {}, "TRANSPORT_PATH_TRICK"),
                ("path spelling", "alice", "/v1/items/?account=alpha", "GET", token, {}, "TRANSPORT_PATH_TRICK"),
                ("wrong bound value", "alice", "/v1/items?account=beta", "GET", token, {}, "CONTRACT_VIOLATION"),
                ("bound value case", "alice", "/v1/items?account=Alpha", "GET", token, {}, "CONTRACT_VIOLATION"),
                ("query key case", "alice", "/v1/items?Account=alpha", "GET", token, {}, "CONTRACT_VIOLATION"),
                ("encoded query alias", "alice", "/v1/items?account=alpha&%61ccount=beta", "GET", token, {}, "TRANSPORT_AMBIGUOUS_ENCODING"),
                ("duplicate query key", "alice", "/v1/items?account=alpha&account=beta", "GET", token, {}, "TRANSPORT_AMBIGUOUS_ENCODING"),
            ]
            responses = [body]
            for label, agent, target, method, presented_token, extra_headers, reason in cases:
                headers = {"Authorization": f"Bearer {presented_token}", **extra_headers}
                status, _, body = request(proxy.paths[agent], base + target,
                                          method=method, headers=headers)
                responses.append(body)
                assert status == 403, (label, status, body)
                payload = json.loads(body)
                codes = payload.get("reason_codes", [payload.get("error")])
                assert reason in codes, (label, body)
                assert origin.accepts == len(origin.requests) == 2, label

            # A once-encoded value resolves to the bound value under the
            # supported contract; the constraint is on the decoded value.
            status, _, body = request(proxy.paths["alice"],
                                      base + "/v1/items?account=%61lpha",
                                      headers=valid_headers)
            responses.append(body)
            assert status == 200, body
            assert origin.accepts == len(origin.requests) == 3
            assert _authorization(_wire(origin.requests[2])) == [
                f"Bearer {VAULT_CREDENTIAL}".encode()
            ]
            assert origin.requests[2]["request_target"] == "/v1/items?account=%61lpha"

        for response in responses:
            assert VAULT_CREDENTIAL.encode() not in response
            assert token.encode() not in response
        for name in ("audit.jsonl", "events.jsonl"):
            events = (directory / name).read_bytes()
            assert VAULT_CREDENTIAL.encode() not in events, name
            assert token.encode() not in events, name
        audit_rows = [json.loads(line) for line in (directory / "audit.jsonl").read_text().splitlines()]
        assert sum(row["event"] == "gateway.http_injection_allowed" for row in audit_rows) == 2
        assert sum(row["event"] == "gateway.allow" for row in audit_rows) == 2


@pytest.mark.parametrize("allow_http", [None, False, True], ids=["default", "false", "true"])
def test_running_gateway_plain_http_injection_setting(proxy_backend, tmp_path, allow_http):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _fixture_state(directory)
    setting = "" if allow_http is None else f"  allow_http: {str(allow_http).lower()}\n"
    (directory / "services/redirect.yaml").write_text(
        SERVICE.replace("  allow_http: true\n", setting)
    )

    with _origin("127.0.0.1") as origin:
        port = origin.server_address[1]
        base = f"http://127.0.0.1:{port}"
        with launch_proxy(
            proxy_backend, directory, _policy(port), native_policy=True,
            agent_api=True, gateway_services_dir=directory / "services",
            gateway_builtin_services_dir=directory / "builtin",
            network_guard_enabled=True, network_guard_block=True,
        ) as proxy:
            token = _gateway_token(proxy)
            status, headers, body = request(
                proxy.paths["alice"], base + "/v1/items?account=alpha",
                headers={"Authorization": f"Bearer {token}"},
            )
            if allow_http:
                assert status == 200, body
                assert origin.accepts == len(origin.requests) == 1
                upstream = _wire(origin.requests[0])
                assert _authorization(upstream) == [f"Bearer {VAULT_CREDENTIAL}".encode()]
                assert token.encode() not in upstream
            else:
                assert status == 301, (status, body)
                location = next(value for name, value in headers.items()
                                if name.lower() == "location")
                assert location == f"https://127.0.0.1:{port}/v1/items?account=alpha"
                assert origin.accepts == 0 and origin.requests == []
                assert proxy.events("proxy.egress") == []
            assert token.encode() not in body and VAULT_CREDENTIAL.encode() not in body

        audit_rows = [json.loads(line) for line in (directory / "audit.jsonl").read_text().splitlines()]
        event = "gateway.http_injection_allowed" if allow_http else "gateway.https_redirect"
        assert sum(row["event"] == event for row in audit_rows) == 1
        assert all(row["agent"] == "alice" for row in audit_rows if row["event"] == event)
        for name in ("audit.jsonl", "events.jsonl"):
            routine = (directory / name).read_bytes()
            assert token.encode() not in routine and VAULT_CREDENTIAL.encode() not in routine


def test_gateway_credential_guard_keeps_direct_secrets_at_owned_origin(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _fixture_state(directory)
    (directory / "services/redirect.yaml").write_text(SERVICE)
    unknown = "B7mQ2rV9xC4nT8pL3wF6kH1sD5jY0aZ7qN2eR9vM4uP8"

    with _origin("127.0.0.1") as owned, _origin("127.0.0.2") as untrusted:
        owned_port = owned.server_address[1]
        untrusted_port = untrusted.server_address[1]
        policy = f'''budget = 12000
[hosts."127.0.0.1"]
service = "redirect"
credentials = ["synthetic-gateway-vault:*"]
[hosts."127.0.0.1:{owned_port}"]
egress = "allow"
[hosts."127.0.0.2:{untrusted_port}"]
egress = "allow"
[hosts."*"]
egress = "deny"
[agents.alice]
[agents.alice.services.redirect]
capability = "reader"
token = "{VAULT_NAME}"
[[agents.alice.contract_bindings]]
service = "redirect"
capability = "reader"
template = "redirect.reader.v1"
bound_values = {{ account = "alpha" }}
grantable_operations = ["list_items"]
[agents.bob]
[[credential_rules]]
name = "synthetic-gateway-vault"
patterns = ["{VAULT_CREDENTIAL}"]
allowed_hosts = ["127.0.0.1"]
header_names = ["authorization"]
[addons.credential_guard]
enabled = true
[addons.credential_guard.settings]
use_default_credential_rules = false
'''
        with launch_proxy(
            proxy_backend, directory, policy, native_policy=True,
            agent_api=True, gateway_services_dir=directory / "services",
            gateway_builtin_services_dir=directory / "builtin",
            network_guard_enabled=True, network_guard_block=True,
            credential_head_decision=True,
        ) as proxy:
            token = _gateway_token(proxy)
            status, _, body = request(
                proxy.paths["alice"],
                f"http://127.0.0.1:{owned_port}/v1/items?account=alpha",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert status == 200, body
            assert owned.accepts == len(owned.requests) == 1
            assert _authorization(_wire(owned.requests[0])) == [
                f"Bearer {VAULT_CREDENTIAL}".encode()
            ]

            ordinary_url = f"http://127.0.0.2:{untrusted_port}/ordinary"
            status, _, body = request(proxy.paths["alice"], ordinary_url)
            assert status == 200, body
            assert untrusted.accepts == len(untrusted.requests) == 1
            assert _authorization(_wire(untrusted.requests[0])) == []

            for secret in (VAULT_CREDENTIAL, unknown):
                status, headers, body = request(
                    proxy.paths["alice"], ordinary_url,
                    headers={"Authorization": f"Bearer {secret}"},
                )
                assert status in (403, 428), (secret, status, body)
                assert next(value for name, value in headers.items()
                            if name.lower() == "x-blocked-by") == "credential-guard"
                assert untrusted.accepts == len(untrusted.requests) == 1
                assert secret.encode() not in body and VAULT_CREDENTIAL.encode() not in body

        assert all(secret.encode() not in _wire(row)
                   for row in untrusted.requests
                   for secret in (token, VAULT_CREDENTIAL, unknown))
        audit = [json.loads(line) for line in (directory / "audit.jsonl").read_text().splitlines()]
        denied = [row for row in audit if row["event"] == "security.credential_guard"
                  and row.get("host") == "127.0.0.2"]
        assert {row["details"]["rule"] for row in denied} == {
            "synthetic-gateway-vault", "unknown_secret",
        }
        assert len(denied) == 2 and all(row["decision"] == "require_approval" for row in denied)
        for name in ("audit.jsonl", "events.jsonl"):
            routine = (directory / name).read_bytes()
            assert all(secret.encode() not in routine
                       for secret in (token, VAULT_CREDENTIAL, unknown))


def test_gateway_capture_keeps_owned_evidence_scoped_and_redacted(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    directory.mkdir()
    _fixture_state(directory)
    (directory / "services/redirect.yaml").write_text(SERVICE)
    with _origin("127.0.0.1") as origin:
        port = origin.server_address[1]
        policy = _policy(port) + '''
[addons.test_context]
target_hosts = ["127.0.0.1"]
inject_declared = true
'''
        with launch_proxy(
            proxy_backend, directory, policy, native_policy=True,
            agent_api=True, flow_store_enabled=True,
            gateway_services_dir=directory / "services",
            gateway_builtin_services_dir=directory / "builtin",
            network_guard_enabled=True, network_guard_block=True,
        ) as proxy:
            token = _gateway_token(proxy)
            declared = scoped_api(
                proxy, "alice", "/api/test-context/current", method="POST",
                body=json.dumps({"context": "run=gateway-621;agent=alice;test=capture"}).encode(),
            )
            assert declared["agent"] == "alice"
            status, headers, body = request(
                proxy.paths["alice"],
                f"http://127.0.0.1:{port}/v1/items?account=alpha",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert status == 200, body
            assert origin.accepts == len(origin.requests) == 1
            assert _authorization(_wire(origin.requests[0])) == [
                f"Bearer {VAULT_CREDENTIAL}".encode()
            ]
            request_id = next(value for name, value in headers.items()
                              if name.lower() == "x-safeyolo-request-id")
            search = "/api/flows/search?run=gateway-621&test=capture"
            deadline = time.monotonic() + 2
            while True:
                flows = scoped_api(proxy, "alice", search)["flows"]
                owned = [row for row in flows if row["request_id"] == request_id]
                if owned or time.monotonic() >= deadline:
                    break
                time.sleep(0.025)
            assert len(owned) == 1, flows
            flow_id = owned[0]["id"]
            assert owned[0]["evidence_owner"] == "alice"
            assert scoped_api(proxy, "bob", search)["flows"] == []
            detail = scoped_api(proxy, "alice", f"/api/flows/{flow_id}")
            recorded_headers = json.loads(detail["request_headers_json"])
            authorization = [value for name, value in recorded_headers
                             if name.lower() == "authorization"]
            assert len(authorization) == 1 and authorization[0].startswith("[GATEWAY:...")
            assert detail["path"] == "/v1/items"
            assert json.loads(detail["query_string"])["account"] == "alpha"
            assert token not in detail["request_headers_json"]
            assert VAULT_CREDENTIAL not in detail["request_headers_json"]
            assert scoped_api(proxy, "bob", f"/api/flows/{flow_id}", expected=404) == {
                "error": "Flow not found",
            }
            response = scoped_api(proxy, "alice", f"/api/flows/{flow_id}/response-body")
            assert base64.b64decode(response["body_base64"]) == body
            scoped_api(proxy, "bob", f"/api/flows/{flow_id}/response-body", expected=404)
