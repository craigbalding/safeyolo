"""Running service-gateway token, route, and bound-query scope on both backends."""

import json

from tests.proxy_migration.harness import launch_proxy, request
from tests.proxy_migration.test_gateway_redirect import (
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
