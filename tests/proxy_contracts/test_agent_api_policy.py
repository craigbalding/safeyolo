"""Authenticated configured baseline reads through the actual Agent API.

Expected nongateway fields and order come from the frozen 18-case source policy
projection. Gateway-bearing responses stay in memory, with safe representations
and boolean assertions; only synthetic references appear in authored policies.
Absent/null startup is a separate runtime contract. The prior health/lookup
fixture remains unchanged.
"""

import json

import pytest

from tests.proxy_contracts.harness import request as send_request
from tests.proxy_contracts.scenarios import origin_server
from tests.proxy_contracts.test_agent_api_contract import (
    AUTH_REQUIRED,
    HOST,
    TOKEN,
    api_proxy,
    api_request,
    assert_api_response,
)
from tests.proxy_contracts.test_native_network_policy import policy_proxy, replace_policy

EMPTY_BASELINE = {
    "metadata": {
        "version": "1.0", "task_id": None, "description": None, "created": None,
        "approved": None, "brief_hash": None, "policy_hash": None,
    },
    "permissions": [], "budgets": {}, "required": [], "credential_rules": [],
    "scan_patterns": [], "addons": {}, "domains": {}, "clients": {},
    "gateway": {}, "simple_permissions": {},
}
EMPTY_CONDITION = dict.fromkeys((
    "credential", "method", "port", "path_prefix", "content_type", "tactics",
    "enables", "irreversible", "account", "agent", "service", "capability",
))

IAM_SOURCE = '''[[permissions]]
action = "network:request"
resource = "exact.invalid/*"
budget = 9
[[permissions]]
action = "network:request"
resource = "exact.invalid/*"
condition = {}
[[permissions]]
action = "file:read"
resource = "/workspace/*"
effect = "deny"
[[permissions]]
action = "file:write"
resource = "/workspace/out"
condition = { method = "put", credential = ["x:*"], account = "agent", ignored = "drop" }
[[permissions]]
action = "subprocess:exec"
resource = "program:*"
tier = "inferred"
[simple_permissions]
"authored:count" = 17
'''
IAM_BASELINE = {
    **EMPTY_BASELINE,
    "permissions": [
        {"action": "file:write", "resource": "/workspace/out", "effect": "allow", "budget": None,
         "tier": "explicit", "condition": {**EMPTY_CONDITION, "credential": ["x:*"], "method": "put", "account": "agent"}},
        {"action": "network:request", "resource": "exact.invalid/*", "effect": "allow", "budget": None,
         "tier": "explicit", "condition": EMPTY_CONDITION},
        {"action": "network:request", "resource": "exact.invalid/*", "effect": "allow", "budget": 9,
         "tier": "explicit", "condition": None},
        {"action": "file:read", "resource": "/workspace/*", "effect": "deny", "budget": None,
         "tier": "explicit", "condition": None},
        {"action": "subprocess:exec", "resource": "program:*", "effect": "allow", "budget": None,
         "tier": "inferred", "condition": None},
    ],
    "simple_permissions": {"authored:count": 17},
}

HOST_SOURCE = '''simple_permissions = { ignored = 99 }
[hosts."first.invalid"]
egress = "allow"
rules = [
  { action = "network:request", resource = "first.invalid/*", condition = {} },
  { action = "network:request", resource = "first.invalid/*", effect = "deny" },
  { action = "file:read", resource = "other.invalid/*" },
]
[hosts."*:8443"]
egress = "deny"
[hosts."*.wild.invalid"]
egress = "prompt"
[hosts."*"]
egress = "deny"
'''
HOST_BASELINE = {
    **EMPTY_BASELINE,
    "permissions": [
        {"action": "network:request", "resource": "*.wild.invalid/*", "effect": "prompt", "budget": None,
         "tier": "explicit", "condition": None},
        {"action": "network:request", "resource": "*", "effect": "deny", "budget": None,
         "tier": "explicit", "condition": {**EMPTY_CONDITION, "port": 8443}},
        {"action": "network:request", "resource": "*", "effect": "deny", "budget": None,
         "tier": "explicit", "condition": None},
    ],
    "simple_permissions": {"network:request:allow": 1, "network:request:deny": 1, "file:read:allow": 1},
}


def assert_policy_response(result, baseline):
    expected = {"policy": baseline}
    assert_api_response(result, 200, expected)
    # The static source projection fixes object order as well as schema values.
    # Comparing to a serialization of the response itself would miss reordering.
    assert result[2] == json.dumps(expected).encode()


@pytest.mark.parametrize("source,baseline", [
    ("", EMPTY_BASELINE), ("[hosts]\n", EMPTY_BASELINE),
    (IAM_SOURCE, IAM_BASELINE), (HOST_SOURCE, HOST_BASELINE),
], ids=["empty-iam", "empty-hosts", "iam-visible-order", "host-simple-extraction"])
def test_agent_api_policy_canonical_baseline_is_shared(proxy_backend, tmp_path, source, baseline):
    with origin_server() as parent:
        with policy_proxy(proxy_backend, tmp_path / proxy_backend, source, agent_api=True,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            bodies = []
            for agent in ("alice", "bob"):
                forged = "bob" if agent == "alice" else "alice"
                result = api_request(proxy, f"/policy?agent={forged}&agent_id={forged}", agent=agent,
                                     headers={"X-SafeYolo-Agent": forged})
                assert_policy_response(result, baseline)
                bodies.append(result[2])
            assert bodies[0] == bodies[1]
            assert parent.accepts == 0 and parent.requests == []
            assert proxy.events("traffic.egress") == []


def test_agent_api_policy_read_uses_last_valid_reload(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    with origin_server() as parent:
        with policy_proxy(proxy_backend, directory, IAM_SOURCE, agent_api=True,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            assert_policy_response(api_request(proxy, "/policy"), IAM_BASELINE)
            replace_policy(proxy, proxy_backend, directory, HOST_SOURCE)
            after_reload = api_request(proxy, "/policy")
            assert_policy_response(after_reload, HOST_BASELINE)
            replace_policy(proxy, proxy_backend, directory, "[hosts\n", valid=False)
            after_failure = api_request(proxy, "/policy", agent="bob")
            assert_policy_response(after_failure, HOST_BASELINE)
            assert after_failure[2] == after_reload[2]
            assert parent.accepts == 0 and parent.requests == []
            assert proxy.events("traffic.egress") == []


@pytest.mark.parametrize("auth,body", [
    (None, AUTH_REQUIRED), ("Bearer fixture-wrong-token", {"error": "Invalid agent token"}),
], ids=["missing", "wrong"])
def test_agent_api_policy_requires_the_shared_token(proxy_backend, tmp_path, auth, body):
    with api_proxy(proxy_backend, tmp_path / proxy_backend) as proxy:
        assert_api_response(api_request(proxy, "/policy", auth=auth), 401, body)


GATEWAY_SOURCE = '''[hosts."slack.com"]
service = "slack"
[agents.alice.services.slack]
capability = "reader"
token = "fixture-vault-reference"
account = "agent"
[gateway]
grant_ttl_seconds = 31
'''
NO_GATEWAY_GRANT_SOURCE = '''[hosts."slack.com"]
service = "slack"
[agents.alice.services]
[gateway]
grant_ttl_seconds = 31
'''


def gateway_services(proxy, agent):
    forged = "bob" if agent == "alice" else "alice"
    status, _, body = send_request(
        proxy.paths[agent], f"http://{HOST}/gateway/services?agent={forged}",
        headers={"Authorization": f"Bearer {TOKEN}", "X-SafeYolo-Agent": forged},
    )
    assert status == 200
    return json.loads(body)["authorized"]


def assert_gateway_diagnostics(proxy, expected, tokens):
    for agent in ("alice", "bob"):
        forged = "bob" if agent == "alice" else "alice"
        status, _, body = send_request(
            proxy.paths[agent], f"http://{HOST}/policy?agent={forged}&agent_id={forged}",
            headers={"Authorization": f"Bearer {TOKEN}", "X-SafeYolo-Agent": forged},
        )
        assert status == 200
        assert not any(token.encode() in body for token in tokens)
        assert b"fixture-vault-reference" not in body
        assert b'"token_map"' not in body and b'"agent_env"' not in body
        assert json.loads(body)["policy"]["gateway"] == expected


@pytest.mark.parametrize("capability", ["reader", 7], ids=["string-capability", "numeric-capability"])
def test_agent_api_policy_gateway_tokens_stay_with_the_caller_across_reload(proxy_backend, tmp_path, capability):
    directory = tmp_path / proxy_backend
    builtin = directory / "builtin"
    services = directory / "services"
    builtin.mkdir(parents=True)
    services.mkdir()
    for name, host in (("slack", "slack.com"), ("second", "second.invalid")):
        (services / f"{name}.yaml").write_text(f"""schema_version: 1
name: {name}
default_host: {host}
capabilities:
  reader:
    routes: [{{methods: [GET], path: /read}}]
""")
    source = GATEWAY_SOURCE + '''[hosts."second.invalid"]
service = "second"
[agents.bob.services.second]
capability = "reader"
token = "fixture-vault-reference-bob"
[agents.alice.services.second]
capability = "reader"
token = "fixture-vault-reference-alice-second"
'''
    source = source.replace('capability = "reader"', f"capability = {json.dumps(capability)}")
    expected = {"host_map": {"slack.com": "slack", "second.invalid": "second"}, "grant_ttl_seconds": 31}
    with origin_server() as parent:
        with policy_proxy(proxy_backend, directory, source, agent_api=True,
                          gateway_services_dir=services, gateway_builtin_services_dir=builtin,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            alice = gateway_services(proxy, "alice")
            bob = gateway_services(proxy, "bob")
            assert set(alice) == {"slack", "second"}
            assert set(bob) == {"second"}
            assert all(service["capability"] == capability for service in (*alice.values(), *bob.values()))
            tokens = [service["token"] for service in (*alice.values(), *bob.values())]
            assert len(set(tokens)) == 3
            assert_gateway_diagnostics(proxy, expected, tokens)
            assert gateway_services(proxy, "alice") == alice
            assert gateway_services(proxy, "bob") == bob

            replace_policy(proxy, proxy_backend, directory, source)
            reloaded = gateway_services(proxy, "alice")
            rotated = reloaded["slack"]["token"] != alice["slack"]["token"]
            assert rotated, "Successful identical reload did not rotate the gateway token"
            tokens.extend(service["token"] for service in reloaded.values())
            tokens.extend(service["token"] for service in gateway_services(proxy, "bob").values())
            assert_gateway_diagnostics(proxy, expected, tokens)

            replace_policy(proxy, proxy_backend, directory, "[hosts\n", valid=False)
            assert gateway_services(proxy, "alice") == reloaded
            assert_gateway_diagnostics(proxy, expected, tokens)

            replace_policy(proxy, proxy_backend, directory, NO_GATEWAY_GRANT_SOURCE)
            assert gateway_services(proxy, "alice") == {}
            assert gateway_services(proxy, "bob") == {}
            assert_gateway_diagnostics(proxy, {"host_map": {"slack.com": "slack"}, "grant_ttl_seconds": 31}, tokens)
            assert parent.accepts == 0 and parent.requests == []
            assert proxy.events("traffic.egress") == []
    assert all(not any(token.encode() in path.read_bytes() for token in tokens)
               for path in directory.rglob("*") if path.is_file())
