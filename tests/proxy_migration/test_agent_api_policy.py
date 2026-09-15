"""Authenticated configured baseline reads through the actual Agent API.

Expected nongateway fields and order come from the frozen 18-case source policy
projection. Gateway-bearing responses stay in memory, with safe representations
and boolean assertions; only synthetic references appear in authored policies.
Absent/null startup is a separate runtime contract. The prior health/lookup
fixture remains unchanged.
"""

import json

import pytest

from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.scenarios import origin_server
from tests.proxy_migration.test_agent_api_contract import (
    AUTH_REQUIRED,
    HOST,
    TOKEN,
    api_proxy,
    api_request,
    assert_api_response,
)
from tests.proxy_migration.test_native_network_policy import policy_proxy, replace_policy

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
            assert proxy.events("proxy.egress") == []


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
            assert proxy.events("proxy.egress") == []


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


class GatewayPolicyRead:
    """Keep gateway response bytes out of wire logs and failure representations."""

    def __init__(self, proxy, agent="alice"):
        __tracebackhide__ = True
        forged = "bob" if agent == "alice" else "alice"
        status, headers, body = send_request(
            proxy.paths[agent], f"http://{HOST}/policy?agent={forged}&agent_id={forged}",
            headers={"Authorization": f"Bearer {TOKEN}", "X-SafeYolo-Agent": forged},
        )
        status_ok = status == 200
        assert status_ok, "Gateway baseline read did not succeed"
        headers = {name.lower(): value for name, value in headers.items()}
        headers_ok = headers.get("content-type") == "application/json" and headers.get("x-safeyolo-agent-api") == "true"
        assert headers_ok, "Gateway baseline response did not have API JSON headers"
        try:
            self._view = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AssertionError("Gateway baseline response was not valid JSON") from None
        self._wire = body

    def __repr__(self):
        return "GatewayPolicyRead()"

    def token_count(self):
        __tracebackhide__ = True
        return len(self._view["policy"]["gateway"]["token_map"])

    def matches_gateway_model(self, capability="reader", *, granted=True):
        __tracebackhide__ = True
        token_map = self._view["policy"]["gateway"]["token_map"]
        if len(token_map) != int(granted):
            return False
        expected_gateway = {"token_map": {}, "agent_env": {"alice": {}}, "host_map": {"slack.com": "slack"}}
        if granted:
            token = next(iter(token_map))
            if not (token.startswith("sgw_") and len(token) == 68
                    and all(character in "0123456789abcdef" for character in token[4:])):
                return False
            expected_gateway["token_map"][token] = {
                "agent": "alice", "service": "slack", "capability": capability,
                "token": "fixture-vault-reference", "account": "agent",
            }
            expected_gateway["agent_env"]["alice"]["slack"] = token
        expected_gateway["grant_ttl_seconds"] = 31
        expected = {"policy": {**EMPTY_BASELINE, "gateway": expected_gateway}}
        return self._wire == json.dumps(expected).encode()

    def same_snapshot(self, other):
        __tracebackhide__ = True
        return self._wire == other._wire

    def same_tokens(self, other):
        __tracebackhide__ = True
        return (self._view["policy"]["gateway"]["token_map"].keys()
                == other._view["policy"]["gateway"]["token_map"].keys())

    def token_values_absent_from_files(self, directory):
        __tracebackhide__ = True
        tokens = [token.encode() for token in self._view["policy"]["gateway"]["token_map"]]
        return all(not any(token in path.read_bytes() for token in tokens)
                   for path in directory.rglob("*") if path.is_file())


def source_gateway_runtime_is_absent(proxy):
    """Observe the source addon boundary without recording any possible tokens."""
    __tracebackhide__ = True
    status, _, body = send_request(proxy.paths["alice"], f"http://{HOST}/gateway/services",
                                  headers={"Authorization": f"Bearer {TOKEN}"})
    return status == 503 and body == b'{"error": "service-gateway addon not loaded"}'


def test_agent_api_policy_gateway_tokens_follow_baseline_reload(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    reads = []
    with origin_server() as parent:
        with policy_proxy(proxy_backend, directory, GATEWAY_SOURCE, agent_api=True,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            if proxy_backend == "python":
                runtime_absent = source_gateway_runtime_is_absent(proxy)
                assert runtime_absent, "Source gateway runtime unexpectedly loaded"
            before = GatewayPolicyRead(proxy)
            repeated = GatewayPolicyRead(proxy)
            other_agent = GatewayPolicyRead(proxy, "bob")
            reads.extend((before, repeated, other_agent))
            canonical = all(read.matches_gateway_model() for read in reads)
            shared_stable = before.same_snapshot(repeated) and before.same_snapshot(other_agent)
            assert canonical, "Gateway canonical fields or values changed"
            assert shared_stable, "Repeated or cross-agent baseline reads changed the snapshot"

            replace_policy(proxy, proxy_backend, directory, GATEWAY_SOURCE)
            reloaded = GatewayPolicyRead(proxy)
            reads.append(reloaded)
            rotated = not before.same_tokens(reloaded)
            canonical = reloaded.matches_gateway_model()
            assert rotated, "Successful identical reload did not rotate the gateway token"
            assert canonical, "Reload changed canonical gateway fields or values"

            replace_policy(proxy, proxy_backend, directory, "[hosts\n", valid=False)
            retained = GatewayPolicyRead(proxy, "bob")
            reads.append(retained)
            failure_retained = reloaded.same_snapshot(retained)
            assert failure_retained, "Failed reload changed the last valid gateway snapshot"

            replace_policy(proxy, proxy_backend, directory, NO_GATEWAY_GRANT_SOURCE)
            removed = GatewayPolicyRead(proxy)
            removed_other_agent = GatewayPolicyRead(proxy, "bob")
            reads.extend((removed, removed_other_agent))
            empty_canonical = removed.matches_gateway_model(granted=False)
            empty_shared = removed.same_snapshot(removed_other_agent)
            assert empty_canonical, "Last-grant removal did not expose the canonical empty token map"
            assert empty_shared, "Identities observed different grant-removal snapshots"
            assert parent.accepts == 0 and parent.requests == []
            assert proxy.events("proxy.egress") == []
    tokens_private = all(read.token_values_absent_from_files(directory) for read in reads)
    assert tokens_private, "Gateway bearer values reached fixture files"
    (directory / "gateway-policy-observations.json").write_text(json.dumps({
        "source_gateway_absence_observed": proxy_backend == "python", "canonical_values_preserved": canonical,
        "repeated_and_shared_reads_stable": shared_stable, "successful_reload_rotated_token": rotated,
        "failed_reload_retained_snapshot": failure_retained, "last_grant_removal_empty": empty_canonical,
        "empty_snapshot_shared": empty_shared, "tokens_absent_from_files": tokens_private,
        "baseline_reads": len(reads), "tokens_before": before.token_count(), "tokens_after_removal": removed.token_count(),
    }, indent=2) + "\n")


def test_agent_api_policy_preserves_non_string_gateway_capability(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    source = GATEWAY_SOURCE.replace('capability = "reader"', "capability = 7")
    with origin_server() as parent:
        with policy_proxy(proxy_backend, directory, source, agent_api=True,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            if proxy_backend == "python":
                runtime_absent = source_gateway_runtime_is_absent(proxy)
                assert runtime_absent, "Source gateway runtime unexpectedly loaded"
            first = GatewayPolicyRead(proxy)
            other_agent = GatewayPolicyRead(proxy, "bob")
            canonical = first.matches_gateway_model(capability=7) and other_agent.matches_gateway_model(capability=7)
            shared = first.same_snapshot(other_agent)
            assert canonical, "Source-valid non-string capability did not survive the canonical baseline"
            assert shared, "Non-string grant baseline was filtered by caller identity"
            assert parent.accepts == 0 and parent.requests == []
            assert proxy.events("proxy.egress") == []
    tokens_private = first.token_values_absent_from_files(directory) and other_agent.token_values_absent_from_files(directory)
    assert tokens_private, "Gateway bearer values reached fixture files"
    (directory / "gateway-policy-observations.json").write_text(json.dumps({
        "source_gateway_absence_observed": proxy_backend == "python", "non_string_capability_preserved": canonical,
        "snapshot_shared": shared, "tokens_absent_from_files": tokens_private, "token_count": first.token_count(),
    }, indent=2) + "\n")
