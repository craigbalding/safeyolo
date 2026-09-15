"""Authenticated /config reads use the accepted model and exact source hash.

Static values come from actual-source config and policy-hash goldens. The wire
fixture does not compute a competing hash or activate scanners. Policies contain
synthetic rule definitions and unused data only, with no gateway grants. Task
projection and unconfigured startup remain canonical-core contracts.
"""

import copy
import json

import pytest

from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.scenarios import origin_server
from tests.proxy_migration.test_agent_api_contract import AUTH_REQUIRED, api_proxy, api_request, assert_api_response
from tests.proxy_migration.test_native_network_policy import assert_rejection, policy_proxy, replace_policy

EMPTY_CONFIG = {"credential_rules": [], "scan_patterns": [], "addons": {}, "policy_hash": "sha256:917ea0d8c9828d33"}
TYPE_ERROR = {"error": "Internal error: TypeError"}
DEFAULT_SOURCE = {
    "permissions": [],
    "credential_rules": [{"name": "base", "patterns": ["fixture-[0-9]+"], "allowed_hosts": ["api.fixture.invalid"]}],
    "scan_patterns": [{"name": "base", "pattern": "fixture-é"}],
    "addons": {"credential_guard": {
        "enabled": False, "settings": {"use_default_credential_rules": False}, "custom": "preserved",
    }},
}
DEFAULT_CONFIG = {
    "credential_rules": [{
        "name": "base", "patterns": ["fixture-[0-9]+"], "allowed_hosts": ["api.fixture.invalid"],
        "header_names": ["authorization", "x-api-key"], "suggested_url": "",
    }],
    "scan_patterns": [{
        "name": "base", "pattern": "fixture-é", "target": "both", "scope": ["body"],
        "action": "log", "severity": "medium", "message": "", "case_sensitive": True,
    }],
    "addons": DEFAULT_SOURCE["addons"],
    "policy_hash": "sha256:071744ff2a2174fd",
}
RELOADED_SOURCE = copy.deepcopy(DEFAULT_SOURCE)
RELOADED_SOURCE["credential_rules"][0]["name"] = "reloaded"
RELOADED_SOURCE["addons"]["credential_guard"]["enabled"] = True
RELOADED_CONFIG = copy.deepcopy(DEFAULT_CONFIG)
RELOADED_CONFIG["credential_rules"][0]["name"] = "reloaded"
RELOADED_CONFIG["addons"]["credential_guard"]["enabled"] = True
RELOADED_CONFIG["policy_hash"] = "sha256:16e3ee46e6a12191"


def read_config(proxy, parent, expected, *, agent="alice", status=200):
    """Retain exact four-field JSON order and prove no local API egress."""
    before = parent.accepts, len(proxy.events("proxy.egress"))
    forged = "bob" if agent == "alice" else "alice"
    path = "/config" if agent == "alice" else f"/config///?agent={forged}&unused=%FF"
    result = api_request(proxy, path, agent=agent, headers={"X-SafeYolo-Agent": forged})
    assert_api_response(result, status, expected)
    assert result[2] == json.dumps(expected).encode()
    assert (parent.accepts, len(proxy.events("proxy.egress"))) == before
    return result[2]


@pytest.mark.parametrize("source,expected", [({}, EMPTY_CONFIG), (DEFAULT_SOURCE, DEFAULT_CONFIG)],
                         ids=["configured-empty", "defaults-disabled-addon"])
def test_agent_api_config_fields_and_hash_are_shared(proxy_backend, tmp_path, source, expected):
    with origin_server() as parent:
        with policy_proxy(proxy_backend, tmp_path / proxy_backend, json.dumps(source), policy_format="json",
                          agent_api=True, parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            first = read_config(proxy, parent, expected)
            assert read_config(proxy, parent, expected, agent="bob") == first
            assert parent.accepts == 0 and parent.requests == []
            assert proxy.events("proxy.egress") == []


@pytest.mark.parametrize("method,status,body", [
    ("GET", 401, AUTH_REQUIRED),
    ("POST", 405, {"error": "Method Not Allowed", "allowed": ["GET"]}),
])
def test_agent_api_config_reuses_local_auth_and_method_checks(proxy_backend, tmp_path, method, status, body):
    with api_proxy(proxy_backend, tmp_path / proxy_backend) as proxy:
        assert_api_response(api_request(proxy, "/config", method=method, auth=None), status, body)


def test_agent_api_config_reload_changes_fields_and_hash_then_retains_last_valid(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    with origin_server() as parent:
        with policy_proxy(proxy_backend, directory, json.dumps(DEFAULT_SOURCE), policy_format="json",
                          agent_api=True, parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            first = read_config(proxy, parent, DEFAULT_CONFIG)
            replace_policy(proxy, proxy_backend, directory, json.dumps(RELOADED_SOURCE))
            changed = read_config(proxy, parent, RELOADED_CONFIG, agent="bob")
            assert changed != first
            replace_policy(proxy, proxy_backend, directory, '{"permissions":false}', valid=False)
            assert read_config(proxy, parent, RELOADED_CONFIG) == changed
            assert parent.accepts == 0 and parent.requests == []
            assert proxy.events("proxy.egress") == []


def test_agent_api_config_hash_includes_unprojected_iam_permissions(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    permission = {"action": "network:request", "resource": "alpha.invalid/*", "effect": "allow"}
    source = {"permissions": [permission]}
    allow_config = {**EMPTY_CONFIG, "policy_hash": "sha256:4e982e6b059254af"}
    deny_config = {**EMPTY_CONFIG, "policy_hash": "sha256:f3956c8df3df40fd"}
    with origin_server() as parent:
        with policy_proxy(proxy_backend, directory, json.dumps(source), policy_format="json",
                          agent_api=True, parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            read_config(proxy, parent, allow_config)
            result = send_request(proxy.paths["alice"], "http://alpha.invalid/hash-metadata")
            assert result[0] == 200 and result[2] == b"hello"
            assert parent.accepts == 1 and len(proxy.events("proxy.egress")) == 1
            permission["effect"] = "deny"
            replace_policy(proxy, proxy_backend, directory, json.dumps(source))
            read_config(proxy, parent, deny_config, agent="bob")
            result = send_request(proxy.paths["bob"], "http://alpha.invalid/hash-metadata")
            assert_rejection(*result, 403, "alpha.invalid")
            assert parent.accepts == 1 and len(proxy.events("proxy.egress")) == 1
            for field in ("credential_rules", "scan_patterns", "addons"):
                assert allow_config[field] == deny_config[field]
            assert allow_config["policy_hash"] != deny_config["policy_hash"]


@pytest.mark.parametrize("location", ["gateway", "addon"], ids=["unprojected-date", "projected-date"])
def test_agent_api_config_only_serializes_projected_temporal_values(proxy_backend, tmp_path, location):
    directory = tmp_path / proxy_backend
    source = "permissions: []\n" + (
        "gateway: {unused: 2024-01-01}\n" if location == "gateway"
        else "addons: {credential_guard: {settings: {unused: 2024-01-01}}}\n"
    )
    expected = {**EMPTY_CONFIG, "policy_hash": "sha256:de47be91d54fade2"} if location == "gateway" else TYPE_ERROR
    with origin_server() as parent:
        with policy_proxy(proxy_backend, directory, source, policy_format="yaml", agent_api=True,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            for agent in ("alice", "bob"):
                read_config(proxy, parent, expected, agent=agent, status=200 if location == "gateway" else 500)
                assert_api_response(api_request(proxy, "/policy", agent=agent), 500, TYPE_ERROR)
            if location == "addon":
                # Source model JSON gives this quoted value the same hash as
                # the typed date, despite ordinary response JSON now succeeding.
                quoted = source.replace("unused: 2024-01-01", 'unused: "2024-01-01"')
                replace_policy(proxy, proxy_backend, directory, quoted)
                recovered = {
                    **EMPTY_CONFIG,
                    "addons": {"credential_guard": {"enabled": True, "settings": {"unused": "2024-01-01"}}},
                    "policy_hash": "sha256:d8b203cda0ca138f",
                }
                for agent in ("alice", "bob"):
                    read_config(proxy, parent, recovered, agent=agent)
            assert parent.accepts == 0 and parent.requests == []
            assert proxy.events("proxy.egress") == []
