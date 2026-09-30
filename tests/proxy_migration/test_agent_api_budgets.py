"""Live /budgets reads share the current policy and existing enforcement state.

These local, metadata-only cases use real child clocks and loader reloads. A
rate of one request per minute keeps remaining=0 for thirty seconds after the
first charge; each consuming scenario asserts that bounded interval. Core
fixtures cover numeric extremes and file-task ceilings. No gateway grants,
status counters, replacement matcher or extra budget store participate here.
"""

import json
import time

import pytest

from tests.proxy_migration.harness import request as send_request
from tests.proxy_migration.scenarios import origin_server
from tests.proxy_migration.test_agent_api_contract import AUTH_REQUIRED, api_proxy, api_request, assert_api_response
from tests.proxy_migration.test_native_network_policy import assert_rejection, policy_proxy, replace_policy

EMPTY = {"tracked_keys": 0, "budgets": {}, "global_budgets": {}}
ALPHA_KEY = "network:request:alpha.invalid"
ALPHA = {
    "tracked_keys": 1,
    "budgets": {ALPHA_KEY: {"budget_per_minute": 1, "remaining": 0, "resource": "alpha.invalid"}},
    "global_budgets": {},
}
HIDDEN_ALPHA = {"tracked_keys": 1, "budgets": {}, "global_budgets": {}}
BUDGET_POLICY = '''[[permissions]]
action = "network:request"
resource = "alpha.invalid/*"
effect = "budget"
budget = 1
condition = {}
[[permissions]]
action = "network:request"
resource = "denied.invalid/*"
effect = "deny"
'''


def read_budgets(proxy, parent, expected, *, agent="alice"):
    """Keep exact field order and prove this local read adds no parent contact."""
    before = parent.accepts, len(proxy.events("proxy.egress"))
    forged = "bob" if agent == "alice" else "alice"
    result = api_request(proxy, f"/budgets?agent={forged}&agent_id={forged}", agent=agent,
                         headers={"X-SafeYolo-Agent": forged})
    assert_api_response(result, 200, expected)
    assert result[2] == json.dumps(expected).encode()
    assert (parent.accepts, len(proxy.events("proxy.egress"))) == before
    return result[2]


def assert_no_refill(started):
    assert time.monotonic() - started < 30, "Scenario crossed the proved rate=1 no-refill interval"


def test_agent_api_budgets_empty_schema_is_shared(proxy_backend, tmp_path):
    with origin_server() as parent:
        with policy_proxy(proxy_backend, tmp_path / proxy_backend, "", agent_api=True,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            for agent in ("alice", "bob"):
                read_budgets(proxy, parent, EMPTY, agent=agent)
            assert parent.accepts == 0 and parent.requests == []
            assert proxy.events("proxy.egress") == []


@pytest.mark.parametrize("method,status,body", [
    ("GET", 401, AUTH_REQUIRED),
    ("POST", 405, {"error": "Method Not Allowed", "allowed": ["GET"]}),
])
def test_agent_api_budgets_reuses_local_auth_and_method_checks(proxy_backend, tmp_path, method, status, body):
    with api_proxy(proxy_backend, tmp_path / proxy_backend) as proxy:
        assert_api_response(api_request(proxy, "/budgets", method=method, auth=None), status, body)


def test_agent_api_budgets_preview_and_denial_do_not_charge(proxy_backend, tmp_path):
    with origin_server() as parent:
        with policy_proxy(proxy_backend, tmp_path / proxy_backend, BUDGET_POLICY, agent_api=True,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            started = time.monotonic()
            for agent in ("alice", "bob"):
                for host, effect in (("alpha.invalid", "allow"), ("denied.invalid", "deny")):
                    assert_api_response(api_request(proxy, f"/lookup?host={host}", agent=agent), 200, {
                        "host": host, "port": 443, "method": "GET", "path": "/",
                        "agent": agent, "effect": effect, "reason": "",
                    })
                read_budgets(proxy, parent, EMPTY, agent=agent)
            assert parent.accepts == 0 and proxy.events("proxy.egress") == []
            for host, status, expected in (
                ("denied.invalid", 403, EMPTY), ("alpha.invalid", 200, ALPHA),
                ("denied.invalid", 403, ALPHA), ("alpha.invalid", 200, ALPHA),
                ("alpha.invalid", 429, ALPHA),
            ):
                before = parent.accepts, len(proxy.events("proxy.egress"))
                result = send_request(proxy.paths["alice"], f"http://{host}/budget-metadata")
                if status == 200:
                    assert result[0] == 200 and result[2] == b"hello"
                    assert parent.accepts == before[0] + 1
                else:
                    assert_rejection(*result, status, host)
                    assert (parent.accepts, len(proxy.events("proxy.egress"))) == before
                for agent in ("alice", "bob"):
                    read_budgets(proxy, parent, expected, agent=agent)
            assert parent.accepts == 2 and len(proxy.events("proxy.egress")) == 2
            assert len(parent.requests) == 2
            assert_no_refill(started)


@pytest.mark.parametrize("hidden_rule", ["agent-scoped", "exact-simple"])
def test_agent_api_budgets_retained_counter_uses_last_valid_rule(proxy_backend, tmp_path, hidden_rule):
    directory = tmp_path / proxy_backend
    visible_allow = BUDGET_POLICY.replace('effect = "budget"', 'effect = "allow"')
    hidden = (visible_allow.replace("condition = {}", 'condition = { agent = "alice" }')
              if hidden_rule == "agent-scoped" else visible_allow.replace("condition = {}\n", ""))
    with origin_server() as parent:
        with policy_proxy(proxy_backend, directory, BUDGET_POLICY, agent_api=True,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            started = time.monotonic()
            result = send_request(proxy.paths["alice"], "http://alpha.invalid/retain-metadata")
            assert result[0] == 200 and result[2] == b"hello"
            read_budgets(proxy, parent, ALPHA)
            replace_policy(proxy, proxy_backend, directory, visible_allow)
            read_budgets(proxy, parent, ALPHA, agent="bob")
            replace_policy(proxy, proxy_backend, directory, hidden)
            read_budgets(proxy, parent, HIDDEN_ALPHA)
            replace_policy(proxy, proxy_backend, directory, "[[permissions]\n", valid=False)
            read_budgets(proxy, parent, HIDDEN_ALPHA, agent="bob")
            replace_policy(proxy, proxy_backend, directory, BUDGET_POLICY)
            read_budgets(proxy, parent, ALPHA)
            assert parent.accepts == 1 and len(proxy.events("proxy.egress")) == 1
            assert_no_refill(started)


def test_agent_api_budgets_host_and_global_keys_keep_charge_order(proxy_backend, tmp_path):
    policy = '''[budgets]
"network:request" = 1
"credential:use" = 7
[[permissions]]
action = "network:request"
resource = "*.invalid/*"
effect = "budget"
budget = 1
'''
    expected = {
        "tracked_keys": 3,
        "budgets": {
            "network:request:zeta.invalid": {"budget_per_minute": 1, "remaining": 0, "resource": "zeta.invalid"},
            "network:request:__global__": {"budget_per_minute": 1, "remaining": 0, "resource": "__global__"},
            ALPHA_KEY: ALPHA["budgets"][ALPHA_KEY],
        },
        "global_budgets": {"network:request": 1, "credential:use": 7},
    }
    with origin_server() as parent:
        with policy_proxy(proxy_backend, tmp_path / proxy_backend, policy, agent_api=True,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            started = time.monotonic()
            for agent, host in (("alice", "zeta.invalid"), ("bob", "alpha.invalid")):
                result = send_request(proxy.paths[agent], f"http://{host}/ordered-metadata")
                assert result[0] == 200 and result[2] == b"hello"
            first = read_budgets(proxy, parent, expected)
            assert read_budgets(proxy, parent, expected, agent="bob") == first
            assert parent.accepts == 2 and len(proxy.events("proxy.egress")) == 2
            assert_no_refill(started)


def test_agent_api_budgets_does_not_serialize_unrelated_temporal_baseline(proxy_backend, tmp_path):
    directory = tmp_path / proxy_backend
    temporal = BUDGET_POLICY + '''[addons.synthetic.settings]
observed = 2001-02-03
'''
    with origin_server() as parent:
        with policy_proxy(proxy_backend, directory, BUDGET_POLICY, agent_api=True,
                          parent_proxy=f"http://127.0.0.1:{parent.server_address[1]}") as proxy:
            started = time.monotonic()
            result = send_request(proxy.paths["alice"], "http://alpha.invalid/temporal-metadata")
            assert result[0] == 200 and result[2] == b"hello"
            first = read_budgets(proxy, parent, ALPHA)
            replace_policy(proxy, proxy_backend, directory, temporal)
            for agent in ("alice", "bob"):
                assert_api_response(api_request(proxy, "/policy", agent=agent), 500,
                                    {"error": "Internal error: TypeError"})
                assert read_budgets(proxy, parent, ALPHA, agent=agent) == first
            # The second real request still has its original burst allowance;
            # stable zero-valued reports alone would not prove no consumption.
            result = send_request(proxy.paths["bob"], "http://alpha.invalid/after-temporal-reads")
            assert result[0] == 200 and result[2] == b"hello"
            read_budgets(proxy, parent, ALPHA, agent="bob")
            assert parent.accepts == 2 and len(proxy.events("proxy.egress")) == 2
            assert_no_refill(started)
