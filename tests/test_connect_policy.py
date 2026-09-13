"""CONNECT admission uses actual metadata, normal policy and separate quotas."""

import json

import pytest
from mitmproxy import ctx
from mitmproxy.test import tflow

from safeyolo.policy.engine import PolicyEngine
from safeyolo.policy.models import Condition, Permission, UnifiedPolicy


def connect_flow(host="example.com", port=22):
    flow = tflow.tflow()
    flow.request.method = "CONNECT"
    flow.request.host = host
    flow.request.port = port
    flow.request.path = ""
    flow.request.scheme = ""
    return flow


@pytest.mark.parametrize("host,status", [("evil.com", 403), ("unknown-host.com", 428), ("example.com", None)])
def test_connect_uses_real_policy(network_guard, host, status):
    flow = connect_flow(host)
    network_guard.http_connect(flow)
    assert (flow.response.status_code if flow.response else None) == status
    if status:
        assert flow.response.headers["X-Blocked-By"] == "network-guard"
    if status == 428:
        assert "wait_for_approval" in json.dumps(json.loads(flow.response.content))


def test_connect_warn_mode(network_guard):
    ctx.options.network_guard_block = False
    flow = connect_flow("evil.com")
    network_guard.http_connect(flow)
    assert flow.response is None
    assert network_guard.stats.warned == 1


@pytest.mark.parametrize("condition", [Condition(method="GET"), Condition(path_prefix="/ws")])
def test_connect_does_not_invent_inner_method_or_path(condition):
    engine = PolicyEngine()
    engine._loader.set_baseline(UnifiedPolicy(permissions=[
        Permission(action="network:request", resource="example.com/*", condition=condition),
    ]))
    assert engine.evaluate_request("example.com", method="CONNECT", path="").effect == "deny"
    assert engine.evaluate_request("example.com", method="GET", path="/ws").effect == "allow"


def test_connect_agent_override():
    engine = PolicyEngine()
    engine._loader.set_baseline(UnifiedPolicy(permissions=[
        Permission(action="network:request", resource="example.com/*", condition=Condition(agent="alice")),
        Permission(action="network:request", resource="*", effect="deny"),
    ]))
    assert engine.evaluate_request("example.com", method="CONNECT", path="", agent="alice").effect == "allow"
    assert engine.evaluate_request("example.com", method="CONNECT", path="", agent="bob").effect == "deny"


def test_connect_budget_is_bounded_without_spending_http_quota(monkeypatch):
    monkeypatch.setattr("safeyolo.policy.budget_tracker.time.time", lambda: 1000.0)
    engine = PolicyEngine()
    engine._loader.set_baseline(UnifiedPolicy(permissions=[
        Permission(action="network:request", resource="*", effect="budget", budget=1),
    ], budgets={"network:request": 1}))
    assert engine.evaluate_request("example.com", method="CONNECT", path="").effect == "allow"
    assert engine.evaluate_request("example.com", method="CONNECT", path="").effect == "allow"
    assert engine.evaluate_request("example.com", method="CONNECT", path="").effect == "budget_exceeded"
    assert engine.evaluate_request("example.com").effect == "allow"
    stats = engine.get_budget_stats()["budgets"]
    assert "network:connect:__global__" in stats
    assert "network:connect:example.com" in stats
    assert "network:request:__global__" in stats
