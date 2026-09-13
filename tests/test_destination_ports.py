"""Destination ports survive policy, approval, persistence and diagnostic paths."""

import json
from unittest.mock import create_autospec, patch

import pytest
from mitmproxy.test import tflow
from pydantic import ValidationError

from safeyolo.api import AdminAPI
from safeyolo.core.audit_stream import resolved_approval_key
from safeyolo.core.destination import destination_key, network_approval_key, split_destination
from safeyolo.operator_approvals import approve, deny
from safeyolo.policy.engine import PolicyEngine
from safeyolo.policy.models import Condition, Permission, UnifiedPolicy
from safeyolo.proxy_modes.unix_listener import UnixMode


@pytest.mark.parametrize("value", [0, -1, 65536, True, "22", [], [22, "443"], [False]])
def test_reject_invalid_port_conditions(value):
    with pytest.raises(ValidationError):
        Condition(port=value)


@pytest.mark.parametrize("value,expected", [
    ("example.com", ("example.com", None)),
    ("example.com:443", ("example.com", 443)),
    ("*.example.com:443", ("*.example.com", 443)),
    ("127.0.0.1:22", ("127.0.0.1", 22)),
    ("[::1]:22", ("::1", 22)),
    ("::1", ("::1", None)),
])
def test_endpoint_syntax(value, expected):
    assert split_destination(value) == expected
    assert destination_key(*expected) == value


@pytest.mark.parametrize("value", ["example.com:0", "example.com:65536", "example.com:ssh", "[::1]:", ":22", "[xyz]:22"])
def test_reject_invalid_endpoints(value):
    with pytest.raises(ValueError):
        split_destination(value)


def policy(tmp_path, text):
    path = tmp_path / "policy.toml"
    path.write_text(text)
    return PolicyEngine(baseline_path=path)


def test_effective_host_port_and_agent_precedence(tmp_path):
    engine = policy(tmp_path, '''
budget = 12000
[hosts]
"*" = { egress = "prompt" }
"*.example.com:443" = { egress = "allow" }
"api.example.com" = { egress = "deny" }
"api.example.com:443" = { egress = "allow" }
[agents.alice]
egress = "deny"
[agents.alice.hosts]
"api.example.com" = { egress = "prompt" }
"api.example.com:22" = { egress = "allow" }
''')
    def effect(host, port, agent=None):
        return engine.evaluate_request(host, port=port, agent=agent, consume_budget=False).effect
    assert effect("api.example.com", 443) == "allow"
    assert effect("api.example.com", 22) == "deny"
    assert effect("cdn.example.com", 443) == "allow"
    assert effect("cdn.example.com", 80) == "prompt"
    assert effect("api.example.com", 443, "alice") == "prompt"
    assert effect("api.example.com", 22, "alice") == "allow"
    assert effect("cdn.example.com", 443, "alice") == "deny"
    assert effect("api.example.com", 22, "bob") == "deny"


def test_legacy_host_only_rule_still_allows_any_port(tmp_path):
    engine = policy(tmp_path, '[hosts]\n"example.com" = { egress = "allow" }\n')
    for port in (22, 80, 443, 65535):
        assert engine.evaluate_request("example.com", port=port).effect == "allow"


def test_port_list_and_missing_port():
    engine = PolicyEngine()
    engine._loader.set_baseline(UnifiedPolicy(permissions=[
        Permission(action="network:request", resource="*", condition=Condition(port=[22, 443])),
    ]))
    assert engine.evaluate_request("example.com", port=22).effect == "allow"
    assert engine.evaluate_request("example.com", port=443).effect == "allow"
    assert engine.evaluate_request("example.com", port=80).effect == "deny"
    assert engine.evaluate_request("example.com").effect == "deny"


def test_approval_persists_only_the_requested_agent_host_and_port(tmp_path):
    engine = policy(tmp_path, '''# operator note
budget = 12000
[hosts]
"*" = { egress = "prompt" }
''')
    engine.add_host_allowance("127.0.0.1", port=22, agent="alice")
    engine.add_host_allowance("127.0.0.1", port=443, agent="alice")
    engine.add_host_allowance("::1", port=22, agent="alice")
    # Reload a separate evaluator from the persisted TOML.
    fresh = PolicyEngine(baseline_path=tmp_path / "policy.toml")
    assert fresh.evaluate_request("127.0.0.1", port=22, agent="alice").effect == "allow"
    assert fresh.evaluate_request("127.0.0.1", port=443, agent="alice").effect == "allow"
    assert fresh.evaluate_request("::1", port=22, agent="alice").effect == "allow"
    assert fresh.evaluate_request("127.0.0.1", port=11434, agent="alice").effect == "prompt"
    assert fresh.evaluate_request("127.0.0.1", port=22, agent="bob").effect == "prompt"
    engine.add_host_denial("127.0.0.1", port=22, agent="alice")
    assert engine.evaluate_request("127.0.0.1", port=22, agent="alice").effect == "deny"
    assert engine.evaluate_request("127.0.0.1", port=443, agent="alice").effect == "allow"
    assert (tmp_path / "policy.toml").read_text().startswith("# operator note")


def test_lookup_checks_quota_without_spending_it(tmp_path, monkeypatch):
    monkeypatch.setattr("safeyolo.policy.budget_tracker.time.time", lambda: 1000.0)
    engine = policy(tmp_path, 'budget = 1\n[hosts]\n"example.com:22" = { rate = 1 }\n')
    for _ in range(10):
        assert engine.evaluate_request("example.com", port=22, method="CONNECT", consume_budget=False).effect == "allow"
    assert engine._budget_tracker.get_stats()["tracked_keys"] == 0
    engine.evaluate_request("example.com", port=22, method="CONNECT")
    engine.evaluate_request("example.com", port=22, method="CONNECT")
    assert engine.evaluate_request("example.com", port=22, method="CONNECT", consume_budget=False).effect == "budget_exceeded"
    assert "network:connect:example.com:22" in engine.get_budget_stats()["budgets"]


def test_trusted_agent_and_actual_port_reach_pdp(network_guard):
    from pdp import get_policy_client

    engine = get_policy_client()._pdp._engine
    engine._loader.set_baseline(UnifiedPolicy(permissions=[
        Permission(action="network:request", resource="*", condition=Condition(port=22, agent="alice")),
    ]))
    for port, agent, status in [(22, "alice", None), (443, "alice", 403), (22, "bob", 403)]:
        flow = tflow.tflow()
        flow.request.method = "CONNECT"
        flow.request.path = ""
        flow.request.port = port
        flow.client_conn.proxy_mode = UnixMode.parse(f"unix:/tmp/10.0.0.5_{agent}/proxy.sock")
        network_guard.http_connect(flow)
        assert (flow.response.status_code if flow.response else None) == status


def test_approval_identity_and_operator_round_trip(network_guard):
    events = []
    for agent, port in [("alice", 22), ("alice", 443), ("bob", 22)]:
        flow = tflow.tflow()
        flow.request.host = "unknown-host.com"
        flow.request.port = port
        flow.client_conn.proxy_mode = UnixMode.parse(f"unix:/tmp/10.0.0.5_{agent}/proxy.sock")
        with patch("safeyolo.core.base.write_event", autospec=True) as write:
            network_guard.request(flow)
        event = write.call_args.kwargs
        event["approval"] = event["approval"].model_dump()
        events.append(event)
    assert len({e["approval"]["key"] for e in events}) == 3
    api = create_autospec(AdminAPI, instance=True, spec_set=True)
    api.allow_host.return_value = {"status": "added"}
    approve(events[0], api)
    api.allow_host.assert_called_once_with(host="unknown-host.com", rate=600, agent="alice", port=22)
    deny(events[0], api)
    assert api.deny_host.call_args.kwargs["port"] == 22
    assert api.deny_host.call_args.kwargs["agent"] == "alice"
    key = resolved_approval_key({"event": "admin.host_allowed", "details": {"host": "unknown-host.com", "agent": "alice", "port": 22}})
    assert key == events[0]["approval"]["key"] + ":" + events[0]["approval"]["target"]
    assert json.loads(network_approval_key("alice", "::1", 22)) == ["alice", "::1", 22]
