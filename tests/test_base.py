"""Assurance-boundary tests for the shared security addon contract."""

from __future__ import annotations

import json
from unittest.mock import create_autospec, patch

import pytest
from mitmproxy import http
from mitmproxy.test import taddons, tflow

from pdp.client import PolicyClient
from safeyolo.core.audit_schema import Decision, EventKind, Severity
from safeyolo.core.base import AddonStats, SecurityAddon
from safeyolo.core.identity import IdentityStatus
from safeyolo.core.trace import get_store
from safeyolo.mitm_addons.service_discovery import ServiceDiscovery

pytestmark = pytest.mark.assurance_boundary


class BoundaryAddon(SecurityAddon):
    name = "test-addon"


def _flow(host: str = "example.com") -> http.HTTPFlow:
    flow = tflow.tflow(resp=False)
    flow.request.host = host
    flow.client_conn.peername = ("10.0.0.4", 32100)
    return flow


def _policy(*, enabled: bool = True) -> PolicyClient:
    client = create_autospec(PolicyClient, instance=True, spec_set=True)
    client.is_addon_enabled.return_value = enabled
    return client


def _discovery(agent: str) -> ServiceDiscovery:
    discovery = ServiceDiscovery()
    discovery._ip_to_name["10.0.0.4"] = agent
    return discovery


def _steps(flow: http.HTTPFlow):
    return get_store().get(
        flow.metadata["request_id"], flow.metadata["agent"]
    ).steps


def test_stats_and_option_contracts_use_real_addon_and_option_state():
    stats = AddonStats()
    assert (stats.checks, stats.allowed, stats.blocked, stats.warned) == (0, 0, 0, 0)

    addon = BoundaryAddon()
    assert addon._option_prefix() == "test_addon"
    with taddons.context(addon) as context:
        assert addon.is_enabled() is True
        assert addon.should_block() is True
        context.options.add_option("test_addon_enabled", bool, False, "test")
        context.options.add_option("test_addon_block", bool, False, "test")
        assert addon.is_enabled() is False
        assert addon.should_block() is False


def test_prior_response_bypasses_without_policy_lookup_and_records_trace():
    addon = BoundaryAddon()
    flow = _flow()
    flow.response = http.Response.make(451, b"blocked")
    flow.metadata.update(trace=True, request_id="req-prior", agent="agent-a")
    client = _policy()

    with patch("safeyolo.core.base.get_policy_client", new=lambda: client):
        assert addon.is_bypassed(flow) is True

    client.is_addon_enabled.assert_not_called()
    steps = _steps(flow)
    assert [(step.state, step.reason) for step in steps] == [
        ("bypassed", "prior_response")
    ]


@pytest.mark.parametrize("enabled, expected", [(True, False), (False, True)])
def test_policy_controls_bypass_for_unscoped_identity(enabled: bool, expected: bool):
    addon = BoundaryAddon()
    flow = _flow()
    client = _policy(enabled=enabled)

    with patch("safeyolo.core.base.get_policy_client", new=lambda: client), patch(
        "safeyolo.core.base.get_service_discovery", new=lambda: None
    ), patch("mitmproxy.ctx.master", new=None, create=True):
        assert addon.is_bypassed(flow) is expected

    assert flow.metadata["agent_identity_status"] == IdentityStatus.UNAVAILABLE.value
    client.is_addon_enabled.assert_called_once_with("test_addon", "example.com", None)


def test_live_registry_discovery_takes_precedence_and_scopes_policy():
    addon = BoundaryAddon()
    discovery = _discovery("agent-a")
    flow = _flow()
    client = _policy(enabled=False)

    with taddons.context(addon, discovery), patch(
        "safeyolo.core.base.get_policy_client", new=lambda: client
    ), patch(
        "safeyolo.core.base.get_service_discovery",
        new=lambda: (_ for _ in ()).throw(AssertionError("stale singleton consulted")),
    ):
        assert addon.is_bypassed(flow) is True

    assert flow.metadata["agent"] == "agent-a"
    assert flow.metadata["agent_identity_source"] == "ip_map"
    client.is_addon_enabled.assert_called_once_with("test_addon", "example.com", "agent-a")


def test_registry_absence_does_not_fall_back_to_stale_singleton():
    addon = BoundaryAddon()
    stale = _discovery("stale-agent")
    flow = _flow()
    client = _policy()

    with taddons.context(addon), patch(
        "safeyolo.core.base.get_policy_client", new=lambda: client
    ), patch("safeyolo.core.base.get_service_discovery", new=lambda: stale):
        assert addon.is_bypassed(flow) is False

    assert "agent" not in flow.metadata
    client.is_addon_enabled.assert_called_once_with("test_addon", "example.com", None)


def test_identity_conflict_is_never_converted_to_policy_bypass():
    addon = BoundaryAddon()
    discovery = _discovery("mapped-agent")
    flow = _flow()
    flow.metadata["agent"] = "different-agent"
    client = _policy(enabled=False)

    with taddons.context(addon, discovery), patch(
        "safeyolo.core.base.get_policy_client", new=lambda: client
    ):
        assert addon.is_bypassed(flow) is False

    assert flow.metadata["agent_identity_status"] == IdentityStatus.CONFLICT.value
    assert "agent" not in flow.metadata
    client.is_addon_enabled.assert_not_called()


def test_policy_unavailability_does_not_bypass_security_addon():
    addon = BoundaryAddon()
    flow = _flow()

    def unavailable() -> PolicyClient:
        raise RuntimeError("PDP unavailable")

    with patch("safeyolo.core.base.get_policy_client", new=unavailable), patch(
        "mitmproxy.ctx.master", new=None, create=True
    ), patch("safeyolo.core.base.get_service_discovery", new=lambda: None):
        assert addon.is_bypassed(flow) is False


def test_block_sets_exact_response_metadata_stats_and_trace():
    addon = BoundaryAddon()
    flow = _flow()
    flow.metadata.update(trace=True, request_id="req-block", agent="agent-a")

    addon.block(
        flow,
        429,
        {"error": "Rate limited", "reason": "budget exhausted"},
        {"Retry-After": "60"},
    )

    assert flow.response.status_code == 429
    assert json.loads(flow.response.content) == {
        "error": "Rate limited",
        "reason": "budget exhausted",
    }
    assert flow.response.headers["Content-Type"] == "application/json"
    assert flow.response.headers["X-Blocked-By"] == "test-addon"
    assert flow.response.headers["X-SafeYolo-Request-Id"] == "req-block"
    assert flow.response.headers["Retry-After"] == "60"
    assert flow.metadata["blocked_by"] == "test-addon"
    assert flow.metadata["block_reason"] == "budget exhausted"
    assert addon.stats.blocked == 1
    assert _steps(flow)[-1].outcome == "blocked"


@pytest.mark.parametrize("body", [{"error": "blocked"}, {"reason": None}])
def test_block_does_not_invent_missing_reason(body: dict):
    addon = BoundaryAddon()
    flow = _flow()
    addon.block(flow, 403, body)
    assert "block_reason" not in flow.metadata


def test_warn_and_stats_snapshot_report_exact_counters():
    addon = BoundaryAddon()
    flow = _flow()
    flow.metadata.update(trace=True, request_id="req-warn", agent="agent-a")
    addon.stats.checks = 4
    addon.stats.allowed = 2
    addon.warn(flow)

    assert addon.get_stats() == {
        "enabled": True,
        "checks_total": 4,
        "allowed_total": 2,
        "blocked_total": 0,
        "warned_total": 1,
    }
    assert _steps(flow)[-1].outcome == "warned"


def test_log_decision_emits_schema_values_and_attribution():
    addon = BoundaryAddon()
    discovery = _discovery("agent-a")
    flow = _flow()
    flow.metadata.update(request_id="req-123", agent="agent-a")
    from safeyolo.core import base

    writer = create_autospec(base.write_event, spec_set=True)
    with taddons.context(addon, discovery), patch(
        "safeyolo.core.base.write_event", new=writer
    ):
        addon.log_decision(
            flow,
            Decision.DENY,
            severity=Severity.HIGH,
            summary="Blocked for test",
            host="example.com",
            reason="policy denied",
        )

    writer.assert_called_once_with(
        "security.test_addon",
        kind=EventKind.SECURITY,
        severity=Severity.HIGH,
        summary="Blocked for test",
        decision=Decision.DENY,
        host="example.com",
        request_id="req-123",
        agent="agent-a",
        evidence_owner="agent-a",
        trusted_transport_identity="agent-a",
        initiator="unknown",
        attribution_status="resolved",
        attribution_provenance={
            "transport_source": "ip_map",
            "ip_map_agent": "agent-a",
        },
        addon="test-addon",
        approval=None,
        details={"reason": "policy denied"},
    )


def test_trace_error_records_exception_type_without_sensitive_message():
    addon = BoundaryAddon()
    flow = _flow()
    flow.metadata.update(trace=True, request_id="req-error", agent="agent-a")
    addon._trace_error(flow, exc=ValueError("secret-in-url"))
    step = _steps(flow)[-1]
    assert step.state == "error"
    assert step.reason == "ValueError"
    assert "secret-in-url" not in repr(step)
