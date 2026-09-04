"""Chain-level assurance for trusted agent identity resolution."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from agent_api import AgentAPI
from mitmproxy.test import tflow
from request_id import RequestIdGenerator
from service_discovery import ServiceDiscovery
from service_gateway import ServiceGateway, TokenBinding

from safeyolo.core.identity import (
    AttributionStatus,
    IdentityStatus,
    TrafficInitiator,
    attribute_traffic,
    resolve_agent_identity,
)
from safeyolo.core.service_loader import (
    AuthConfig,
    Capability,
    CapabilityRoute,
    ServiceDefinition,
    ServiceRegistry,
)
from safeyolo.proxy_modes.unix_listener import UnixMode
from safeyolo.storage.flow_store import FlowStore

pytestmark = pytest.mark.assurance_boundary


def _flow(*, uds_agent=None, metadata_agent=None, client_ip="10.0.0.5"):
    flow = tflow.tflow()
    flow.client_conn.peername = (client_ip, 12345)
    if uds_agent:
        flow.client_conn.proxy_mode = UnixMode.parse(
            f"unix:/tmp/{client_ip}_{uds_agent}/proxy.sock"
        )
    if metadata_agent is not None:
        flow.metadata["agent"] = metadata_agent
    return flow


def _discovery(mapped_agent=None, client_ip="10.0.0.5"):
    discovery = ServiceDiscovery()
    if mapped_agent:
        discovery._ip_to_name = {client_ip: mapped_agent}
    return discovery


def _gateway_with_token(tmp_path: Path):
    token = f"sgw_{'a' * 64}"
    gateway = ServiceGateway()
    gateway._host_map = {"api.example.com": "example"}
    gateway._token_map[token] = TokenBinding(
        agent="alice",
        service_name="example",
        capability_name="reader",
        vault_token="example-secret",
    )
    service = ServiceDefinition(
        name="example",
        auth=AuthConfig(type="bearer"),
        capabilities={
            "reader": Capability(
                name="reader",
                routes=[CapabilityRoute(methods=["GET"], path="/v1/**")],
            )
        },
    )
    registry = ServiceRegistry(tmp_path, tmp_path / "no-builtins")
    registry._services = {"example": service}
    return gateway, registry, token


@pytest.mark.parametrize(
    ("uds_agent", "mapped_agent", "metadata_agent", "status", "agent", "source"),
    [
        ("alice", "alice", None, IdentityStatus.RESOLVED, "alice", "uds"),
        ("alice", None, None, IdentityStatus.RESOLVED, "alice", "uds"),
        ("alice", "bob", None, IdentityStatus.CONFLICT, None, None),
        ("alice", "alice", "bob", IdentityStatus.CONFLICT, None, None),
        (None, "alice", None, IdentityStatus.RESOLVED, "alice", "ip_map"),
        (None, None, None, IdentityStatus.UNAVAILABLE, None, None),
        (None, None, "alice", IdentityStatus.UNAVAILABLE, None, None),
    ],
)
def test_identity_matrix(
    uds_agent,
    mapped_agent,
    metadata_agent,
    status,
    agent,
    source,
):
    flow = _flow(uds_agent=uds_agent, metadata_agent=metadata_agent)
    result = resolve_agent_identity(flow, _discovery(mapped_agent))

    assert result.status is status
    assert result.agent == agent
    assert result.source == source
    assert flow.metadata.get("agent") == agent


def test_service_discovery_stamps_authoritative_uds_identity_when_map_is_missing():
    discovery = _discovery()
    flow = _flow(uds_agent="alice")

    discovery.request(flow)

    assert flow.metadata["agent"] == "alice"
    assert flow.metadata["agent_identity_source"] == "uds"


def test_service_discovery_does_not_overwrite_uds_map_conflict():
    discovery = _discovery("bob")
    flow = _flow(uds_agent="alice")

    with patch("service_discovery.write_event", autospec=True) as audit:
        discovery.request(flow)

    assert "agent" not in flow.metadata
    assert flow.metadata["agent_identity_status"] == "conflict"
    assert flow.metadata["agent_identity_conflict"]["reason"] == "uds_ip_map_mismatch"
    assert audit.call_args.args[0] == "security.agent_identity_conflict"
    assert audit.call_args.kwargs["attribution_status"] == "conflict"
    assert audit.call_args.kwargs["details"] == {
        "reason": "uds_ip_map_mismatch",
        "uds_agent": "alice",
        "mapped_agent": "bob",
    }


def test_real_request_chain_carries_one_identity_into_gateway(tmp_path):
    discovery = _discovery("alice")
    gateway, registry, token = _gateway_with_token(tmp_path)
    flow = _flow(uds_agent="alice")
    flow.request.url = "https://api.example.com/v1/items"
    flow.request.headers["authorization"] = f"Bearer {token}"

    RequestIdGenerator().request(flow)
    discovery.request(flow)
    with patch(
        "service_gateway.ctx",
        SimpleNamespace(options=SimpleNamespace(gateway_enabled=True)),
    ), patch(
        "service_gateway.find_addon", autospec=True, return_value=discovery
    ), patch(
        "service_gateway.get_service_registry", autospec=True, return_value=registry
    ), patch(
        "service_gateway.get_vault", autospec=True, return_value=None
    ), patch(
        "pdp.is_policy_client_configured", autospec=True, return_value=False
    ):
        gateway.request(flow)

    # It reached the vault boundary, proving identity validation accepted the
    # same real identity stamped by discovery rather than skipping the check.
    body = json.loads(flow.response.content)
    assert body["reason_codes"] == ["VAULT_UNAVAILABLE"]
    assert flow.metadata["agent"] == "alice"
    assert flow.metadata["agent_identity_source"] == "uds"
    assert flow.metadata["request_id"].startswith("req-")


def test_real_request_chain_rejects_uds_map_disagreement(tmp_path):
    discovery = _discovery("bob")
    gateway, registry, token = _gateway_with_token(tmp_path)
    flow = _flow(uds_agent="alice")
    flow.request.url = "https://api.example.com/v1/items"
    flow.request.headers["authorization"] = f"Bearer {token}"

    RequestIdGenerator().request(flow)
    discovery.request(flow)
    with patch(
        "service_gateway.ctx",
        SimpleNamespace(options=SimpleNamespace(gateway_enabled=True)),
    ), patch(
        "service_gateway.find_addon", autospec=True, return_value=discovery
    ), patch(
        "service_gateway.get_service_registry", autospec=True, return_value=registry
    ):
        gateway.request(flow)

    body = json.loads(flow.response.content)
    assert body["reason_codes"] == ["AGENT_IDENTITY_CONFLICT"]
    assert "agent" not in flow.metadata
    assert flow.metadata["agent_identity_status"] == "conflict"


def test_metadata_conflict_remains_terminal_across_request_chain(tmp_path):
    discovery = _discovery("alice")
    gateway, registry, token = _gateway_with_token(tmp_path)
    flow = _flow(uds_agent="alice", metadata_agent="bob")
    flow.request.url = "https://api.example.com/v1/items"
    flow.request.headers["authorization"] = f"Bearer {token}"

    discovery.request(flow)
    assert flow.metadata["agent_identity_conflict"]["reason"] == "trusted_metadata_mismatch"

    with patch(
        "service_gateway.ctx",
        SimpleNamespace(options=SimpleNamespace(gateway_enabled=True)),
    ), patch(
        "service_gateway.find_addon", autospec=True, return_value=discovery
    ), patch(
        "service_gateway.get_service_registry", autospec=True, return_value=registry
    ):
        gateway.request(flow)

    body = json.loads(flow.response.content)
    assert body["reason_codes"] == ["AGENT_IDENTITY_CONFLICT"]
    assert "agent" not in flow.metadata


def test_attribution_separates_delegated_initiator_from_evidence_owner():
    flow = _flow(uds_agent="alice")
    flow.metadata["origin"] = "operator"

    identity = resolve_agent_identity(flow, _discovery("alice"))
    attribution = attribute_traffic(flow, identity)

    assert attribution.evidence_owner == "alice"
    assert attribution.trusted_transport_identity == "alice"
    assert attribution.initiator is TrafficInitiator.OPERATOR
    assert attribution.status is AttributionStatus.DELEGATED
    assert attribution.provenance == {
        "transport_source": "uds",
        "uds_agent": "alice",
        "ip_map_agent": "alice",
        "delegation": "operator-provenance",
    }
    assert "metadata_agent" not in attribution.provenance


def test_attribution_quarantines_unavailable_identity_and_spoofed_metadata():
    flow = _flow(metadata_agent="spoofed-agent")

    attribution = attribute_traffic(flow, resolve_agent_identity(flow))

    assert attribution.evidence_owner is None
    assert attribution.trusted_transport_identity is None
    assert attribution.initiator is TrafficInitiator.UNKNOWN
    assert attribution.status is AttributionStatus.UNAVAILABLE
    assert attribution.provenance == {"reason": "no_trusted_identity"}
    assert "metadata_agent" not in attribution.provenance


def test_attribution_conflict_keeps_trusted_sources_operator_only():
    flow = _flow(uds_agent="alice", metadata_agent="spoofed")

    attribution = attribute_traffic(
        flow,
        resolve_agent_identity(flow, _discovery("bob")),
    )

    assert attribution.evidence_owner is None
    assert attribution.trusted_transport_identity is None
    assert attribution.status is AttributionStatus.CONFLICT
    assert attribution.provenance == {
        "uds_agent": "alice",
        "ip_map_agent": "bob",
        "reason": "uds_ip_map_mismatch",
    }


def test_agent_api_ownership_fails_closed_without_trusted_identity():
    api = AgentAPI()
    flow = _flow(metadata_agent="alice")

    assert api._verify_flow_ownership(flow, {"agent_id": "alice"}) is False
    assert "agent" not in flow.metadata


@pytest.mark.parametrize(
    ("handler_name", "body"),
    [
        ("_handle_flow_search", None),
        ("_handle_flow_endpoints", {}),
        ("_handle_flow_facets", {}),
        ("_handle_flow_body_search", {"engagement_id": "eng-1", "query": "secret"}),
        (
            "_handle_flow_request_body_search",
            {"engagement_id": "eng-1", "query": "secret"},
        ),
    ],
)
def test_agent_api_flow_queries_cannot_run_unscoped(tmp_path, handler_name, body):
    store = FlowStore(db_path=str(tmp_path / "flows.sqlite3"))
    store.init_db()

    class FlowSearchAPI(AgentAPI):
        def _get_flow_store(self):
            return store

    api = FlowSearchAPI()
    flow = _flow(metadata_agent="alice")
    flow.request.method = "POST" if body is not None else "GET"
    flow.request.url = f"https://_safeyolo.proxy.internal/{handler_name}"
    if body is not None:
        flow.request.content = json.dumps(body).encode()
        flow.request.headers["content-type"] = "application/json"

    getattr(api, handler_name)(flow)

    assert flow.response.status_code == 403
    assert json.loads(flow.response.content) == {"error": "Could not identify agent"}
    store.close()
