"""Assurance-boundary tests for agent-scoped flow evidence."""

from __future__ import annotations

import json
import time
from unittest.mock import create_autospec, patch

import pytest
from flow_recorder import AGENT_API_HOST, FlowRecorder
from mitmproxy import http
from mitmproxy.flow import Error
from mitmproxy.test import taddons, tflow

from safeyolo.core import flow_writer
from safeyolo.core.flow_writer import _FlowWriter
from safeyolo.proxy_modes.unix_listener import UnixMode
from safeyolo.storage.flow_store import FlowStore

pytestmark = pytest.mark.assurance_boundary


@pytest.fixture
def recorder(tmp_path):
    addon = FlowRecorder()
    store = FlowStore(str(tmp_path / "flows.sqlite3"))
    store.init_db()
    addon.store = store
    with taddons.context(addon), patch.object(flow_writer, "_writer", new=None):
        yield addon, store
    store.close()


def _flow(
    *,
    url: str = "https://app.example.com/api/todos/42?view=full",
    status: int | None = 200,
    with_context: bool = True,
    agent: str | None = "agent-a",
):
    flow = tflow.tflow(resp=False)
    flow.request.url = url
    flow.request.method = "POST"
    flow.request.content = b'{"title":"test"}'
    flow.request.headers["Content-Type"] = "application/json"
    flow.client_conn.peername = ("192.0.2.20", 41000)
    if agent:
        flow.client_conn.proxy_mode = UnixMode.parse(
            f"unix:/tmp/192.0.2.20_{agent}/proxy.sock"
        )
    if status is not None:
        flow.response = http.Response.make(
            status, b'{"id":42}', {"Content-Type": "application/json"}
        )
    flow.metadata.update(request_id="req-1", start_time=time.time() - 0.1)
    if with_context:
        flow.metadata["test_context"] = {
            "run": "run-1",
            "test": "IDOR-003",
            "role": "attacker",
            "agent": "idor",
            "suite": "authorization",
            "subject": "todo",
            "step": "read-other-user",
            "intent": "negative",
            "expect": "deny",
        }
    return flow


def _invoke(addon: FlowRecorder, store: FlowStore, flow, hook: str = "response"):
    enqueue = create_autospec(
        flow_writer.put_record, spec_set=True, side_effect=store.record_flow
    )
    with patch("safeyolo.core.flow_writer.put_record", new=enqueue):
        getattr(addon, hook)(flow)
    return enqueue


@pytest.mark.parametrize(
    "mutate",
    [
        lambda flow, addon: flow.metadata.pop("test_context"),
        lambda flow, addon: flow.metadata.update(safeyolo_probe=True),
        lambda flow, addon: setattr(flow.request, "host", AGENT_API_HOST),
        lambda flow, addon: setattr(flow.request, "host", AGENT_API_HOST.upper()),
        lambda flow, addon: setattr(addon, "store", None),
    ],
)
def test_scope_probe_internal_host_and_store_gates_skip(recorder, mutate):
    addon, store = recorder
    flow = _flow()
    mutate(flow, addon)
    enqueue = _invoke(addon, store, flow)
    enqueue.assert_not_called()
    assert addon.get_stats()["skipped"] == 1


def test_global_disable_gate_skips_even_valid_flow(recorder):
    addon, store = recorder
    flow = _flow()
    from mitmproxy import ctx

    ctx.options.flow_store_enabled = False
    enqueue = _invoke(addon, store, flow)
    enqueue.assert_not_called()
    assert addon.get_stats()["skipped"] == 1


@pytest.mark.parametrize("marker", ["true", 1, [True], {"probe": True}])
def test_probe_gate_requires_literal_boolean_true(recorder, marker):
    addon, store = recorder
    flow = _flow()
    flow.metadata["safeyolo_probe"] = marker
    _invoke(addon, store, flow)
    assert addon.get_stats()["recorded"] == 1
    assert len(store.search_flows({})) == 1


def test_unresolved_or_spoofed_identity_is_not_recorded(recorder):
    addon, store = recorder
    flow = _flow(agent=None)
    flow.metadata["agent"] = "spoofed-agent"
    enqueue = _invoke(addon, store, flow)
    enqueue.assert_not_called()
    assert addon.get_stats()["skipped"] == 1
    assert flow.metadata["agent_identity_status"] == "unavailable"
    assert "agent" not in flow.metadata


@pytest.mark.parametrize(
    "blocked_by, expected_state, expected_reason",
    [(None, "completed", "OK"), ("credential-guard", "blocked", "credential-guard")],
)
def test_response_state_identity_url_and_context_are_persisted(
    recorder, blocked_by, expected_state, expected_reason
):
    addon, store = recorder
    flow = _flow(agent="agent-a", status=403 if blocked_by else 200)
    if blocked_by:
        flow.metadata["blocked_by"] = blocked_by
    _invoke(addon, store, flow)

    summary = store.search_flows({})[0]
    detail = store.get_flow(summary["id"])
    assert summary["flow_state"] == expected_state
    assert summary["reason"] == expected_reason
    assert summary["agent_id"] == "agent-a"
    assert summary["evidence_owner"] == "agent-a"
    assert summary["trusted_transport_identity"] == "agent-a"
    assert summary["initiator"] == "unknown"
    assert summary["attribution_status"] == "resolved"
    assert json.loads(summary["attribution_provenance_json"]) == {
        "transport_source": "uds",
        "uds_agent": "agent-a",
    }
    assert summary["engagement_id"] == "agent-a"
    assert summary["source_id"] == "192.0.2.20"
    assert summary["host"] == "app.example.com"
    assert summary["path"] == "/api/todos/42"
    assert json.loads(summary["query_string"]) == {"view": "full"}
    assert detail["run"] == "run-1"
    assert detail["test"] == "IDOR-003"
    assert detail["role"] == "attacker"
    assert detail["test_agent"] == "idor"
    assert detail["suite"] == "authorization"
    assert detail["subject"] == "todo"
    assert detail["step"] == "read-other-user"
    assert detail["intent"] == "negative"
    assert detail["expect"] == "deny"
    assert json.loads(detail["context_json"])["run"] == "run-1"
    assert addon.get_stats()["recorded"] == 1


def test_gateway_injected_credential_header_is_redacted(recorder):
    addon, store = recorder
    flow = _flow()
    flow.request.headers["Authorization"] = "Bearer super-secret-token"
    flow.metadata["gateway_injected_header"] = "Authorization"
    _invoke(addon, store, flow)
    summary = store.search_flows({})[0]
    headers = store.get_flow(summary["id"])["request_headers_json"]
    assert "super-secret-token" not in headers
    assert "[GATEWAY:...oken]" in headers


def test_error_hook_records_real_mitmproxy_error(recorder):
    addon, store = recorder
    flow = _flow(status=None)
    flow.error = Error("DNS lookup failed")
    _invoke(addon, store, flow, hook="error")
    summary = store.search_flows({})[0]
    assert summary["flow_state"] == "error"
    assert summary["status_code"] is None
    assert summary["reason"] == "DNS lookup failed"
    assert summary["agent_id"] == "agent-a"


def test_operator_provenance_and_websocket_state_are_persisted(recorder):
    addon, store = recorder
    flow = _flow()
    flow.metadata.update(
        origin="operator",
        operator_action="replay",
        source_flow_id="17",
        is_websocket=True,
    )
    _invoke(addon, store, flow)
    summary = store.search_flows({})[0]
    detail = store.get_flow(summary["id"])
    assert summary["source_type"] == "operator"
    assert summary["evidence_owner"] == "agent-a"
    assert summary["trusted_transport_identity"] == "agent-a"
    assert summary["initiator"] == "operator"
    assert summary["attribution_status"] == "delegated"
    assert json.loads(summary["attribution_provenance_json"])["delegation"] == "operator-provenance"
    assert detail["is_websocket"] == 1
    assert [
        {"tag": tag["tag"], "value": tag["value"]} for tag in detail["tags"]
    ] == [
        {"tag": "operator_action", "value": "replay"},
        {"tag": "source_flow_id", "value": "17"},
    ]


@pytest.mark.parametrize("duplicate", [False, True])
def test_operator_replay_refreshes_initiator_in_traffic_and_store(recorder, tmp_path, duplicate):
    """Real replay hooks replace the initiator, not the captured evidence owner."""
    from operator_provenance import OperatorProvenance
    from request_id import RequestIdGenerator
    from request_logger import RequestLogger
    from service_discovery import ServiceDiscovery

    from safeyolo.core import utils
    from safeyolo.core.audit_writer import get_writer
    from safeyolo.core.identity import flow_attribution

    addon, store = recorder
    discovery = ServiceDiscovery()
    operator = OperatorProvenance()
    request_ids = RequestIdGenerator()
    logger = RequestLogger()
    path = tmp_path / "replay-audit.jsonl"
    original = _flow()

    with taddons.context(addon, discovery, operator, request_ids, logger), \
         patch.object(utils, "AUDIT_LOG_PATH", new=path):
        request_ids.request(original)
        discovery.request(original)
        logger.request(original)
        logger.response(original)
        original_attribution = flow_attribution(original, discovery)
        operator._remember(original)

        replay = original.copy() if duplicate else original
        if duplicate:
            operator._view_add(replay)
        replay.backup()
        replay.is_replay = "request"
        replay.response = None
        operator._view_update(replay)
        request_ids.request(replay)
        operator.request(replay)
        discovery.request(replay)
        logger.request(replay)
        replay.response = http.Response.make(200, b"replayed")
        _invoke(addon, store, replay)
        logger.response(replay)
        assert get_writer().wait_for_drain(timeout_s=3.0)

    events = [json.loads(line) for line in path.read_text().splitlines()]
    traffic = [event for event in events if event["event"].startswith("traffic.")]
    assert len(traffic) == 4
    assert original_attribution.initiator.value == "unknown"
    for event in traffic[:2]:
        assert event["details"]["attribution"]["initiator"] == "unknown"
    replay_audit = next(
        event for event in events
        if event["event"] == "admin.traffic_operator_action"
        and event["details"]["action"] == "replay"
    )
    for event in [replay_audit, *traffic[2:]]:
        attribution = event["details"]["attribution"]
        assert attribution["evidence_owner"] == "agent-a"
        assert attribution["trusted_transport_identity"] == "agent-a"
        assert attribution["initiator"] == "operator"
        assert attribution["attribution_status"] == "delegated"
    stored = store.search_flows({})
    assert len(stored) == 1
    assert stored[0]["evidence_owner"] == "agent-a"
    assert stored[0]["trusted_transport_identity"] == "agent-a"
    assert stored[0]["initiator"] == "operator"
    assert stored[0]["attribution_status"] == "delegated"


@pytest.mark.parametrize("identity_state", ["unavailable", "conflict", "late_change"])
def test_operator_replay_does_not_restore_quarantined_ownership(recorder, identity_state):
    from operator_provenance import OperatorProvenance
    from request_id import RequestIdGenerator
    from service_discovery import ServiceDiscovery

    from safeyolo.core.identity import (
        LATE_ATTRIBUTION_CHANGE_KEY,
        detect_late_attribution_change,
        flow_attribution,
        flow_identity,
    )

    addon, store = recorder
    discovery = ServiceDiscovery()
    operator = OperatorProvenance()
    request_ids = RequestIdGenerator()
    flow = _flow(agent=None if identity_state == "unavailable" else "agent-a")
    if identity_state == "conflict":
        discovery._ip_to_name = {"192.0.2.20": "agent-b"}

    with taddons.context(addon, discovery, operator, request_ids):
        discovery.request(flow)
        original_identity = flow_identity(flow, discovery)
        original_attribution = flow_attribution(flow, discovery)
        if identity_state == "late_change":
            discovery._ip_to_name = {"192.0.2.20": "agent-b"}
            assert detect_late_attribution_change(flow, discovery)
        operator._remember(flow)
        flow.backup()
        flow.is_replay = "request"
        flow.response = None
        operator._view_update(flow)
        request_ids.request(flow)
        operator.request(flow)
        discovery.request(flow)
        flow.response = http.Response.make(200, b"replayed")
        enqueue = _invoke(addon, store, flow)

    attribution = flow_attribution(flow, discovery)
    assert flow_identity(flow, discovery) == original_identity
    assert attribution.evidence_owner == original_attribution.evidence_owner
    assert attribution.initiator.value == "operator"
    if identity_state == "late_change":
        assert flow.metadata[LATE_ATTRIBUTION_CHANGE_KEY]["quarantined"] is True
    else:
        assert attribution.status == original_attribution.status
        assert attribution.evidence_owner is None
    enqueue.assert_not_called()
    assert store.search_flows({}) == []


def test_record_build_failure_is_best_effort_and_counted(recorder):
    addon, store = recorder
    flow = _flow()
    # A non-dict context reaches the real record builder and fails on .get.
    flow.metadata["test_context"] = True
    enqueue = _invoke(addon, store, flow)
    enqueue.assert_not_called()
    assert addon.get_stats()["errors"] == 1
    assert addon.get_stats()["recorded"] == 0


def test_late_identity_change_between_gate_and_build_is_quarantined(recorder):
    """The gate/build pair cannot store evidence after ownership changes."""
    from service_discovery import ServiceDiscovery

    addon, store = recorder
    discovery = ServiceDiscovery()
    discovery._ip_to_name = {"192.0.2.20": "agent-a"}
    flow = _flow()

    with patch("safeyolo.core.utils.find_addon", autospec=True, return_value=discovery), \
         patch("safeyolo.core.utils.write_event", autospec=True):
        original_build = addon._build_record

        def mutate_before_build(current_flow, flow_state):
            discovery._ip_to_name["192.0.2.20"] = "agent-b"
            return original_build(current_flow, flow_state)

        with patch.object(
            addon,
            "_build_record",
            autospec=True,
            side_effect=mutate_before_build,
        ):
            addon.response(flow)

    assert store.search_flows({}) == []
    assert addon.get_stats()["skipped"] == 1
    assert addon.get_stats()["errors"] == 0


def test_writer_backpressure_and_write_failures_surface_in_stats(recorder):
    addon, _ = recorder
    writer = create_autospec(_FlowWriter, instance=True, spec_set=True)
    writer.dropped_queue_full = 3
    writer.dropped_on_error = 2
    getter = create_autospec(flow_writer.get_writer, spec_set=True, return_value=writer)
    with patch("safeyolo.core.flow_writer.get_writer", new=getter):
        stats = addon.get_stats()
    assert stats == {
        "recorded": 0,
        "errors": 0,
        "skipped": 0,
        "queue_dropped": 3,
        "write_errors": 2,
    }


def test_shutdown_stops_writer_before_closing_real_store(tmp_path):
    order: list[str] = []

    class TrackingFlowStore(FlowStore):
        def close(self):
            order.append("store.close")
            super().close()

    addon = FlowRecorder()
    store = TrackingFlowStore(str(tmp_path / "shutdown.sqlite3"))
    store.init_db()
    addon.store = store
    writer = create_autospec(_FlowWriter, instance=True, spec_set=True)
    writer._shutdown.side_effect = lambda: order.append("writer.shutdown")
    getter = create_autospec(flow_writer.get_writer, spec_set=True, return_value=writer)

    with patch("safeyolo.core.flow_writer.get_writer", new=getter):
        addon.done()

    assert order == ["writer.shutdown", "store.close"]


def test_running_uses_real_store_and_installs_writer(tmp_path):
    addon = FlowRecorder()
    db_path = tmp_path / "running.sqlite3"
    installer = create_autospec(flow_writer.install, spec_set=True)
    with taddons.context(addon) as context, patch(
        "safeyolo.core.config_cache.addon_section", new=lambda name: {}
    ), patch("safeyolo.core.flow_writer.install", new=installer):
        context.options.flow_store_db_path = str(db_path)
        addon.running()

    assert isinstance(addon.store, FlowStore)
    assert db_path.exists()
    installer.assert_called_once_with(addon.store)
    addon.store.close()
