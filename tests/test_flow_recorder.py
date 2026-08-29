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
    assert detail["is_websocket"] == 1
    assert [
        {"tag": tag["tag"], "value": tag["value"]} for tag in detail["tags"]
    ] == [
        {"tag": "operator_action", "value": "replay"},
        {"tag": "source_flow_id", "value": "17"},
    ]


def test_record_build_failure_is_best_effort_and_counted(recorder):
    addon, store = recorder
    flow = _flow()
    # A non-dict context reaches the real record builder and fails on .get.
    flow.metadata["test_context"] = True
    enqueue = _invoke(addon, store, flow)
    enqueue.assert_not_called()
    assert addon.get_stats()["errors"] == 1
    assert addon.get_stats()["recorded"] == 0


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
