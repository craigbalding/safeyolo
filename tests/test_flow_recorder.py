"""Tests for addons/flow_recorder.py - mitmproxy flow recording addon."""

import time
from unittest.mock import MagicMock

import pytest
from flow_recorder import FlowRecorder
from flow_store import FlowStore
from mitmproxy import http
from mitmproxy.test import taddons, tflow


@pytest.fixture
def recorder(tmp_path):
    """Create a FlowRecorder with an in-memory FlowStore."""
    addon = FlowRecorder()
    with taddons.context(addon) as tctx:
        tctx.options.flow_store_enabled = True
        tctx.options.flow_store_db_path = str(tmp_path / "test_flows.sqlite3")

        # Initialize store directly (bypass PDP config loading)
        store = FlowStore(db_path=tctx.options.flow_store_db_path)
        store.init_db()
        addon.store = store

        yield addon

        store.close()


def _make_test_flow(
    method="GET",
    url="https://app.example.com/api/todos/42",
    response_status=200,
    response_body=b'{"id":42}',
    response_ct="application/json",
    with_context=True,
    agent="agent-1",
    request_id="req-test000001",
):
    """Create a test flow with standard metadata."""
    flow = tflow.tflow()
    flow.request.method = method
    flow.request.url = url
    flow.request.host = "app.example.com"
    flow.request.content = b""

    flow.response = http.Response.make(
        response_status,
        response_body,
        {"Content-Type": response_ct},
    )

    flow.metadata["request_id"] = request_id
    flow.metadata["start_time"] = time.time() - 0.1
    flow.metadata["agent"] = agent

    if with_context:
        flow.metadata["ccapt_context"] = {
            "run": "sec1",
            "agent": "idor",
            "test": "IDOR-003",
        }

    return flow


class TestScopeGate:
    def test_flow_without_ccapt_context_is_skipped(self, recorder):
        """Flows without ccapt_context metadata are not recorded."""
        flow = _make_test_flow(with_context=False)
        recorder.response(flow)
        assert recorder._stats["skipped"] == 1
        assert recorder._stats["recorded"] == 0

    def test_agent_api_requests_skipped(self, recorder):
        """Requests to agent API host are not recorded."""
        flow = _make_test_flow()
        flow.request.host = "_safeyolo.proxy.internal"
        recorder.response(flow)
        assert recorder._stats["skipped"] == 1

    def test_disabled_recorder_skips(self, recorder, tmp_path):
        """When disabled, nothing is recorded."""
        disabled = FlowRecorder()
        with taddons.context(disabled) as tctx:
            tctx.options.flow_store_enabled = False
            tctx.options.flow_store_db_path = str(tmp_path / "disabled.sqlite3")

            flow = _make_test_flow()
            disabled.response(flow)
            assert disabled._stats["skipped"] == 1

    def test_no_store_skips(self, recorder):
        """If store is None (init failed), flows are skipped."""
        recorder.store = None
        flow = _make_test_flow()
        recorder.response(flow)
        assert recorder._stats["skipped"] == 1


class TestResponseRecording:
    def test_completed_flow_recorded(self, recorder):
        flow = _make_test_flow()
        recorder.response(flow)
        assert recorder._stats["recorded"] == 1

        results = recorder.store.search_flows({})
        assert len(results) == 1
        assert results[0]["flow_state"] == "completed"
        assert results[0]["status_code"] == 200

    def test_blocked_flow_recorded(self, recorder):
        flow = _make_test_flow(response_status=403)
        flow.metadata["blocked_by"] = "credential-guard"
        recorder.response(flow)
        assert recorder._stats["recorded"] == 1

        results = recorder.store.search_flows({})
        assert len(results) == 1
        assert results[0]["flow_state"] == "blocked"

    def test_agent_id_from_metadata(self, recorder):
        flow = _make_test_flow(agent="boris")
        recorder.response(flow)

        results = recorder.store.search_flows({})
        assert results[0]["agent_id"] == "boris"
        assert results[0]["engagement_id"] == "boris"

    def test_context_fields_extracted(self, recorder):
        flow = _make_test_flow()
        flow.metadata["ccapt_context"] = {
            "run": "recon1",
            "agent": "scanner",
            "test": "SQLI-001",
            "role": "attacker",
        }
        recorder.response(flow)

        results = recorder.store.search_flows({})
        assert results[0]["run"] == "recon1"
        assert results[0]["test"] == "SQLI-001"
        assert results[0]["role"] == "attacker"


class TestErrorRecording:
    def test_error_flow_recorded(self, recorder):
        flow = _make_test_flow(request_id="req-error00001")
        flow.response = None
        flow.error = MagicMock()
        flow.error.msg = "Connection refused"
        recorder.error(flow)
        assert recorder._stats["recorded"] == 1

        results = recorder.store.search_flows({})
        assert len(results) == 1
        assert results[0]["flow_state"] == "error"

    def test_error_without_context_skipped(self, recorder):
        flow = _make_test_flow(with_context=False)
        flow.error = MagicMock()
        flow.error.msg = "DNS failure"
        recorder.error(flow)
        assert recorder._stats["skipped"] == 1


class TestBestEffort:
    def test_db_write_failure_doesnt_raise(self, recorder):
        """DB failures are caught and counted, not raised."""
        flow = _make_test_flow()
        # Close the store to force a write failure
        recorder.store.close()
        recorder.store._conn = None

        # Should not raise
        recorder.response(flow)
        assert recorder._stats["errors"] == 1

    def test_error_hook_failure_doesnt_raise(self, recorder):
        flow = _make_test_flow()
        flow.error = MagicMock()
        flow.error.msg = "timeout"
        recorder.store.close()
        recorder.store._conn = None

        recorder.error(flow)
        assert recorder._stats["errors"] == 1


class TestStats:
    def test_stats_incremented(self, recorder):
        # Record one
        flow1 = _make_test_flow(request_id="req-stats00001")
        recorder.response(flow1)

        # Skip one (no context)
        flow2 = _make_test_flow(request_id="req-stats00002", with_context=False)
        recorder.response(flow2)

        stats = recorder.get_stats()
        assert stats["recorded"] == 1
        assert stats["skipped"] == 1
        assert stats["errors"] == 0
