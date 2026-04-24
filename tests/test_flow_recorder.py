"""Tests for addons/flow_recorder.py - mitmproxy flow recording addon."""

import json
import time
from unittest.mock import MagicMock

import pytest
from flow_recorder import FlowRecorder
from mitmproxy import http
from mitmproxy.test import taddons, tflow

from safeyolo.storage.flow_store import FlowStore


@pytest.fixture
def recorder(tmp_path):
    """Create a FlowRecorder with an in-memory FlowStore."""
    addon = FlowRecorder()
    with taddons.context(addon) as tctx:
        tctx.options.flow_store_enabled = True
        tctx.options.flow_store_db_path = str(tmp_path / "test_flows.sqlite3")

        # Initialize store directly (bypass PDP config loading) and
        # wire up the async writer that `response`/`error` now enqueue
        # through. Tests asserting on `store.search_flows` must first
        # call `_drain_flow_writer()` to wait for background writes.
        store = FlowStore(db_path=tctx.options.flow_store_db_path)
        store.init_db()
        addon.store = store
        import safeyolo.core.flow_writer as flow_writer
        flow_writer._writer = None  # reset between tests
        flow_writer.install(store)

        # `FlowRecorder.response`/`.error` now enqueue to the async
        # writer instead of calling `store.record_flow` synchronously.
        # Tests read via `addon.store.search_flows` right after the
        # hook call, so wrap it here to auto-drain the writer first.
        # Keeps every test body unchanged.
        _orig_search = store.search_flows
        def search_flows_autodrain(*args, **kwargs):
            w = flow_writer.get_writer()
            if w is not None:
                w.wait_for_drain(timeout_s=3.0)
            return _orig_search(*args, **kwargs)
        store.search_flows = search_flows_autodrain  # type: ignore[method-assign]

        yield addon

        w = flow_writer.get_writer()
        if w is not None:
            w._shutdown()
        store.close()


def _drain_flow_writer() -> None:
    """Block until the async writer has applied all enqueued records.

    `FlowRecorder.response`/`.error` enqueue onto a background thread;
    tests that then assert on `addon.store.search_flows` must wait.
    """
    import safeyolo.core.flow_writer as flow_writer
    w = flow_writer.get_writer()
    assert w is not None, "flow_writer was not installed for this test"
    assert w.wait_for_drain(timeout_s=3.0), "flow writer failed to drain"


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

    def test_request_id_recorded(self, recorder):
        """request_id from flow metadata appears in the stored record."""
        flow = _make_test_flow(request_id="req-abc123xyz")
        recorder.response(flow)

        results = recorder.store.search_flows({})
        assert len(results) == 1
        assert results[0]["request_id"] == "req-abc123xyz"

    def test_url_parts_extracted(self, recorder):
        """scheme, host, port, method, path, full_url are extracted from the request."""
        flow = _make_test_flow(
            method="POST",
            url="https://app.example.com:8443/api/v2/items",
        )
        flow.request.host = "app.example.com"
        flow.request.port = 8443
        flow.request.scheme = "https"
        recorder.response(flow)

        results = recorder.store.search_flows({})
        assert len(results) == 1
        row_id = results[0]["id"]
        full = recorder.store.get_flow(row_id)
        assert full["scheme"] == "https"
        assert full["host"] == "app.example.com"
        assert full["port"] == 8443
        assert full["method"] == "POST"
        assert full["path"] == "/api/v2/items"
        assert full["full_url"] == "https://app.example.com:8443/api/v2/items"

    def test_path_strips_query_string(self, recorder):
        """path field does not include query parameters; they go to query_string."""
        flow = _make_test_flow(
            url="https://app.example.com/search?q=hello&page=2",
        )
        # MultiDictView.to_dict() exists in production mitmproxy but may be
        # absent in test mitmproxy versions.  Patch at the class level so the
        # property-based accessor returns an object that supports to_dict.
        from mitmproxy.coretypes.multidict import MultiDictView
        _orig = getattr(MultiDictView, "to_dict", None)
        if _orig is None:
            MultiDictView.to_dict = lambda self: dict(self)
        try:
            recorder.response(flow)
        finally:
            if _orig is None:
                del MultiDictView.to_dict

        results = recorder.store.search_flows({})
        assert len(results) == 1
        assert results[0]["path"] == "/search"
        row_id = results[0]["id"]
        full = recorder.store.get_flow(row_id)
        qs = json.loads(full["query_string"])
        assert qs == {"q": "hello", "page": "2"}

    def test_timestamps_are_epoch_ms(self, recorder):
        """ts_start and ts_end are epoch milliseconds; duration_ms >= 0."""
        before_ms = int(time.time() * 1000)
        flow = _make_test_flow()
        # start_time is set to time.time() - 0.1 in _make_test_flow
        recorder.response(flow)
        after_ms = int(time.time() * 1000)

        results = recorder.store.search_flows({})
        assert len(results) == 1
        ts_start = results[0]["ts_start"]
        ts_end = results[0]["ts_end"]
        duration_ms = results[0]["duration_ms"]
        # ts_start derived from start_time (100ms before now)
        assert ts_start < ts_end
        # ts_end should be in the range [before, after]
        assert before_ms <= ts_end <= after_ms
        # duration should be approximately 100ms (start_time was 0.1s ago)
        assert duration_ms >= 0
        assert 50 <= duration_ms <= 2000

    def test_start_time_fallback_when_missing(self, recorder):
        """When start_time is not in metadata, ts_start is still set to current time."""
        flow = _make_test_flow()
        del flow.metadata["start_time"]

        before_ms = int(time.time() * 1000)
        recorder.response(flow)
        after_ms = int(time.time() * 1000)

        results = recorder.store.search_flows({})
        assert len(results) == 1
        ts_start = results[0]["ts_start"]
        ts_end = results[0]["ts_end"]
        # Both should be approximately "now"
        assert before_ms <= ts_start <= after_ms
        assert before_ms <= ts_end <= after_ms
        # duration_ms should be ~0 (both timestamps are "now")
        assert results[0]["duration_ms"] >= 0
        assert results[0]["duration_ms"] <= 1000

    def test_is_websocket_flag_recorded(self, recorder):
        """is_websocket metadata flag is persisted in the record."""
        flow = _make_test_flow()
        flow.metadata["is_websocket"] = True
        recorder.response(flow)

        results = recorder.store.search_flows({})
        assert len(results) == 1
        assert results[0]["is_websocket"] == 1  # SQLite stores bools as int


class TestHeaderRedaction:
    def test_gateway_injected_header_redacted(self, recorder):
        """SECURITY: gateway-injected credential header value is not stored in cleartext."""
        flow = _make_test_flow()
        flow.request.headers["Authorization"] = "Bearer sk-secret-key-value-12345678"
        flow.metadata["gateway_injected_header"] = "Authorization"
        recorder.response(flow)

        results = recorder.store.search_flows({})
        row_id = results[0]["id"]
        full = recorder.store.get_flow(row_id)
        headers = json.loads(full["request_headers_json"])

        # Find the Authorization header in the stored pairs
        auth_values = [v for name, v in headers if name.lower() == "authorization"]
        assert len(auth_values) == 1
        # Must be redacted with [GATEWAY:...] pattern, not the raw value
        assert auth_values[0].startswith("[GATEWAY:...")
        assert "sk-secret-key-value-12345678" not in auth_values[0]
        # Last 4 chars of the original value are preserved as suffix
        assert auth_values[0] == "[GATEWAY:...5678]"


class TestBlockedAndErrorReasons:
    def test_blocked_flow_reason_from_metadata(self, recorder):
        """Blocked flows record the blocked_by addon name as the reason."""
        flow = _make_test_flow(response_status=403)
        flow.metadata["blocked_by"] = "credential-guard"
        recorder.response(flow)

        results = recorder.store.search_flows({})
        assert len(results) == 1
        assert results[0]["flow_state"] == "blocked"
        assert results[0]["reason"] == "credential-guard"

    def test_error_flow_reason_from_error_msg(self, recorder):
        """Error flows record the error message as the reason."""
        flow = _make_test_flow(request_id="req-err-reason1")
        flow.response = None
        flow.error = MagicMock()
        flow.error.msg = "Connection refused"
        recorder.error(flow)

        results = recorder.store.search_flows({})
        assert len(results) == 1
        assert results[0]["flow_state"] == "error"
        assert results[0]["reason"] == "Connection refused"


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

    def test_error_flow_with_broken_store_surfaces_as_write_error(self, recorder):
        """A flow whose async write fails lands as `write_errors`, not
        hook-side `errors`. (Post-async refactor: `recorded` counts
        successful enqueues; persistent-write failures are tracked by
        the background writer and surfaced via `get_stats()`.)"""
        flow = _make_test_flow(request_id="req-err-count1")
        flow.response = None
        flow.error = MagicMock()
        flow.error.msg = "timeout"

        # Break the store so the writer thread's record_flow raises.
        recorder.store.close()
        recorder.store._conn = None

        recorder.error(flow)
        # Enqueue succeeded, so the hook counts the record.
        assert recorder._stats["recorded"] == 1
        assert recorder._stats["errors"] == 0

        # Let the writer pick it up and fail; the error ends up on the
        # writer's counter, visible via get_stats().
        import safeyolo.core.flow_writer as flow_writer
        flow_writer.get_writer().wait_for_drain(timeout_s=3.0)
        stats = recorder.get_stats()
        assert stats["write_errors"] == 1


class TestBestEffort:
    def test_db_write_failure_doesnt_raise(self, recorder):
        """Writer-thread DB failures are caught + counted, not raised.

        Post-async: the hook returns before the write runs, so errors
        appear on the writer's `write_errors` counter (surfaced via
        `get_stats()`), not the hook-side `errors` counter."""
        flow = _make_test_flow()
        recorder.store.close()
        recorder.store._conn = None

        # Should not raise from the hook.
        recorder.response(flow)
        import safeyolo.core.flow_writer as flow_writer
        flow_writer.get_writer().wait_for_drain(timeout_s=3.0)
        assert recorder.get_stats()["write_errors"] == 1

    def test_error_hook_failure_doesnt_raise(self, recorder):
        """Same guarantee for the error() hook path."""
        flow = _make_test_flow()
        flow.error = MagicMock()
        flow.error.msg = "timeout"
        recorder.store.close()
        recorder.store._conn = None

        recorder.error(flow)
        import safeyolo.core.flow_writer as flow_writer
        flow_writer.get_writer().wait_for_drain(timeout_s=3.0)
        assert recorder.get_stats()["write_errors"] == 1


class TestLifecycle:
    def test_done_closes_store(self, tmp_path):
        """done() closes the FlowStore connection."""
        addon = FlowRecorder()
        with taddons.context(addon) as tctx:
            tctx.options.flow_store_enabled = True
            tctx.options.flow_store_db_path = str(tmp_path / "lifecycle.sqlite3")

            store = FlowStore(db_path=tctx.options.flow_store_db_path)
            store.init_db()
            addon.store = store

            addon.done()

            # After done(), the store connection should be None (closed)
            assert store._conn is None

    def test_done_safe_when_no_store(self):
        """done() does not raise when store was never initialized."""
        addon = FlowRecorder()
        assert addon.store is None
        # Should not raise
        addon.done()

    def test_running_disabled_leaves_store_none(self, tmp_path):
        """When flow_store_enabled=False, running() does not create a store."""
        addon = FlowRecorder()
        with taddons.context(addon) as tctx:
            tctx.options.flow_store_enabled = False
            tctx.options.flow_store_db_path = str(tmp_path / "nope.sqlite3")

            addon.running()

            assert addon.store is None


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

    def test_get_stats_returns_independent_copy(self, recorder):
        """get_stats() returns a copy; mutating it does not affect internal state."""
        flow = _make_test_flow(request_id="req-copy00001")
        recorder.response(flow)

        stats1 = recorder.get_stats()
        assert stats1["recorded"] == 1

        # Mutate the returned dict
        stats1["recorded"] = 999
        stats1["skipped"] = 999

        # Internal state is unchanged
        stats2 = recorder.get_stats()
        assert stats2["recorded"] == 1
        assert stats2["skipped"] == 0
