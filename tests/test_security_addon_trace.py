"""Trace-instrumentation contract for `SecurityAddon` (issue #213).

These tests exercise the base-class wrappers (`is_bypassed`, `block`,
`warn`, `_trace_evaluated`, `_trace_bypassed`, `_trace_error`) to prove
that opt-in traces reflect what actually happened in the addon pipeline
and that non-traced requests pay no cost.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from mitmproxy.test import taddons, tflow

from safeyolo.core.base import SecurityAddon
from safeyolo.core.trace import (
    STATE_BYPASSED,
    STATE_EVALUATED,
    get_store,
    reset_store_for_tests,
)
from safeyolo.proxy_modes.unix_listener import UnixMode


class _TestAddon(SecurityAddon):
    name = "unit-test-addon"


@pytest.fixture
def fresh_store():
    reset_store_for_tests()
    yield get_store()
    reset_store_for_tests()


def _traced_flow(request_id="req-aabbccdd11223344aabbccdd11223344", agent="agent-1"):
    flow = tflow.tflow()
    flow.client_conn.proxy_mode = UnixMode.parse(
        f"unix:/tmp/10.0.0.5_{agent}/proxy.sock"
    )
    flow.metadata["trace"] = True
    flow.metadata["request_id"] = request_id
    flow.metadata["agent"] = agent
    return flow


def _untraced_flow(request_id="req-ffffffffffffffffffffffffffffffff"):
    flow = tflow.tflow()
    flow.metadata["request_id"] = request_id
    return flow


# =============================================================================
# is_bypassed: prior_response vs policy_disabled
# =============================================================================


class TestIsBypassedTrace:
    def test_prior_response_recorded_by_is_bypassed(self, fresh_store):
        """`is_bypassed` records `prior_response` — the addon owns its
        short-circuit decision AND its trace evidence (issue #213 second-pass
        review: tracing must not alter which code executes; the decorator is
        observation-only and does NOT emit `bypassed/*` on the addon's behalf).
        """
        from mitmproxy import http as mitm_http

        addon = _TestAddon()
        flow = _traced_flow()
        flow.response = mitm_http.Response.make(403, b"", {})

        assert addon.is_bypassed(flow) is True

        rec = fresh_store.get(flow.metadata["request_id"], "agent-1")
        assert rec is not None
        assert len(rec.steps) == 1
        assert rec.steps[0].state == STATE_BYPASSED
        assert rec.steps[0].reason == "prior_response"

    def test_policy_disabled_recorded_as_bypassed(self, fresh_store):
        addon = _TestAddon()
        flow = _traced_flow()

        mock_client = type("MockClient", (), {"is_addon_enabled": staticmethod(lambda *_a, **_kw: False)})
        with patch("safeyolo.core.base.get_policy_client", return_value=mock_client, autospec=True,):
            assert addon.is_bypassed(flow) is True

        rec = fresh_store.get(flow.metadata["request_id"], "agent-1")
        assert rec is not None
        assert rec.steps[0].reason == "policy_disabled"

    def test_untraced_flow_records_nothing(self, fresh_store):
        from mitmproxy import http as mitm_http

        addon = _TestAddon()
        flow = _untraced_flow()
        flow.response = mitm_http.Response.make(403, b"", {})
        addon.is_bypassed(flow)
        assert fresh_store.get(flow.metadata["request_id"], "agent-1") is None


# =============================================================================
# block / warn
# =============================================================================


class TestBlockAndWarnTrace:
    def test_block_records_evaluated_blocked(self, fresh_store):
        addon = _TestAddon()
        with taddons.context(addon):
            flow = _traced_flow()
            addon.block(flow, 403, {"error": "no"})

        rec = fresh_store.get(flow.metadata["request_id"], "agent-1")
        assert rec is not None
        step = rec.steps[0]
        assert step.state == STATE_EVALUATED
        assert step.outcome == "blocked"
        assert step.details == {"status": 403}

    def test_block_stamps_request_id_on_response(self, fresh_store):
        addon = _TestAddon()
        with taddons.context(addon):
            flow = _traced_flow()
            addon.block(flow, 403, {"error": "no"})
        assert flow.response.headers["X-SafeYolo-Request-Id"] == flow.metadata["request_id"]

    def test_warn_records_evaluated_warned(self, fresh_store):
        addon = _TestAddon()
        flow = _traced_flow()
        addon.warn(flow)

        rec = fresh_store.get(flow.metadata["request_id"], "agent-1")
        assert rec is not None
        step = rec.steps[0]
        assert step.state == STATE_EVALUATED
        assert step.outcome == "warned"


# =============================================================================
# Failure isolation
# =============================================================================


class TestTraceInstrumentationIsolation:
    def test_trace_failure_does_not_regress_enforcement(self, fresh_store, monkeypatch):
        """A bug in trace recording must not prevent the addon from blocking."""
        addon = _TestAddon()

        def _boom(*_a, **_kw):
            raise RuntimeError("simulated store failure")

        monkeypatch.setattr(fresh_store, "append_step", _boom)

        with taddons.context(addon):
            flow = _traced_flow()
            # Would raise if trace exception propagated back into block().
            addon.block(flow, 403, {"error": "no"})

        # Enforcement side-effects still happened.
        assert flow.response is not None
        assert flow.response.status_code == 403
        assert flow.metadata["blocked_by"] == "unit-test-addon"
