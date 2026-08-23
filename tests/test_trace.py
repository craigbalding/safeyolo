"""Tests for the opt-in per-request trace substrate (issue #213).

Covers the pure `TraceStore` mechanics and the `record_step` call-site
contract — the /trace endpoint lives in `test_agent_api.py::TestTrace`.
"""

from __future__ import annotations

import time

import pytest
from mitmproxy.test import tflow

from safeyolo.core import trace as trace_mod
from safeyolo.core.trace import (
    STATE_EVALUATED,
    STATE_NOT_LOADED,
    Step,
    TraceStore,
    get_store,
    record_step,
    reset_store_for_tests,
    set_expected_addons,
)

# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def fresh_store():
    """Isolated singleton per test — prevents cross-test bleed."""
    reset_store_for_tests()
    yield get_store()
    reset_store_for_tests()


@pytest.fixture
def traced_flow():
    """A flow that opted into tracing with a canonical request_id + agent."""
    flow = tflow.tflow()
    flow.metadata["trace"] = True
    flow.metadata["request_id"] = "req-aabbccdd11223344aabbccdd11223344"
    flow.metadata["agent"] = "agent-1"
    return flow


@pytest.fixture
def untraced_flow():
    """A flow with a request_id but no trace opt-in."""
    flow = tflow.tflow()
    flow.metadata["request_id"] = "req-ffffffffffffffffffffffffffffffff"
    return flow


# =============================================================================
# record_step — the call-site contract
# =============================================================================

class TestRecordStep:
    def test_no_op_when_trace_flag_absent(self, fresh_store, untraced_flow):
        """`record_step` must be free when tracing wasn't opted-in."""
        record_step(untraced_flow, addon="x", hook="request", state=STATE_EVALUATED)
        assert fresh_store.get(
            untraced_flow.metadata["request_id"], "agent-1"
        ) is None

    def test_no_op_when_request_id_missing(self, fresh_store):
        flow = tflow.tflow()
        flow.metadata["trace"] = True
        record_step(flow, addon="x", hook="request", state=STATE_EVALUATED)
        # No record was created: iterate store's internal map to confirm.
        assert not fresh_store._records

    def test_swallows_exceptions(self, fresh_store, traced_flow, monkeypatch):
        """An exception inside append_step must not propagate back to the
        addon — enforcement must never regress because of a trace bug.
        """
        def _boom(*_a, **_kw):
            raise RuntimeError("simulated trace-store failure")

        monkeypatch.setattr(fresh_store, "append_step", _boom)
        # Should not raise
        record_step(traced_flow, addon="x", hook="request", state=STATE_EVALUATED)

    def test_records_step_with_full_metadata(self, fresh_store, traced_flow):
        record_step(
            traced_flow,
            addon="credential-guard",
            hook="request",
            state=STATE_EVALUATED,
            outcome="no_detection",
            duration_us=42,
            details={"rules_evaluated": 3},
        )
        rec = fresh_store.get(traced_flow.metadata["request_id"], "agent-1")
        assert rec is not None
        assert len(rec.steps) == 1
        step = rec.steps[0]
        assert step.addon == "credential-guard"
        assert step.state == STATE_EVALUATED
        assert step.outcome == "no_detection"
        assert step.duration_us == 42
        assert step.details == {"rules_evaluated": 3}


# =============================================================================
# Store — ordering, TTL, caps, LRU
# =============================================================================

class TestTraceStoreOrdering:
    def test_preserves_step_order(self):
        store = TraceStore()
        for i, addon in enumerate(["a", "b", "c"]):
            store.append_step("req-x", "agent-1", Step(addon=addon, hook="request", state=STATE_EVALUATED))
        rec = store.get("req-x", "agent-1")
        assert [s.addon for s in rec.steps] == ["a", "b", "c"]

    def test_step_cap_marks_truncated(self):
        store = TraceStore(steps_max=3)
        for i in range(5):
            store.append_step(
                "req-x", "agent-1",
                Step(addon=f"a{i}", hook="request", state=STATE_EVALUATED),
            )
        rec = store.get("req-x", "agent-1")
        assert len(rec.steps) == 3
        assert rec.truncated is True


class TestTraceStoreAgentScope:
    def test_wrong_agent_returns_none(self):
        store = TraceStore()
        store.append_step("req-x", "agent-a", Step(addon="x", hook="request", state=STATE_EVALUATED))
        assert store.get("req-x", "agent-b") is None
        assert store.get("req-x", "agent-a") is not None

    def test_none_agent_never_reads(self):
        """A None/unknown caller cannot read anyone's trace — including one
        that was recorded with agent=None. Prevents `?agent=None` becoming
        a wildcard."""
        store = TraceStore()
        store.append_step("req-x", None, Step(addon="x", hook="request", state=STATE_EVALUATED))
        assert store.get("req-x", None) is None
        # ...and a resolved caller who doesn't match the (None) owner also
        # gets nothing:
        assert store.get("req-x", "agent-a") is None

    def test_unknown_id_returns_none_same_as_wrong_agent(self):
        """Missing and wrong-agent look identical to the caller."""
        store = TraceStore()
        store.append_step("req-x", "agent-a", Step(addon="x", hook="request", state=STATE_EVALUATED))
        assert store.get("req-missing", "agent-a") is None
        assert store.get("req-x", "agent-b") is None

    def test_agent_id_latched_on_first_write(self):
        """First writer wins on agent_id — a later mis-attributed write
        cannot re-claim ownership of an existing trace."""
        store = TraceStore()
        store.append_step("req-x", "agent-a", Step(addon="x", hook="request", state=STATE_EVALUATED))
        store.append_step("req-x", "agent-b", Step(addon="y", hook="request", state=STATE_EVALUATED))
        rec = store.get("req-x", "agent-a")
        assert rec is not None
        assert rec.agent_id == "agent-a"
        # agent-b still cannot read
        assert store.get("req-x", "agent-b") is None


class TestTraceStoreCaps:
    def test_global_cap_evicts_oldest(self):
        store = TraceStore(global_max=2, per_agent_max=10)
        store.append_step("req-a", "agent-1", Step(addon="x", hook="request", state=STATE_EVALUATED))
        store.append_step("req-b", "agent-1", Step(addon="x", hook="request", state=STATE_EVALUATED))
        store.append_step("req-c", "agent-1", Step(addon="x", hook="request", state=STATE_EVALUATED))
        assert store.get("req-a", "agent-1") is None  # evicted
        assert store.get("req-b", "agent-1") is not None
        assert store.get("req-c", "agent-1") is not None

    def test_per_agent_cap_evicts_only_that_agents(self):
        store = TraceStore(global_max=100, per_agent_max=2)
        store.append_step("req-a1", "agent-A", Step(addon="x", hook="request", state=STATE_EVALUATED))
        store.append_step("req-b1", "agent-B", Step(addon="x", hook="request", state=STATE_EVALUATED))
        store.append_step("req-a2", "agent-A", Step(addon="x", hook="request", state=STATE_EVALUATED))
        store.append_step("req-a3", "agent-A", Step(addon="x", hook="request", state=STATE_EVALUATED))
        # oldest agent-A trace evicted; agent-B untouched
        assert store.get("req-a1", "agent-A") is None
        assert store.get("req-a2", "agent-A") is not None
        assert store.get("req-a3", "agent-A") is not None
        assert store.get("req-b1", "agent-B") is not None


class TestTraceStoreTTL:
    def test_expires_records_older_than_ttl(self, monkeypatch):
        store = TraceStore(ttl_s=1)
        store.append_step(
            "req-old", "agent-1",
            Step(addon="x", hook="request", state=STATE_EVALUATED, ts=time.time() - 5),
        )
        # Force created_at back too so both "last activity" candidates are stale.
        rec = store._records["req-old"]
        rec.created_at = time.time() - 5
        # Any subsequent read triggers the TTL sweep.
        assert store.get("req-old", "agent-1") is None


# =============================================================================
# Serialisation & safety
# =============================================================================

@pytest.fixture
def isolated_manifest():
    """Snapshot the manifest and restore on exit. Tests that set a scoped
    manifest use this to avoid bleeding into other tests."""
    original = list(trace_mod.EXPECTED_ADDONS)
    yield
    set_expected_addons(original)


class TestSerialise:
    def test_not_loaded_diff_from_expected(self, isolated_manifest):
        set_expected_addons(["network-guard", "credential-guard", "pattern-scanner"])

        store = TraceStore()
        store.append_step(
            "req-x", "agent-1",
            Step(addon="credential-guard", hook="request", state=STATE_EVALUATED),
        )
        rec = store.get("req-x", "agent-1")
        payload = store.serialise(rec)
        not_loaded_names = [e["addon"] for e in payload["not_loaded"]]
        assert set(not_loaded_names) == {"network-guard", "pattern-scanner"}
        for entry in payload["not_loaded"]:
            assert entry["state"] == STATE_NOT_LOADED

    def test_details_reject_nested_structures(self):
        """Complex values in `details` must be coerced to a type-name
        marker so trace never accidentally carries request/response
        bodies or header dumps a caller passed by reference."""
        store = TraceStore()
        store.append_step(
            "req-x", "agent-1",
            Step(
                addon="x", hook="request", state=STATE_EVALUATED,
                details={"scalar": "ok", "leak_attempt": {"authorization": "Bearer abc"}},
            ),
        )
        payload = store.serialise(store.get("req-x", "agent-1"))
        details = payload["steps"][0]["details"]
        assert details["scalar"] == "ok"
        assert details["leak_attempt"] == "<dict>"

    def test_details_over_cap_is_truncated_flag(self):
        store = TraceStore(details_max_bytes=64)
        store.append_step(
            "req-x", "agent-1",
            Step(
                addon="x", hook="request", state=STATE_EVALUATED,
                details={f"k{i}": "value-that-is-long-enough" for i in range(20)},
            ),
        )
        payload = store.serialise(store.get("req-x", "agent-1"))
        assert payload["steps"][0]["details"] == {"_truncated": True}

    def test_none_fields_dropped_from_payload(self):
        store = TraceStore()
        store.append_step(
            "req-x", "agent-1",
            Step(addon="x", hook="request", state=STATE_EVALUATED),
        )
        step = store.serialise(store.get("req-x", "agent-1"))["steps"][0]
        # No noise for fields that weren't set — makes the wire payload
        # meaningful when a key IS present.
        assert "outcome" not in step
        assert "reason" not in step
        assert "duration_us" not in step
        assert "details" not in step
        assert "ts" not in step  # ts is internal, never on the wire
