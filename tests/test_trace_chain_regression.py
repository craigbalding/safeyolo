"""End-to-end trace-chain regression tests for issue #213.

These three tests together prove the core promise of #213 — a request's
trace can distinguish `evaluated`, `bypassed`, and `not_loaded` for every
expected pipeline addon — rather than merely exercising helper functions.

Structure:
- A synthetic "early blocker" addon uses `SecurityAddon.block` (base wrapper)
  so the trace records `evaluated/blocked` for it.
- Real downstream addons are then invoked in sequence with the shared flow.
  The `@trace_addon_hook` decorator on each real addon detects the
  already-set `flow.response` and records `bypassed/prior_response` without
  entering the addon body, so no PDP / ServiceDiscovery / registry wiring
  is needed for those addons in the regression flow.
- Test 2 flips a global mitmproxy option to prove `bypassed/addon_disabled`.
- Test 3 monkey-patches the expected-addon registry to prove `not_loaded`
  surfaces addons that were declared expected but never called.
"""

from __future__ import annotations

import pytest
from mitmproxy.test import taddons, tflow

from safeyolo.core import trace as trace_mod
from safeyolo.core.base import SecurityAddon
from safeyolo.core.trace import (
    REASON_ADDON_DISABLED,
    REASON_PRIOR_RESPONSE,
    STATE_BYPASSED,
    STATE_EVALUATED,
    STATE_NOT_LOADED,
    get_store,
    register_expected_addon,
    reset_store_for_tests,
    trace_addon_hook,
)

TRACED_REQUEST_ID = "req-cccccc00000000000000000000000000"
TRACED_AGENT = "regression-agent"


class _EarlyBlocker(SecurityAddon):
    """Stand-in for whichever real addon blocks first in a given request.

    Uses `SecurityAddon.block` so we exercise the exact block plumbing all
    real addons rely on (audit trace + response headers). Marked
    `trace_expected` so `not_loaded` synthesis includes it when omitted.
    """
    name = "test-early-blocker"
    trace_expected = True

    @trace_addon_hook("request")
    def request(self, flow):
        self.block(flow, 403, {"error": "test-blocked-early"})


@pytest.fixture
def traced_flow():
    """A flow that already carries request_id + trace + agent metadata.

    Bypasses the RequestIdGenerator path deliberately — those tests live in
    test_request_id.py. This fixture models the state a request is in after
    the request-id addon has run.
    """
    flow = tflow.tflow()
    flow.metadata["trace"] = True
    flow.metadata["request_id"] = TRACED_REQUEST_ID
    flow.metadata["agent"] = TRACED_AGENT
    return flow


@pytest.fixture(autouse=True)
def _reset_store():
    reset_store_for_tests()
    yield
    reset_store_for_tests()


def _steps_by_addon(record):
    return {s.addon: s for s in record.steps}


# =============================================================================
# Test 1 — blocked chain: prior_response fans out to every downstream addon
# =============================================================================


class TestBlockedChainRegression:
    """When an early addon blocks, every downstream expected addon must
    appear with `bypassed/prior_response` — the central #213 promise that
    replaces silent 'missing audit event' ambiguity with explicit evidence.
    """

    def test_downstream_addons_show_prior_response(self, traced_flow, tmp_path, monkeypatch):
        """When an early addon blocks:
        - Addons with an explicit `flow.response` short-circuit emit
          `bypassed/prior_response` from their own body (credential-guard,
          test-context, service-gateway).
        - Addons that use base `is_bypassed()` emit the same from that
          method (network-guard, circuit-breaker).
        - Addons that don't check `flow.response` at all still run — the
          decorator is observation-only and MUST NOT skip the body. Their
          real outcome is recorded (pattern-scanner has no such check;
          it runs and reports `no_rules`).
        This proves tracing did not silently change which code executes.
        """
        # credential-guard.configure writes hmac secret under SAFEYOLO_DATA_DIR;
        # default '/safeyolo/data' isn't writable in this sandbox.
        monkeypatch.setenv("SAFEYOLO_DATA_DIR", str(tmp_path))

        from circuit_breaker import CircuitBreaker
        from credential_guard import CredentialGuard
        from network_guard import NetworkGuard
        from pattern_scanner import PatternScanner
        from service_gateway import ServiceGateway
        from test_context import TestContext

        blocker = _EarlyBlocker()
        downstream = [
            CircuitBreaker(),
            CredentialGuard(),
            PatternScanner(),
            NetworkGuard(),
            ServiceGateway(),
            TestContext(),
        ]

        with taddons.context(blocker, *downstream) as tctx:
            # gateway_enabled defaults to False; enable so its
            # short-circuit is prior_response rather than addon_disabled
            # (the test is about the blocked-chain fan-out, not the
            # separately-covered addon_disabled path).
            tctx.options.gateway_enabled = True
            blocker.request(traced_flow)
            for addon in downstream:
                addon.request(traced_flow)

        record = get_store().get(TRACED_REQUEST_ID, TRACED_AGENT)
        assert record is not None
        steps = _steps_by_addon(record)

        assert steps["test-early-blocker"].state == STATE_EVALUATED
        assert steps["test-early-blocker"].outcome == "blocked"

        # Addons whose own bodies short-circuit on flow.response:
        for name in (
            "credential-guard",
            "network-guard",
            "circuit-breaker",
            "service-gateway",
            "test-context",
        ):
            assert name in steps, f"{name} did not appear in trace"
            assert steps[name].state == STATE_BYPASSED, f"{name} state != bypassed"
            assert steps[name].reason == REASON_PRIOR_RESPONSE, (
                f"{name} reason != prior_response (got {steps[name].reason!r})"
            )

        # pattern-scanner has no flow.response early-return in its request
        # method — it scans regardless. The trace must reflect what actually
        # ran, not what tracing would prefer. Zero rules loaded in this test
        # environment, so the outcome is `no_rules`.
        assert steps["pattern-scanner"].state == STATE_EVALUATED
        assert steps["pattern-scanner"].outcome == "no_rules"


# =============================================================================
# Test 2 — globally disabled addon reports bypassed/addon_disabled
# =============================================================================


class TestDisabledAddonRegression:
    """A loaded-but-disabled addon must record `bypassed/addon_disabled`, not
    look identical to `not_loaded`. This is the distinction the review
    called central to why #213 exists.
    """

    def test_network_guard_disabled_shows_addon_disabled(self, traced_flow):
        from network_guard import NetworkGuard

        addon = NetworkGuard()
        with taddons.context(addon) as tctx:
            tctx.options.network_guard_enabled = False
            addon.request(traced_flow)

        record = get_store().get(TRACED_REQUEST_ID, TRACED_AGENT)
        steps = _steps_by_addon(record)
        assert steps["network-guard"].state == STATE_BYPASSED
        assert steps["network-guard"].reason == REASON_ADDON_DISABLED

    def test_service_gateway_disabled_shows_addon_disabled(self, traced_flow):
        """`service-gateway` isn't a SecurityAddon subclass — uses the
        standalone trace helpers. Verify its addon_disabled branch too.
        """
        from service_gateway import ServiceGateway

        addon = ServiceGateway()
        with taddons.context(addon) as tctx:
            tctx.options.gateway_enabled = False
            addon.request(traced_flow)

        record = get_store().get(TRACED_REQUEST_ID, TRACED_AGENT)
        steps = _steps_by_addon(record)
        assert steps["service-gateway"].state == STATE_BYPASSED
        assert steps["service-gateway"].reason == REASON_ADDON_DISABLED


# =============================================================================
# Test 3 — expected addon omitted from the loaded set shows not_loaded
# =============================================================================


class TestNotLoadedRegression:
    """An expected addon that was never called for this request must appear
    in the trace as `state=not_loaded`. This closes the ambiguity that
    prompted #213: absence-as-diagnosis rather than absence-as-silence.
    """

    def test_expected_addon_never_invoked_surfaces_as_not_loaded(
        self, traced_flow, monkeypatch
    ):
        # Isolate the expected registry so the assertions are precise.
        monkeypatch.setattr(trace_mod, "_expected_addons", [])
        register_expected_addon("network-guard")
        register_expected_addon("credential-guard")
        register_expected_addon("pattern-scanner")

        from credential_guard import CredentialGuard

        # Only credential-guard runs. network-guard and pattern-scanner are
        # expected but never called — they must appear in `not_loaded`.
        # Simulate "an earlier addon already responded" so the decorator's
        # prior_response short-circuit fires — no PDP wiring needed.
        from mitmproxy import http as mitm_http
        traced_flow.response = mitm_http.Response.make(403, b"", {})

        with taddons.context(CredentialGuard()) as tctx:
            addon = tctx.master.addons.get("credential-guard")
            addon.request(traced_flow)

        record = get_store().get(TRACED_REQUEST_ID, TRACED_AGENT)
        assert record is not None

        payload = get_store().serialise(record)
        observed = {step["addon"] for step in payload["steps"]}
        not_loaded = {entry["addon"] for entry in payload["not_loaded"]}

        assert "credential-guard" in observed
        assert not_loaded == {"network-guard", "pattern-scanner"}
        for entry in payload["not_loaded"]:
            assert entry["state"] == STATE_NOT_LOADED


# =============================================================================
# Test 4 — parity: traced and untraced execution are externally identical
# =============================================================================


class TestTracedVsUntracedParity:
    """Instrumentation must be observation-only.

    Runs the same constructed flow through the same addon chain twice —
    once with `flow.metadata['trace'] = True`, once without — and asserts
    that every externally-relevant flow mutation is identical. Trace
    records are the only permitted difference. This is the direct
    regression against a decorator that alters which code executes when
    tracing is enabled (issue #213 second-pass review).
    """

    def _build_flow(self, traced: bool):
        """A fresh flow at the state produced by RequestIdGenerator, with
        the trace opt-in metadata set (or not).
        """
        flow = tflow.tflow()
        flow.request.method = "GET"
        flow.request.url = "https://parity.example.test/thing"
        flow.metadata["request_id"] = "req-parity000000000000000000000000000" if traced else "req-untraced000000000000000000000000"
        flow.metadata["agent"] = TRACED_AGENT
        if traced:
            flow.metadata["trace"] = True
        return flow

    def _run_chain(self, flow, tmp_path, monkeypatch):
        monkeypatch.setenv("SAFEYOLO_DATA_DIR", str(tmp_path))

        from circuit_breaker import CircuitBreaker
        from credential_guard import CredentialGuard
        from network_guard import NetworkGuard
        from pattern_scanner import PatternScanner
        from service_gateway import ServiceGateway
        from test_context import TestContext

        chain = [
            NetworkGuard(),
            CircuitBreaker(),
            CredentialGuard(),
            PatternScanner(),
            ServiceGateway(),
            TestContext(),
        ]
        with taddons.context(*chain) as tctx:
            tctx.options.gateway_enabled = True
            # Skip network_guard's PDP call by treating the addon as disabled
            # for the parity comparison — otherwise both runs would fail the
            # same way (still identical), but the exception path is not what
            # we want to measure. Same for both traced and untraced runs so
            # any behavioural difference is real.
            tctx.options.network_guard_enabled = False
            for addon in chain:
                addon.request(flow)
        return flow

    def test_flow_state_identical_traced_vs_untraced(
        self, tmp_path, monkeypatch
    ):
        untraced = self._run_chain(self._build_flow(traced=False), tmp_path, monkeypatch)
        # Reset store between runs so the traced run's per-agent quota is
        # not affected by any lingering entries.
        reset_store_for_tests()
        traced = self._run_chain(self._build_flow(traced=True), tmp_path, monkeypatch)

        # Response state must be identical (neither should have set a
        # response — the parity contract is about the code path both
        # runs took, not the outcome of a synthesised block).
        assert (traced.response is None) == (untraced.response is None), (
            "trace toggling changed whether a response was synthesised"
        )

        # blocked_by / addon-owned metadata keys the enforcement path uses.
        enforcement_keys = (
            "blocked_by",
            "ratelimit_remaining",
            "credential_fingerprint",
            "pattern_matched",
            "pattern_location",
            "gateway_service",
            "gateway_capability",
            "gateway_agent",
            "gateway_account",
            "gateway_injected_header",
            "ccapt_context",
            "test_agent_match",
            "test_context_source",
        )
        for key in enforcement_keys:
            assert traced.metadata.get(key) == untraced.metadata.get(key), (
                f"metadata[{key!r}] diverged between traced/untraced runs "
                f"(traced={traced.metadata.get(key)!r}, "
                f"untraced={untraced.metadata.get(key)!r})"
            )

        # Request headers/method/URL must not have been mutated differently
        # by the two runs.
        assert dict(traced.request.headers) == dict(untraced.request.headers)
        assert traced.request.method == untraced.request.method
        assert traced.request.url == untraced.request.url

        # The traced run's flow.metadata may hold no trace-timer artefacts —
        # the decorator's `finally` clause must remove every key it set.
        for key in list(traced.metadata.keys()):
            assert not key.startswith("_trace_hook_start:"), (
                f"traced flow leaked timer key {key!r} into flow.metadata"
            )
