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

    def test_downstream_addons_show_prior_response(self, traced_flow):
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

        # taddons.context is needed for addons that read ctx.options in their
        # early paths; the block short-circuit means most of that code never
        # runs, but the option namespace still needs to exist.
        with taddons.context(blocker, *downstream):
            blocker.request(traced_flow)
            for addon in downstream:
                addon.request(traced_flow)

        record = get_store().get(TRACED_REQUEST_ID, TRACED_AGENT)
        assert record is not None
        steps = _steps_by_addon(record)

        assert steps["test-early-blocker"].state == STATE_EVALUATED
        assert steps["test-early-blocker"].outcome == "blocked"

        for name in (
            "circuit-breaker",
            "credential-guard",
            "pattern-scanner",
            "network-guard",
            "service-gateway",
            "test-context",
        ):
            assert name in steps, f"{name} did not appear in trace"
            assert steps[name].state == STATE_BYPASSED, f"{name} state != bypassed"
            assert steps[name].reason == REASON_PRIOR_RESPONSE, (
                f"{name} reason != prior_response (got {steps[name].reason!r})"
            )


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
