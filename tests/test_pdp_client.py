"""
Tests for pdp/client.py — PolicyClient registry, LocalPolicyClient, HttpPolicyClient.

Contract under test:
  - Registry: configure/get/reset singleton lifecycle, fail-closed on unconfigured
  - LocalPolicyClient: delegates to PDPCore, catches exceptions and returns Effect.ERROR
  - HttpPolicyClient: HTTP evaluate with fail-closed on 5xx/timeout/connection error,
    configurable unavailable_mode, semaphore backpressure
"""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from pdp.client import (
    HttpPolicyClient,
    LocalPolicyClient,
    PolicyClient,
    PolicyClientConfig,
    UnavailableMode,
    configure_policy_client,
    get_policy_client,
    is_policy_client_configured,
    reset_policy_client,
)
from pdp.schemas import (
    DecisionEventBlock,
    Effect,
    PolicyDecision,
    create_http_event,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(event_id: str = "evt-test-001"):
    """Build a minimal HttpEvent for tests."""
    return create_http_event(
        event_id=event_id,
        sensor_id="test-sensor",
        principal_id="agent:test",
        method="GET",
        host="example.com",
        port=443,
        path="/api/v1/test",
        headers_present=["host", "user-agent"],
    )


def _make_allow_decision(event_id: str = "evt-test-001") -> PolicyDecision:
    """Build a PolicyDecision with ALLOW effect."""
    return PolicyDecision(
        version=1,
        event=DecisionEventBlock(
            event_id=event_id,
            policy_hash="abc123",
            engine_version="pdp-0.1.0",
        ),
        effect=Effect.ALLOW,
        reason="allowed by test",
        reason_codes=["ALLOWED"],
    )


# ===========================================================================
# TestPolicyClientConfig
# ===========================================================================

class TestPolicyClientConfig:
    """PolicyClientConfig defaults and equality."""

    def test_default_mode_is_local(self):
        config = PolicyClientConfig()
        assert config.mode == "local"

    def test_default_unavailable_mode_is_deny(self):
        config = PolicyClientConfig()
        assert config.unavailable_mode == UnavailableMode.DENY

    def test_equality_same_values(self):
        a = PolicyClientConfig(mode="local", timeout_ms=500)
        b = PolicyClientConfig(mode="local", timeout_ms=500)
        assert a == b

    def test_inequality_different_values(self):
        a = PolicyClientConfig(mode="local")
        b = PolicyClientConfig(mode="http")
        assert a != b


# ===========================================================================
# TestPolicyClientRegistry
# ===========================================================================

class TestPolicyClientRegistry:
    """Singleton registry: configure, get, reset, reconfigure."""

    def setup_method(self):
        reset_policy_client()

    def teardown_method(self):
        reset_policy_client()

    def test_get_before_configure_raises_runtime_error(self):
        with pytest.raises(RuntimeError, match="not configured"):
            get_policy_client()

    def test_is_configured_false_before_configure(self):
        assert is_policy_client_configured() is False

    def test_configure_then_get_returns_client(self):
        config = PolicyClientConfig(mode="local")
        configure_policy_client(config)

        assert is_policy_client_configured() is True
        client = get_policy_client()
        assert isinstance(client, PolicyClient)
        assert isinstance(client, LocalPolicyClient)

    def test_reset_calls_shutdown_and_clears(self):
        config = PolicyClientConfig(mode="local")
        configure_policy_client(config)

        client = get_policy_client()
        with patch.object(client, "shutdown") as mock_shutdown:
            # Re-read the module-level reference via the function
            # reset_policy_client reads _client_instance directly, so
            # we patch the instance's shutdown method
            reset_policy_client()
            mock_shutdown.assert_called_once()

        assert is_policy_client_configured() is False

    def test_reset_when_no_client_is_noop(self):
        # Should not raise
        reset_policy_client()
        assert is_policy_client_configured() is False

    def test_reconfigure_same_config_is_noop(self):
        config = PolicyClientConfig(mode="local")
        configure_policy_client(config)
        first_client = get_policy_client()

        # Second call with identical config
        configure_policy_client(config)
        second_client = get_policy_client()

        assert first_client is second_client

    def test_reconfigure_different_config_replaces_client(self):
        config_a = PolicyClientConfig(mode="local")
        configure_policy_client(config_a)
        first_client = get_policy_client()

        # Reconfigure with different timeout
        config_b = PolicyClientConfig(mode="local", timeout_ms=999)
        configure_policy_client(config_b)
        second_client = get_policy_client()

        assert first_client is not second_client


# ===========================================================================
# TestLocalPolicyClient
# ===========================================================================

class TestLocalPolicyClient:
    """LocalPolicyClient delegates to PDPCore and fails closed on exceptions."""

    def setup_method(self):
        reset_policy_client()

    def teardown_method(self):
        reset_policy_client()

    def test_evaluate_happy_path_returns_policy_decision(self):
        """evaluate() returns a PolicyDecision from PDPCore."""
        config = PolicyClientConfig(mode="local")
        configure_policy_client(config)
        client = get_policy_client()

        event = _make_event()
        decision = client.evaluate(event)

        assert isinstance(decision, PolicyDecision)
        assert decision.event.event_id == "evt-test-001"
        # With no baseline loaded, PDPCore should still return a valid decision
        assert decision.effect in (Effect.ALLOW, Effect.DENY, Effect.ERROR)

    def test_evaluate_catches_pdpcore_exception_returns_error(self):
        """If PDPCore.evaluate() raises, LocalPolicyClient returns Effect.ERROR (fail-closed)."""
        config = PolicyClientConfig(mode="local")
        configure_policy_client(config)
        client = get_policy_client()

        # Force PDPCore.evaluate to raise
        with patch.object(client._pdp, "evaluate", side_effect=RuntimeError("boom")):
            event = _make_event("evt-error-test")
            decision = client.evaluate(event)

        assert decision.effect == Effect.ERROR
        assert "PDP internal error" in decision.reason
        assert "boom" in decision.reason

    def test_error_decision_has_status_500_and_reason_codes(self):
        """Error decisions must include status 500 and PDP_ERROR + INTERNAL_ERROR codes."""
        config = PolicyClientConfig(mode="local")
        configure_policy_client(config)
        client = get_policy_client()

        with patch.object(client._pdp, "evaluate", side_effect=ValueError("kaboom")):
            decision = client.evaluate(_make_event("evt-500-test"))

        assert decision.reason_codes == ["PDP_ERROR", "INTERNAL_ERROR"]
        assert decision.immediate_response is not None
        assert decision.immediate_response.status_code == 500
        assert decision.immediate_response.body_json["event_id"] == "evt-500-test"

    def test_health_check_returns_true(self):
        """Local PDP health check is always True when initialized."""
        config = PolicyClientConfig(mode="local")
        configure_policy_client(config)
        client = get_policy_client()

        assert client.health_check() is True

    def test_shutdown_delegates_to_pdpcore(self):
        """shutdown() calls PDPCore.shutdown()."""
        config = PolicyClientConfig(mode="local")
        configure_policy_client(config)
        client = get_policy_client()

        with patch.object(client._pdp, "shutdown") as mock_shutdown:
            client.shutdown()
            mock_shutdown.assert_called_once()


# ===========================================================================
# TestHttpPolicyClient
# ===========================================================================

class TestHttpPolicyClient:
    """HttpPolicyClient: HTTP evaluate paths, fail-closed, backpressure."""

    def _make_client(
        self,
        unavailable_mode: UnavailableMode = UnavailableMode.DENY,
        timeout_ms: int = 500,
        max_inflight: int = 256,
    ) -> HttpPolicyClient:
        config = PolicyClientConfig(
            mode="http",
            endpoint="http://127.0.0.1:9999",
            timeout_ms=timeout_ms,
            max_inflight=max_inflight,
            unavailable_mode=unavailable_mode,
        )
        return HttpPolicyClient(config)

    # ---- evaluate: happy path ----

    def test_evaluate_200_returns_policy_decision(self):
        """200 response with valid JSON returns a PolicyDecision."""
        client = self._make_client()
        allow = _make_allow_decision("evt-http-200")

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = allow.model_dump(mode="json")

        with patch.object(client._client, "post", return_value=mock_response):
            decision = client.evaluate(_make_event("evt-http-200"))

        assert decision.effect == Effect.ALLOW
        assert decision.event.event_id == "evt-http-200"
        assert decision.reason == "allowed by test"

    # ---- evaluate: 4xx client error ----

    def test_evaluate_4xx_returns_deny_with_pdb_error(self):
        """4xx response returns DENY with PDP_ERROR reason code."""
        client = self._make_client()

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 422
        mock_response.text = "Validation Error"

        with patch.object(client._client, "post", return_value=mock_response):
            decision = client.evaluate(_make_event("evt-4xx"))

        assert decision.effect == Effect.DENY
        assert "PDP_ERROR" in decision.reason_codes
        assert decision.immediate_response.status_code == 500

    # ---- evaluate: 5xx server error (fail-closed) ----

    def test_evaluate_5xx_returns_unavailable_deny(self):
        """5xx response returns DENY with 503 status (fail-closed)."""
        client = self._make_client()

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 502

        with patch.object(client._client, "post", return_value=mock_response):
            decision = client.evaluate(_make_event("evt-5xx"))

        assert decision.effect == Effect.DENY
        assert "PDP_UNAVAILABLE" in decision.reason_codes
        assert "FAIL_CLOSED" in decision.reason_codes
        assert decision.immediate_response.status_code == 503

    # ---- evaluate: timeout (fail-closed) ----

    def test_evaluate_timeout_returns_unavailable_deny(self):
        """Timeout returns DENY with 503 (fail-closed)."""
        client = self._make_client()

        with patch.object(
            client._client, "post", side_effect=httpx.ReadTimeout("timed out")
        ):
            decision = client.evaluate(_make_event("evt-timeout"))

        assert decision.effect == Effect.DENY
        assert "PDP_UNAVAILABLE" in decision.reason_codes
        assert "FAIL_CLOSED" in decision.reason_codes
        assert decision.immediate_response.status_code == 503

    # ---- evaluate: connection error (fail-closed) ----

    def test_evaluate_connect_error_returns_unavailable_deny(self):
        """Connection error returns DENY with 503 (fail-closed)."""
        client = self._make_client()

        with patch.object(
            client._client, "post", side_effect=httpx.ConnectError("refused")
        ):
            decision = client.evaluate(_make_event("evt-conn-err"))

        assert decision.effect == Effect.DENY
        assert "PDP_UNAVAILABLE" in decision.reason_codes
        assert "FAIL_CLOSED" in decision.reason_codes
        assert decision.immediate_response.status_code == 503

    # ---- evaluate: unexpected exception (fail-closed) ----

    def test_evaluate_unexpected_exception_returns_unavailable_deny(self):
        """Unexpected exception returns DENY (fail-closed)."""
        client = self._make_client()

        with patch.object(
            client._client, "post", side_effect=OSError("something broke")
        ):
            decision = client.evaluate(_make_event("evt-unexpected"))

        assert decision.effect == Effect.DENY
        assert "PDP_UNAVAILABLE" in decision.reason_codes

    # ---- unavailable_decision with ALLOW mode (fail-open) ----

    def test_unavailable_decision_deny_mode_returns_503(self):
        """In DENY mode, unavailable_decision returns Effect.DENY with 503."""
        client = self._make_client(unavailable_mode=UnavailableMode.DENY)

        decision = client._unavailable_decision("evt-deny-mode", "test reason")

        assert decision.effect == Effect.DENY
        assert "FAIL_CLOSED" in decision.reason_codes
        assert decision.immediate_response is not None
        assert decision.immediate_response.status_code == 503
        assert decision.immediate_response.body_json["error"] == "Service Unavailable"

    def test_unavailable_decision_allow_mode_returns_allow(self):
        """In ALLOW mode, unavailable_decision returns Effect.ALLOW (fail-open, dangerous)."""
        client = self._make_client(unavailable_mode=UnavailableMode.ALLOW)

        decision = client._unavailable_decision("evt-allow-mode", "test reason")

        assert decision.effect == Effect.ALLOW
        assert "FAIL_OPEN" in decision.reason_codes
        assert "PDP_UNAVAILABLE" in decision.reason_codes
        # ALLOW mode should NOT have an immediate_response (request proceeds)
        assert decision.immediate_response is None

    # ---- semaphore backpressure ----

    def test_semaphore_timeout_returns_deny(self):
        """When the semaphore cannot be acquired, evaluate returns DENY."""
        client = self._make_client(max_inflight=1)

        # Exhaust the semaphore
        client._semaphore.acquire()

        # Now evaluate should fail to acquire within timeout
        # Use a very short timeout to avoid slow tests
        client._timeout = 0.01
        decision = client.evaluate(_make_event("evt-backpressure"))

        assert decision.effect == Effect.DENY
        assert "PDP_UNAVAILABLE" in decision.reason_codes
        assert "backpressure" in decision.reason

        # Release the one we grabbed
        client._semaphore.release()

    # ---- health_check ----

    def test_health_check_200_returns_true(self):
        """health_check returns True on 200."""
        client = self._make_client()

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200

        with patch.object(client._client, "get", return_value=mock_response):
            assert client.health_check() is True

    def test_health_check_error_returns_false(self):
        """health_check returns False on exception."""
        client = self._make_client()

        with patch.object(
            client._client, "get", side_effect=httpx.ConnectError("down")
        ):
            assert client.health_check() is False

    def test_health_check_non_200_returns_false(self):
        """health_check returns False on non-200 status."""
        client = self._make_client()

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 503

        with patch.object(client._client, "get", return_value=mock_response):
            assert client.health_check() is False

    # ---- is_addon_enabled ----

    def test_is_addon_enabled_raises_not_implemented(self):
        """is_addon_enabled() is not supported in HTTP mode."""
        client = self._make_client()

        with pytest.raises(NotImplementedError, match="not supported in HTTP mode"):
            client.is_addon_enabled("credential-guard")

    # ---- get_stats ----

    def test_get_stats_returns_empty_dict(self):
        """get_stats() returns {} (not implemented for HTTP mode)."""
        client = self._make_client()

        assert client.get_stats() == {}

    # ---- unimplemented admin write ops ----

    def test_update_host_rate_returns_error(self):
        client = self._make_client()
        result = client.update_host_rate("example.com", 100)
        assert "error" in result

    def test_add_host_allowance_returns_error(self):
        client = self._make_client()
        result = client.add_host_allowance("example.com")
        assert "error" in result

    def test_add_host_denial_returns_error(self):
        client = self._make_client()
        result = client.add_host_denial("evil.com")
        assert "error" in result

    def test_add_host_bypass_returns_error(self):
        client = self._make_client()
        result = client.add_host_bypass("example.com", "credential-guard")
        assert "error" in result

    # ---- shutdown ----

    def test_shutdown_closes_http_client(self):
        """shutdown() closes the underlying httpx client."""
        client = self._make_client()

        with patch.object(client._client, "close") as mock_close:
            client.shutdown()
            mock_close.assert_called_once()

    # ---- error_decision (4xx path) ----

    def test_error_decision_structure(self):
        """_error_decision returns DENY with PDP_ERROR code and 500 status."""
        client = self._make_client()

        decision = client._error_decision("evt-err", "schema validation failed")

        assert decision.effect == Effect.DENY
        assert decision.reason_codes == ["PDP_ERROR"]
        assert decision.immediate_response.status_code == 500
        assert decision.immediate_response.body_json["event_id"] == "evt-err"
        assert decision.immediate_response.body_json["reason"] == "schema validation failed"
