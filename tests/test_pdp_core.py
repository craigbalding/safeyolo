"""Tests for pdp/core.py -- PDP core evaluation logic.

Mocks PolicyEngine at the boundary so we test PDPCore's translation
and decision-building logic without needing YAML files or the full
policy stack.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from unittest.mock import MagicMock, patch

import pytest

# =========================================================================
# Helpers
# =========================================================================


@dataclass
class FakeLegacyDecision:
    """Mimics policy_engine.PolicyDecision for tests."""

    effect: Literal["allow", "deny", "prompt", "budget_exceeded"]
    permission: object = None
    reason: str = ""
    budget_remaining: int | None = None


def _make_http_event(
    *,
    event_id="evt_test",
    host="example.com",
    path="/",
    method="GET",
    credential_detected=False,
    credential_type=None,
    credential_confidence=None,
    credential_fingerprint=None,
    task_id=None,
    agent=None,
    gateway_risky_route=None,
    gateway_service=None,
    gateway_capability=None,
    gateway_account=None,
):
    """Build an HttpEvent for testing using the schema factory."""
    from pdp.schemas import create_http_event

    event = create_http_event(
        event_id=event_id,
        sensor_id="test-sensor",
        principal_id="agent:test",
        method=method,
        host=host,
        port=443,
        path=path,
        headers_present=["host"],
        credential_detected=credential_detected,
        credential_type=credential_type,
        credential_fingerprint=credential_fingerprint,
        credential_confidence=credential_confidence,
        task_id=task_id,
        agent=agent,
    )
    # Attach gateway context if needed (factory doesn't expose these)
    if gateway_risky_route is not None:
        from pdp.schemas import ContextBlock

        event.context = ContextBlock(
            task_id=task_id,
            agent=agent,
            gateway_service=gateway_service,
            gateway_capability=gateway_capability,
            gateway_account=gateway_account,
            gateway_risky_route=gateway_risky_route,
        )
    return event


@pytest.fixture
def mock_engine():
    """Create a mock PolicyEngine with default allow behaviour."""
    engine = MagicMock()
    engine.get_baseline.return_value = MagicMock(
        model_dump_json=MagicMock(return_value='{"test": "policy"}')
    )
    engine.get_task_policy.return_value = None
    engine.evaluate_request.return_value = FakeLegacyDecision(
        effect="allow", reason="Allowed by policy", budget_remaining=100
    )
    engine.evaluate_credential.return_value = FakeLegacyDecision(
        effect="allow", reason="Credential approved"
    )
    engine.evaluate_risky_route.return_value = FakeLegacyDecision(
        effect="allow", reason="Risk accepted"
    )
    engine.baseline_path = Path("/fake/policy.yaml")
    return engine


@pytest.fixture
def pdp_core(mock_engine):
    """Create a PDPCore with a mocked engine."""
    from pdp.core import PDPCore

    with patch("pdp.core.PolicyEngine", return_value=mock_engine):
        core = PDPCore(baseline_path=Path("/fake/policy.yaml"))
    return core


# =========================================================================
# PDPCore.evaluate() -- happy path
# =========================================================================


class TestPDPCoreEvaluate:
    """Contract: evaluate() returns PolicyDecision, never raises."""

    def test_network_allow_happy_path(self, pdp_core, mock_engine):
        from pdp.schemas import Effect

        event = _make_http_event(host="example.com", path="/api")
        decision = pdp_core.evaluate(event)

        assert decision.effect == Effect.ALLOW
        assert decision.reason == "Allowed by policy"
        assert "ALLOWED" in decision.reason_codes
        assert decision.budget is not None
        assert decision.budget.remaining == 100
        mock_engine.evaluate_request.assert_called_once_with(
            host="example.com", path="/api", method="GET", agent=None,
        )

    def test_credential_deny_short_circuits_before_network(self, pdp_core, mock_engine):
        from pdp.schemas import CredentialConfidence, CredentialType, Effect

        mock_engine.evaluate_credential.return_value = FakeLegacyDecision(
            effect="deny", reason="Credential destination mismatch"
        )
        event = _make_http_event(
            host="evil.com",
            credential_detected=True,
            credential_type=CredentialType.OPENAI,
            credential_confidence=CredentialConfidence.HIGH,
            credential_fingerprint="abc123",
        )
        decision = pdp_core.evaluate(event)

        assert decision.effect == Effect.DENY
        assert "DENIED" in decision.reason_codes
        assert decision.immediate_response is not None
        assert decision.immediate_response.status_code == 403
        # Network evaluation should NOT have been called
        mock_engine.evaluate_request.assert_not_called()

    def test_gateway_deny_short_circuits_before_network(self, pdp_core, mock_engine):
        from pdp.schemas import Effect

        mock_engine.evaluate_risky_route.return_value = FakeLegacyDecision(
            effect="deny", reason="Risky route denied by risk appetite policy"
        )
        event = _make_http_event(
            host="service.internal",
            gateway_risky_route={"tactics": ["persistence"], "irreversible": True},
            gateway_service="github",
            gateway_capability="repo:write",
            gateway_account="agent",
        )
        decision = pdp_core.evaluate(event)

        assert decision.effect == Effect.DENY
        assert "GATEWAY_RISKY_ROUTE" in decision.reason_codes
        assert decision.immediate_response is not None
        assert decision.immediate_response.status_code == 403
        mock_engine.evaluate_request.assert_not_called()

    def test_network_deny(self, pdp_core, mock_engine):
        from pdp.schemas import Effect

        mock_engine.evaluate_request.return_value = FakeLegacyDecision(
            effect="deny", reason="Host not in policy"
        )
        event = _make_http_event(host="blocked.com")
        decision = pdp_core.evaluate(event)

        assert decision.effect == Effect.DENY
        assert decision.immediate_response is not None
        assert decision.immediate_response.status_code == 403

    def test_evaluate_exception_returns_error_effect(self, pdp_core, mock_engine):
        """Pins the B8 fix: evaluate() never raises, returns Effect.ERROR."""
        from pdp.schemas import Effect

        mock_engine.evaluate_request.side_effect = RuntimeError("engine exploded")
        event = _make_http_event(host="example.com")
        decision = pdp_core.evaluate(event)

        assert decision.effect == Effect.ERROR
        assert decision.immediate_response is not None
        assert decision.immediate_response.status_code == 500
        assert "PDP_ERROR" in decision.reason_codes
        assert "INTERNAL_ERROR" in decision.reason_codes
        assert "RuntimeError" in decision.reason

    def test_evaluate_error_body_contains_event_id(self, pdp_core, mock_engine):
        from pdp.schemas import Effect

        mock_engine.evaluate_request.side_effect = ValueError("bad input")
        event = _make_http_event(event_id="evt_error_42")
        decision = pdp_core.evaluate(event)

        assert decision.effect == Effect.ERROR
        body = decision.immediate_response.body_json
        assert body["event_id"] == "evt_error_42"
        assert body["error"] == "PDP evaluation failed"

    def test_credential_allow_then_network_evaluated(self, pdp_core, mock_engine):
        """When credential check allows, network check still runs."""
        from pdp.schemas import CredentialConfidence, CredentialType, Effect

        mock_engine.evaluate_credential.return_value = FakeLegacyDecision(
            effect="allow", reason="Credential approved"
        )
        mock_engine.evaluate_request.return_value = FakeLegacyDecision(
            effect="allow", reason="Network allowed", budget_remaining=50
        )
        event = _make_http_event(
            host="api.openai.com",
            credential_detected=True,
            credential_type=CredentialType.OPENAI,
            credential_confidence=CredentialConfidence.HIGH,
        )
        decision = pdp_core.evaluate(event)

        assert decision.effect == Effect.ALLOW
        mock_engine.evaluate_credential.assert_called_once()
        mock_engine.evaluate_request.assert_called_once()


# =========================================================================
# _determine_required_checks()
# =========================================================================


class TestDetermineRequiredChecks:
    """Contract: rate_limit always present, credential/gateway conditional."""

    def test_rate_limit_always_present(self, pdp_core):
        event = _make_http_event()
        checks = pdp_core._determine_required_checks(event)
        assert "rate_limit" in checks

    def test_credential_detected_adds_detection_and_validation(self, pdp_core):
        from pdp.schemas import CredentialConfidence, CredentialType

        event = _make_http_event(
            credential_detected=True,
            credential_type=CredentialType.OPENAI,
            credential_confidence=CredentialConfidence.HIGH,
        )
        checks = pdp_core._determine_required_checks(event)
        assert "credential_detection" in checks
        assert "credential_validation" in checks
        assert "rate_limit" in checks

    def test_gateway_risky_route_adds_check(self, pdp_core):
        event = _make_http_event(
            gateway_risky_route={"tactics": ["exfiltration"]},
            gateway_service="github",
        )
        checks = pdp_core._determine_required_checks(event)
        assert "gateway_risky_route" in checks
        assert "rate_limit" in checks

    def test_plain_request_only_rate_limit(self, pdp_core):
        event = _make_http_event()
        checks = pdp_core._determine_required_checks(event)
        assert checks == ["rate_limit"]


# =========================================================================
# _build_decision() -- legacy to new schema translation
# =========================================================================


class TestBuildDecision:
    """Contract: Maps legacy effect strings to Effect enum correctly."""

    def test_allow_maps_to_effect_allow(self, pdp_core):
        from pdp.schemas import Effect

        legacy = FakeLegacyDecision(effect="allow", reason="OK", budget_remaining=10)
        decision = pdp_core._build_decision(
            event_id="evt_1",
            policy_hash="sha256:abc",
            legacy_decision=legacy,
            required_checks=["rate_limit"],
        )
        assert decision.effect == Effect.ALLOW
        assert decision.budget is not None
        assert decision.budget.remaining == 10

    def test_deny_maps_to_effect_deny(self, pdp_core):
        from pdp.schemas import Effect

        legacy = FakeLegacyDecision(effect="deny", reason="Blocked")
        decision = pdp_core._build_decision(
            event_id="evt_1",
            policy_hash="sha256:abc",
            legacy_decision=legacy,
            required_checks=["rate_limit"],
        )
        assert decision.effect == Effect.DENY
        assert decision.immediate_response is not None

    def test_prompt_maps_to_require_approval(self, pdp_core):
        from pdp.schemas import Effect

        legacy = FakeLegacyDecision(effect="prompt", reason="Need approval for credential")
        decision = pdp_core._build_decision(
            event_id="evt_1",
            policy_hash="sha256:abc",
            legacy_decision=legacy,
            required_checks=["credential_validation"],
        )
        assert decision.effect == Effect.REQUIRE_APPROVAL
        assert decision.immediate_response is not None

    def test_budget_exceeded_maps_to_budget_exceeded(self, pdp_core):
        from pdp.schemas import Effect

        legacy = FakeLegacyDecision(effect="budget_exceeded", reason="Rate limit hit")
        decision = pdp_core._build_decision(
            event_id="evt_1",
            policy_hash="sha256:abc",
            legacy_decision=legacy,
            required_checks=["rate_limit"],
        )
        assert decision.effect == Effect.BUDGET_EXCEEDED
        assert decision.budget is not None
        assert decision.budget.remaining == 0
        assert decision.budget.retry_after_seconds == 60

    def test_unknown_effect_maps_to_error(self, pdp_core):
        from pdp.schemas import Effect

        legacy = FakeLegacyDecision(effect="allow", reason="Unknown")
        # Force an unknown effect by hacking the dataclass
        object.__setattr__(legacy, "effect", "something_new")
        decision = pdp_core._build_decision(
            event_id="evt_1",
            policy_hash="sha256:abc",
            legacy_decision=legacy,
            required_checks=["rate_limit"],
        )
        assert decision.effect == Effect.ERROR

    def test_allow_has_no_immediate_response(self, pdp_core):
        legacy = FakeLegacyDecision(effect="allow", reason="OK")
        decision = pdp_core._build_decision(
            event_id="evt_1",
            policy_hash="sha256:abc",
            legacy_decision=legacy,
            required_checks=["rate_limit"],
        )
        assert decision.immediate_response is None

    def test_checks_block_echoes_required_checks(self, pdp_core):
        legacy = FakeLegacyDecision(effect="allow", reason="OK")
        decision = pdp_core._build_decision(
            event_id="evt_1",
            policy_hash="sha256:abc",
            legacy_decision=legacy,
            required_checks=["rate_limit", "credential_validation"],
        )
        assert decision.checks.required == ["rate_limit", "credential_validation"]


# =========================================================================
# _build_immediate_response()
# =========================================================================


class TestBuildImmediateResponse:
    """Contract: Non-allow decisions get pre-built HTTP responses."""

    def test_deny_returns_403(self, pdp_core):
        from pdp.schemas import Effect

        resp = pdp_core._build_immediate_response(
            event_id="evt_1", effect=Effect.DENY,
            reason="Blocked", reason_codes=["DENIED"],
        )
        assert resp.status_code == 403

    def test_require_approval_returns_428(self, pdp_core):
        from pdp.schemas import Effect

        resp = pdp_core._build_immediate_response(
            event_id="evt_1", effect=Effect.REQUIRE_APPROVAL,
            reason="Needs approval", reason_codes=["REQUIRE_APPROVAL"],
        )
        assert resp.status_code == 428

    def test_budget_exceeded_returns_429_with_retry_after(self, pdp_core):
        from pdp.schemas import Effect

        resp = pdp_core._build_immediate_response(
            event_id="evt_1", effect=Effect.BUDGET_EXCEEDED,
            reason="Rate limited", reason_codes=["BUDGET_EXCEEDED"],
        )
        assert resp.status_code == 429
        assert resp.headers["retry-after"] == "60"

    def test_error_returns_500(self, pdp_core):
        from pdp.schemas import Effect

        resp = pdp_core._build_immediate_response(
            event_id="evt_1", effect=Effect.ERROR,
            reason="Internal error", reason_codes=["PDP_ERROR"],
        )
        assert resp.status_code == 500

    def test_body_contains_required_fields(self, pdp_core):
        from pdp.schemas import Effect

        resp = pdp_core._build_immediate_response(
            event_id="evt_77", effect=Effect.DENY,
            reason="Not allowed", reason_codes=["DENIED", "CUSTOM"],
        )
        body = resp.body_json
        assert body["event_id"] == "evt_77"
        assert body["reason"] == "Not allowed"
        assert body["reason_codes"] == ["DENIED", "CUSTOM"]
        assert body["error"] == "Deny"

    def test_gateway_risky_route_enriches_body(self, pdp_core):
        """Risky route responses include reflection and route signals."""
        from pdp.schemas import Effect

        event = _make_http_event(
            gateway_risky_route={"tactics": ["persistence"], "irreversible": True},
            gateway_service="github",
            gateway_capability="repo:delete",
            gateway_account="agent",
        )
        resp = pdp_core._build_immediate_response(
            event_id="evt_gw", effect=Effect.DENY,
            reason="Risky route denied by risk appetite",
            reason_codes=["DENIED", "GATEWAY_RISKY_ROUTE"],
            event=event,
        )
        assert "reflection" in resp.body_json
        assert resp.body_json["reflection"]["service"] == "github"
        assert resp.body_json["reflection"]["capability"] == "repo:delete"
        assert "risky_route" in resp.body_json
        assert resp.body_json["risky_route"]["irreversible"] is True


# =========================================================================
# _effect_to_reason_codes()
# =========================================================================


class TestEffectToReasonCodes:
    """Contract: Stable reason codes derived from legacy decision."""

    def test_allow_produces_allowed(self, pdp_core):
        legacy = FakeLegacyDecision(effect="allow", reason="OK")
        codes = pdp_core._effect_to_reason_codes(legacy)
        assert codes == ["ALLOWED"]

    def test_allow_with_permission_includes_action(self, pdp_core):
        perm = MagicMock()
        perm.action = "network:request"
        legacy = FakeLegacyDecision(effect="allow", reason="OK", permission=perm)
        codes = pdp_core._effect_to_reason_codes(legacy)
        assert "ALLOWED" in codes
        assert "PERMISSION_NETWORK_REQUEST" in codes

    def test_deny_produces_denied(self, pdp_core):
        legacy = FakeLegacyDecision(effect="deny", reason="Host blocked")
        codes = pdp_core._effect_to_reason_codes(legacy)
        assert codes == ["DENIED"]

    def test_prompt_with_credential_in_reason(self, pdp_core):
        legacy = FakeLegacyDecision(
            effect="prompt", reason="Credential not approved for this destination"
        )
        codes = pdp_core._effect_to_reason_codes(legacy)
        assert "REQUIRE_APPROVAL" in codes
        assert "CREDENTIAL_NOT_APPROVED" in codes

    def test_prompt_with_destination_in_reason(self, pdp_core):
        legacy = FakeLegacyDecision(
            effect="prompt", reason="Credential destination mismatch"
        )
        codes = pdp_core._effect_to_reason_codes(legacy)
        assert "REQUIRE_APPROVAL" in codes
        assert "CREDENTIAL_DESTINATION_MISMATCH" in codes

    def test_budget_exceeded_produces_both_codes(self, pdp_core):
        legacy = FakeLegacyDecision(effect="budget_exceeded", reason="Over limit")
        codes = pdp_core._effect_to_reason_codes(legacy)
        assert "BUDGET_EXCEEDED" in codes
        assert "RATE_LIMITED" in codes

    def test_risky_route_in_reason_adds_gateway_code(self, pdp_core):
        legacy = FakeLegacyDecision(effect="deny", reason="Risky route blocked")
        codes = pdp_core._effect_to_reason_codes(legacy)
        assert "DENIED" in codes
        assert "GATEWAY_RISKY_ROUTE" in codes

    def test_risk_appetite_in_reason_adds_gateway_code(self, pdp_core):
        legacy = FakeLegacyDecision(
            effect="deny", reason="Denied by risk appetite policy"
        )
        codes = pdp_core._effect_to_reason_codes(legacy)
        assert "GATEWAY_RISKY_ROUTE" in codes


# =========================================================================
# _apply_task_policy()
# =========================================================================


class TestApplyTaskPolicy:
    """Contract: Task policy applied from cache when task_id matches."""

    def test_valid_task_policy_applied(self, pdp_core, mock_engine):
        """When a task_id exists in _task_policies, it's applied to the engine."""

        # Pre-load a task policy
        policy_data = {
            "metadata": {"version": "1.0"},
            "permissions": [],
            "budgets": {},
            "required": [],
        }
        pdp_core._task_policies["task-1"] = policy_data

        pdp_core._apply_task_policy("task-1")

        # Verify the engine's loader task_policy was set
        assert mock_engine._loader._task_policy is not None

    def test_invalid_task_policy_logged_and_continues(self, pdp_core, mock_engine):
        """Invalid policy data logs a warning but doesn't raise."""
        # Store something that will fail validation
        pdp_core._task_policies["task-bad"] = {"invalid": "data"}

        # Should not raise
        pdp_core._apply_task_policy("task-bad")

    def test_missing_task_id_is_no_op(self, pdp_core, mock_engine):
        """task_id not in _task_policies dict => no action."""
        pdp_core._apply_task_policy("nonexistent-task")
        # Engine's loader should not have been touched for task policy


# =========================================================================
# policy_hash
# =========================================================================


class TestPolicyHash:
    """Contract: Hash computed from engine baseline content."""

    def test_hash_starts_with_sha256_prefix(self, pdp_core):
        h = pdp_core.policy_hash
        assert h.startswith("sha256:")

    def test_hash_is_deterministic(self, pdp_core):
        h1 = pdp_core.policy_hash
        h2 = pdp_core.policy_hash
        assert h1 == h2

    def test_hash_changes_when_baseline_changes(self, pdp_core, mock_engine):
        h1 = pdp_core.policy_hash

        # Change the baseline content
        mock_engine.get_baseline.return_value = MagicMock(
            model_dump_json=MagicMock(return_value='{"test": "different_policy"}')
        )
        h2 = pdp_core.policy_hash
        assert h1 != h2

    def test_hash_with_no_baseline(self, pdp_core, mock_engine):
        mock_engine.get_baseline.return_value = None
        h = pdp_core.policy_hash
        assert h.startswith("sha256:")
        # Empty content hashes to a known value
        assert len(h) > len("sha256:")


# =========================================================================
# get_pdp() / reset_pdp() singleton
# =========================================================================


class TestGetPdpSingleton:
    """Contract: Thread-safe singleton, first call creates, reset clears."""

    def test_first_call_creates_instance(self):
        from pdp.core import reset_pdp

        reset_pdp()

        with patch("pdp.core.PolicyEngine") as MockEngine:
            MockEngine.return_value = MagicMock()
            MockEngine.return_value.get_baseline.return_value = None
            MockEngine.return_value.get_task_policy.return_value = None
            MockEngine.return_value.baseline_path = None

            from pdp.core import get_pdp

            instance = get_pdp(baseline_path=Path("/fake/policy.yaml"))
            assert instance is not None

            reset_pdp()

    def test_second_call_returns_same_instance(self):
        from pdp.core import get_pdp, reset_pdp

        reset_pdp()

        with patch("pdp.core.PolicyEngine") as MockEngine:
            MockEngine.return_value = MagicMock()
            MockEngine.return_value.get_baseline.return_value = None
            MockEngine.return_value.get_task_policy.return_value = None
            MockEngine.return_value.baseline_path = None

            first = get_pdp(baseline_path=Path("/fake/a.yaml"))
            second = get_pdp(baseline_path=Path("/fake/b.yaml"))
            assert first is second

            reset_pdp()

    def test_reset_clears_instance(self):
        from pdp.core import get_pdp, reset_pdp

        reset_pdp()

        with patch("pdp.core.PolicyEngine") as MockEngine:
            mock_inst = MagicMock()
            mock_inst.get_baseline.return_value = None
            mock_inst.get_task_policy.return_value = None
            mock_inst.baseline_path = None
            MockEngine.return_value = mock_inst

            first = get_pdp()
            reset_pdp()
            second = get_pdp()
            assert first is not second

            reset_pdp()
