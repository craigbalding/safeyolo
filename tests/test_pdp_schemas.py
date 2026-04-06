"""Tests for pdp/schemas.py -- HttpEvent and PolicyDecision schemas.

Each test maps to a contract item in the schema design. Tests state
expected outcomes directly with hardcoded values.
"""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

# =========================================================================
# CredentialBlock — detected/field consistency validator
# =========================================================================


class TestCredentialBlockDetectedTrue:
    """Contract: When detected=True, type and confidence are required."""

    def test_valid_detected_with_type_and_confidence(self):
        from pdp.schemas import CredentialBlock, CredentialConfidence, CredentialType

        block = CredentialBlock(
            detected=True,
            type=CredentialType.OPENAI,
            fingerprint="abc123",
            confidence=CredentialConfidence.HIGH,
        )
        assert block.detected is True
        assert block.type == CredentialType.OPENAI
        assert block.fingerprint == "abc123"
        assert block.confidence == CredentialConfidence.HIGH

    def test_detected_true_without_type_raises(self):
        from pdp.schemas import CredentialBlock, CredentialConfidence

        with pytest.raises(ValidationError, match="credential type is required"):
            CredentialBlock(
                detected=True,
                type=None,
                fingerprint="abc123",
                confidence=CredentialConfidence.HIGH,
            )

    def test_detected_true_without_confidence_raises(self):
        from pdp.schemas import CredentialBlock, CredentialType

        with pytest.raises(ValidationError, match="credential confidence is required"):
            CredentialBlock(
                detected=True,
                type=CredentialType.OPENAI,
                fingerprint="abc123",
                confidence=None,
            )

    def test_detected_true_without_type_or_confidence_raises(self):
        from pdp.schemas import CredentialBlock

        with pytest.raises(ValidationError, match="credential type is required"):
            CredentialBlock(detected=True)

    def test_detected_true_fingerprint_optional(self):
        from pdp.schemas import CredentialBlock, CredentialConfidence, CredentialType

        block = CredentialBlock(
            detected=True,
            type=CredentialType.ANTHROPIC,
            fingerprint=None,
            confidence=CredentialConfidence.MEDIUM,
        )
        assert block.fingerprint is None
        assert block.detected is True


class TestCredentialBlockDetectedFalse:
    """Contract: When detected=False, type/fingerprint/confidence must all be None."""

    def test_valid_not_detected_all_none(self):
        from pdp.schemas import CredentialBlock

        block = CredentialBlock(detected=False)
        assert block.detected is False
        assert block.type is None
        assert block.fingerprint is None
        assert block.confidence is None

    def test_not_detected_with_type_raises(self):
        from pdp.schemas import CredentialBlock, CredentialType

        with pytest.raises(ValidationError, match="must be None when detected=False"):
            CredentialBlock(detected=False, type=CredentialType.OPENAI)

    def test_not_detected_with_fingerprint_raises(self):
        from pdp.schemas import CredentialBlock

        with pytest.raises(ValidationError, match="must be None when detected=False"):
            CredentialBlock(detected=False, fingerprint="abc123")

    def test_not_detected_with_confidence_raises(self):
        from pdp.schemas import CredentialBlock, CredentialConfidence

        with pytest.raises(ValidationError, match="must be None when detected=False"):
            CredentialBlock(detected=False, confidence=CredentialConfidence.LOW)


# =========================================================================
# HttpEvent — strict validation (extra="forbid")
# =========================================================================


class TestHttpEventValidation:
    """Contract: HttpEvent uses extra='forbid' — rejects unknown fields."""

    def _make_minimal_event_data(self):
        """Return a valid HttpEvent as a dict for manipulation."""
        return {
            "version": 1,
            "event": {
                "event_id": "evt_1",
                "trace_id": "evt_1",
                "kind": "http.request",
                "phase": "pre_upstream",
                "timestamp": "2026-01-01T00:00:00Z",
                "sensor_id": "test-sensor",
            },
            "principal": {
                "principal_id": "agent:test",
                "identity_source": "ipmap",
            },
            "http": {
                "method": "GET",
                "scheme": "https",
                "host": "example.com",
                "port": 443,
                "path": "/",
                "headers_present": ["host"],
            },
            "credential": {"detected": False},
            "body": {"present": False},
        }

    def test_valid_v1_event_accepted(self):
        from pdp.schemas import HttpEvent

        data = self._make_minimal_event_data()
        event = HttpEvent.model_validate(data)
        assert event.version == 1
        assert event.event.event_id == "evt_1"
        assert event.http.host == "example.com"
        assert event.credential.detected is False

    def test_version_2_rejected(self):
        from pdp.schemas import HttpEvent

        data = self._make_minimal_event_data()
        data["version"] = 2
        with pytest.raises(ValidationError, match="version"):
            HttpEvent.model_validate(data)

    def test_version_0_rejected(self):
        from pdp.schemas import HttpEvent

        data = self._make_minimal_event_data()
        data["version"] = 0
        with pytest.raises(ValidationError, match="version"):
            HttpEvent.model_validate(data)

    def test_extra_field_on_top_level_rejected(self):
        from pdp.schemas import HttpEvent

        data = self._make_minimal_event_data()
        data["unknown_field"] = "surprise"
        with pytest.raises(ValidationError, match="extra"):
            HttpEvent.model_validate(data)

    def test_extra_field_on_event_block_rejected(self):
        from pdp.schemas import HttpEvent

        data = self._make_minimal_event_data()
        data["event"]["rogue"] = True
        with pytest.raises(ValidationError, match="extra"):
            HttpEvent.model_validate(data)

    def test_extra_field_on_http_block_rejected(self):
        from pdp.schemas import HttpEvent

        data = self._make_minimal_event_data()
        data["http"]["user_agent"] = "bot"
        with pytest.raises(ValidationError, match="extra"):
            HttpEvent.model_validate(data)

    def test_extra_field_on_credential_block_rejected(self):
        from pdp.schemas import HttpEvent

        data = self._make_minimal_event_data()
        data["credential"]["raw_value"] = "sk-xxx"
        with pytest.raises(ValidationError, match="extra"):
            HttpEvent.model_validate(data)

    def test_extra_field_on_principal_block_rejected(self):
        from pdp.schemas import HttpEvent

        data = self._make_minimal_event_data()
        data["principal"]["role"] = "admin"
        with pytest.raises(ValidationError, match="extra"):
            HttpEvent.model_validate(data)

    def test_extra_field_on_body_block_rejected(self):
        from pdp.schemas import HttpEvent

        data = self._make_minimal_event_data()
        data["body"]["raw_bytes"] = "AQID"
        with pytest.raises(ValidationError, match="extra"):
            HttpEvent.model_validate(data)

    def test_context_is_optional_and_defaults_to_none(self):
        from pdp.schemas import HttpEvent

        data = self._make_minimal_event_data()
        event = HttpEvent.model_validate(data)
        assert event.context is None


# =========================================================================
# PolicyDecision — lenient validation (extra="ignore")
# =========================================================================


class TestPolicyDecisionValidation:
    """Contract: PolicyDecision uses extra='ignore' for forward compatibility."""

    def _make_minimal_decision_data(self, effect="allow"):
        return {
            "version": 1,
            "event": {
                "event_id": "evt_1",
                "policy_hash": "sha256:abc123",
                "engine_version": "pdp-0.1.0",
            },
            "effect": effect,
            "reason": "Test reason",
        }

    def test_extra_fields_silently_ignored(self):
        from pdp.schemas import PolicyDecision

        data = self._make_minimal_decision_data()
        data["future_field"] = {"some": "data"}
        decision = PolicyDecision.model_validate(data)
        assert decision.effect.value == "allow"
        assert not hasattr(decision, "future_field")

    def test_extra_fields_on_decision_event_block_ignored(self):
        from pdp.schemas import PolicyDecision

        data = self._make_minimal_decision_data()
        data["event"]["new_field"] = "v2-data"
        decision = PolicyDecision.model_validate(data)
        assert decision.event.event_id == "evt_1"

    def test_all_effect_values_accepted(self):
        from pdp.schemas import Effect, PolicyDecision

        for effect_value in ["allow", "deny", "require_approval", "budget_exceeded", "error"]:
            data = self._make_minimal_decision_data(effect=effect_value)
            decision = PolicyDecision.model_validate(data)
            assert decision.effect == Effect(effect_value)

    def test_reason_codes_default_to_empty_list(self):
        from pdp.schemas import PolicyDecision

        data = self._make_minimal_decision_data()
        decision = PolicyDecision.model_validate(data)
        assert decision.reason_codes == []

    def test_optional_blocks_default_to_none(self):
        from pdp.schemas import PolicyDecision

        data = self._make_minimal_decision_data()
        decision = PolicyDecision.model_validate(data)
        assert decision.checks is None
        assert decision.budget is None
        assert decision.immediate_response is None
        assert decision.approval is None
        assert decision.cache is None


# =========================================================================
# create_http_event() factory
# =========================================================================


class TestCreateHttpEvent:
    """Contract: Factory produces valid HttpEvent with sensible defaults."""

    def test_happy_path_minimal(self):
        from pdp.schemas import create_http_event

        event = create_http_event(
            event_id="evt_1",
            sensor_id="sensor-1",
            principal_id="agent:test",
            method="GET",
            host="example.com",
            port=443,
            path="/api/v1",
            headers_present=["host", "authorization"],
        )
        assert event.version == 1
        assert event.event.event_id == "evt_1"
        assert event.event.trace_id == "evt_1"  # v1: trace_id = event_id
        assert event.event.kind.value == "http.request"
        assert event.event.phase.value == "pre_upstream"
        assert event.event.sensor_id == "sensor-1"
        assert event.principal.principal_id == "agent:test"
        assert event.principal.identity_source.value == "ipmap"
        assert event.http.method == "GET"
        assert event.http.scheme == "https"
        assert event.http.host == "example.com"
        assert event.http.port == 443
        assert event.http.path == "/api/v1"
        assert event.http.headers_present == ["host", "authorization"]
        assert event.credential.detected is False
        assert event.body.present is False
        assert event.context is None

    def test_credential_detected_false_clears_fields(self):
        """When credential_detected=False, factory forces credential fields to None
        regardless of what caller passes."""
        from pdp.schemas import CredentialConfidence, CredentialType, create_http_event

        event = create_http_event(
            event_id="evt_2",
            sensor_id="sensor-1",
            principal_id="agent:test",
            method="POST",
            host="example.com",
            port=443,
            path="/",
            headers_present=[],
            credential_detected=False,
            credential_type=CredentialType.OPENAI,
            credential_fingerprint="abc123",
            credential_confidence=CredentialConfidence.HIGH,
        )
        assert event.credential.detected is False
        assert event.credential.type is None
        assert event.credential.fingerprint is None
        assert event.credential.confidence is None

    def test_credential_detected_true_passes_fields(self):
        from pdp.schemas import CredentialConfidence, CredentialType, create_http_event

        event = create_http_event(
            event_id="evt_3",
            sensor_id="sensor-1",
            principal_id="agent:test",
            method="POST",
            host="api.openai.com",
            port=443,
            path="/v1/chat",
            headers_present=["authorization"],
            credential_detected=True,
            credential_type=CredentialType.OPENAI,
            credential_fingerprint="finger123",
            credential_confidence=CredentialConfidence.HIGH,
        )
        assert event.credential.detected is True
        assert event.credential.type == CredentialType.OPENAI
        assert event.credential.fingerprint == "finger123"
        assert event.credential.confidence == CredentialConfidence.HIGH

    def test_headers_lowercased(self):
        from pdp.schemas import create_http_event

        event = create_http_event(
            event_id="evt_4",
            sensor_id="sensor-1",
            principal_id="agent:test",
            method="GET",
            host="example.com",
            port=443,
            path="/",
            headers_present=["Content-Type", "AUTHORIZATION", "Host"],
        )
        assert event.http.headers_present == ["content-type", "authorization", "host"]

    def test_method_uppercased(self):
        from pdp.schemas import create_http_event

        event = create_http_event(
            event_id="evt_5",
            sensor_id="sensor-1",
            principal_id="agent:test",
            method="post",
            host="example.com",
            port=443,
            path="/",
            headers_present=[],
        )
        assert event.http.method == "POST"

    def test_context_created_when_task_id_present(self):
        from pdp.schemas import create_http_event

        event = create_http_event(
            event_id="evt_6",
            sensor_id="sensor-1",
            principal_id="agent:test",
            method="GET",
            host="example.com",
            port=443,
            path="/",
            headers_present=[],
            task_id="task-abc",
        )
        assert event.context is not None
        assert event.context.task_id == "task-abc"
        assert event.context.agent is None

    def test_context_created_when_agent_present(self):
        from pdp.schemas import create_http_event

        event = create_http_event(
            event_id="evt_7",
            sensor_id="sensor-1",
            principal_id="agent:test",
            method="GET",
            host="example.com",
            port=443,
            path="/",
            headers_present=[],
            agent="claude-dev",
        )
        assert event.context is not None
        assert event.context.agent == "claude-dev"
        assert event.context.task_id is None

    def test_no_context_when_both_task_id_and_agent_are_none(self):
        from pdp.schemas import create_http_event

        event = create_http_event(
            event_id="evt_8",
            sensor_id="sensor-1",
            principal_id="agent:test",
            method="GET",
            host="example.com",
            port=443,
            path="/",
            headers_present=[],
            task_id=None,
            agent=None,
        )
        assert event.context is None

    def test_timestamp_defaults_to_utc_now(self):
        from pdp.schemas import create_http_event

        before = datetime.now(UTC)
        event = create_http_event(
            event_id="evt_9",
            sensor_id="sensor-1",
            principal_id="agent:test",
            method="GET",
            host="example.com",
            port=443,
            path="/",
            headers_present=[],
        )
        after = datetime.now(UTC)
        assert before <= event.event.timestamp <= after

    def test_explicit_timestamp_used(self):
        from pdp.schemas import create_http_event

        ts = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
        event = create_http_event(
            event_id="evt_10",
            sensor_id="sensor-1",
            principal_id="agent:test",
            method="GET",
            host="example.com",
            port=443,
            path="/",
            headers_present=[],
            timestamp=ts,
        )
        assert event.event.timestamp == ts

    def test_scheme_defaults_to_https(self):
        from pdp.schemas import create_http_event

        event = create_http_event(
            event_id="evt_11",
            sensor_id="sensor-1",
            principal_id="agent:test",
            method="GET",
            host="example.com",
            port=443,
            path="/",
            headers_present=[],
        )
        assert event.http.scheme == "https"

    def test_explicit_scheme_override(self):
        from pdp.schemas import create_http_event

        event = create_http_event(
            event_id="evt_12",
            sensor_id="sensor-1",
            principal_id="agent:test",
            method="GET",
            host="example.com",
            port=80,
            path="/",
            headers_present=[],
            scheme="http",
        )
        assert event.http.scheme == "http"


# =========================================================================
# create_allow_decision() factory
# =========================================================================


class TestCreateAllowDecision:
    """Contract: Factory produces ALLOW decision with correct defaults."""

    def test_happy_path(self):
        from pdp.schemas import Effect, create_allow_decision

        decision = create_allow_decision(
            event_id="evt_1",
            policy_hash="sha256:abc",
            engine_version="pdp-0.1.0",
        )
        assert decision.version == 1
        assert decision.effect == Effect.ALLOW
        assert decision.reason == "Allowed by policy"
        assert decision.reason_codes == ["ALLOWED"]
        assert decision.event.event_id == "evt_1"
        assert decision.event.policy_hash == "sha256:abc"
        assert decision.event.engine_version == "pdp-0.1.0"
        assert decision.budget is None

    def test_default_reason_codes_is_allowed(self):
        from pdp.schemas import create_allow_decision

        decision = create_allow_decision(
            event_id="evt_1",
            policy_hash="sha256:abc",
            engine_version="pdp-0.1.0",
        )
        assert decision.reason_codes == ["ALLOWED"]

    def test_custom_reason_codes_override_default(self):
        from pdp.schemas import create_allow_decision

        decision = create_allow_decision(
            event_id="evt_1",
            policy_hash="sha256:abc",
            engine_version="pdp-0.1.0",
            reason_codes=["ALLOWED", "CACHED"],
        )
        assert decision.reason_codes == ["ALLOWED", "CACHED"]

    def test_budget_remaining_creates_budget_block(self):
        from pdp.schemas import create_allow_decision

        decision = create_allow_decision(
            event_id="evt_1",
            policy_hash="sha256:abc",
            engine_version="pdp-0.1.0",
            budget_remaining=42,
        )
        assert decision.budget is not None
        assert decision.budget.remaining == 42


# =========================================================================
# create_deny_decision() factory
# =========================================================================


class TestCreateDenyDecision:
    """Contract: Factory produces DENY decision with immediate response."""

    def test_happy_path(self):
        from pdp.schemas import Effect, create_deny_decision

        decision = create_deny_decision(
            event_id="evt_1",
            policy_hash="sha256:abc",
            engine_version="pdp-0.1.0",
            reason="Host not allowed",
            reason_codes=["DENIED", "HOST_NOT_IN_POLICY"],
        )
        assert decision.effect == Effect.DENY
        assert decision.reason == "Host not allowed"
        assert decision.reason_codes == ["DENIED", "HOST_NOT_IN_POLICY"]
        assert decision.immediate_response is not None
        assert decision.immediate_response.status_code == 403
        assert decision.immediate_response.headers == {"content-type": "application/json"}

    def test_default_body_contains_event_id_and_reason(self):
        from pdp.schemas import create_deny_decision

        decision = create_deny_decision(
            event_id="evt_42",
            policy_hash="sha256:abc",
            engine_version="pdp-0.1.0",
            reason="Blocked by policy",
            reason_codes=["DENIED"],
        )
        body = decision.immediate_response.body_json
        assert body["error"] == "Denied"
        assert body["event_id"] == "evt_42"
        assert body["reason"] == "Blocked by policy"
        assert body["reason_codes"] == ["DENIED"]

    def test_custom_body_overrides_default(self):
        from pdp.schemas import create_deny_decision

        custom_body = {"error": "Custom", "detail": "special case"}
        decision = create_deny_decision(
            event_id="evt_1",
            policy_hash="sha256:abc",
            engine_version="pdp-0.1.0",
            reason="Custom deny",
            reason_codes=["DENIED"],
            response_body=custom_body,
        )
        assert decision.immediate_response.body_json == custom_body

    def test_custom_status_code(self):
        from pdp.schemas import create_deny_decision

        decision = create_deny_decision(
            event_id="evt_1",
            policy_hash="sha256:abc",
            engine_version="pdp-0.1.0",
            reason="Forbidden",
            reason_codes=["DENIED"],
            status_code=451,
        )
        assert decision.immediate_response.status_code == 451


# =========================================================================
# create_budget_exceeded_decision() factory
# =========================================================================


class TestCreateBudgetExceededDecision:
    """Contract: Factory produces 429 with retry-after and remaining=0."""

    def test_happy_path(self):
        from pdp.schemas import Effect, create_budget_exceeded_decision

        decision = create_budget_exceeded_decision(
            event_id="evt_1",
            policy_hash="sha256:abc",
            engine_version="pdp-0.1.0",
        )
        assert decision.effect == Effect.BUDGET_EXCEEDED
        assert decision.reason == "Rate limit exceeded"
        assert decision.reason_codes == ["BUDGET_EXCEEDED"]

    def test_status_code_is_429(self):
        from pdp.schemas import create_budget_exceeded_decision

        decision = create_budget_exceeded_decision(
            event_id="evt_1",
            policy_hash="sha256:abc",
            engine_version="pdp-0.1.0",
        )
        assert decision.immediate_response.status_code == 429

    def test_retry_after_header_present(self):
        from pdp.schemas import create_budget_exceeded_decision

        decision = create_budget_exceeded_decision(
            event_id="evt_1",
            policy_hash="sha256:abc",
            engine_version="pdp-0.1.0",
            retry_after_seconds=120,
        )
        assert decision.immediate_response.headers["retry-after"] == "120"

    def test_budget_remaining_is_zero(self):
        from pdp.schemas import create_budget_exceeded_decision

        decision = create_budget_exceeded_decision(
            event_id="evt_1",
            policy_hash="sha256:abc",
            engine_version="pdp-0.1.0",
        )
        assert decision.budget is not None
        assert decision.budget.remaining == 0

    def test_retry_after_in_budget_block(self):
        from pdp.schemas import create_budget_exceeded_decision

        decision = create_budget_exceeded_decision(
            event_id="evt_1",
            policy_hash="sha256:abc",
            engine_version="pdp-0.1.0",
            retry_after_seconds=30,
        )
        assert decision.budget.retry_after_seconds == 30

    def test_body_contains_retry_after(self):
        from pdp.schemas import create_budget_exceeded_decision

        decision = create_budget_exceeded_decision(
            event_id="evt_1",
            policy_hash="sha256:abc",
            engine_version="pdp-0.1.0",
            retry_after_seconds=90,
        )
        body = decision.immediate_response.body_json
        assert body["retry_after_seconds"] == 90
        assert body["event_id"] == "evt_1"


# =========================================================================
# Enum coverage
# =========================================================================


class TestEnums:
    """Contract: Enum values are stable strings used in wire protocol."""

    def test_effect_values(self):
        from pdp.schemas import Effect

        assert Effect.ALLOW.value == "allow"
        assert Effect.DENY.value == "deny"
        assert Effect.REQUIRE_APPROVAL.value == "require_approval"
        assert Effect.BUDGET_EXCEEDED.value == "budget_exceeded"
        assert Effect.ERROR.value == "error"

    def test_event_kind_values(self):
        from pdp.schemas import EventKind

        assert EventKind.HTTP_REQUEST.value == "http.request"
        assert EventKind.HTTP_RESPONSE.value == "http.response"

    def test_credential_type_values(self):
        from pdp.schemas import CredentialType

        assert CredentialType.OPENAI.value == "openai"
        assert CredentialType.ANTHROPIC.value == "anthropic"
        assert CredentialType.GITHUB.value == "github"
        assert CredentialType.UNKNOWN.value == "unknown"
