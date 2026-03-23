"""
Tests for audit_schema.py - the shared event contract.

Tests schema validation, serialization round-trips, and strict mode.
"""

import json
from datetime import datetime

import pytest

from audit_schema import (
    ApprovalRequest,
    AuditEvent,
    Decision,
    EventKind,
    Severity,
)


class TestEnums:
    """Test enum values."""

    def test_event_kind_values(self):
        assert EventKind.SECURITY.value == "security"
        assert EventKind.GATEWAY.value == "gateway"
        assert EventKind.TRAFFIC.value == "traffic"
        assert EventKind.OPS.value == "ops"
        assert EventKind.ADMIN.value == "admin"
        assert EventKind.AGENT.value == "agent"

    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"

    def test_decision_values(self):
        assert Decision.ALLOW.value == "allow"
        assert Decision.DENY.value == "deny"
        assert Decision.WARN.value == "warn"
        assert Decision.REQUIRE_APPROVAL.value == "require_approval"
        assert Decision.BUDGET_EXCEEDED.value == "budget_exceeded"
        assert Decision.LOG.value == "log"


class TestApprovalRequest:
    """Test ApprovalRequest model."""

    def test_valid_approval(self):
        a = ApprovalRequest(
            required=True,
            approval_type="credential",
            key="hmac:abc123",
            target="api.openai.com",
        )
        assert a.required is True
        assert a.approval_type == "credential"

    def test_with_scope_hint(self):
        a = ApprovalRequest(
            required=True,
            approval_type="credential",
            key="hmac:abc123",
            target="api.openai.com",
            scope_hint={"rule": "openai", "expected_hosts": ["api.openai.com"]},
        )
        assert a.scope_hint["rule"] == "openai"

    def test_extra_fields_forbidden(self):
        with pytest.raises(Exception):  # ValidationError
            ApprovalRequest(
                required=True,
                approval_type="credential",
                key="hmac:abc123",
                target="api.openai.com",
                unknown_field="should fail",
            )


class TestAuditEvent:
    """Test AuditEvent model."""

    def test_minimal_event(self):
        e = AuditEvent(
            event="security.credential_guard",
            kind=EventKind.SECURITY,
            severity=Severity.HIGH,
            summary="Credential blocked",
        )
        assert e.schema_version == 1
        assert e.event == "security.credential_guard"
        assert e.kind == EventKind.SECURITY
        assert isinstance(e.ts, datetime)

    def test_full_event(self):
        e = AuditEvent(
            event="security.credential_guard",
            kind=EventKind.SECURITY,
            severity=Severity.CRITICAL,
            summary="OpenAI key blocked to wrong host",
            request_id="req-abc123",
            agent="claude",
            addon="credential-guard",
            decision=Decision.DENY,
            host="httpbin.org",
            approval=ApprovalRequest(
                required=True,
                approval_type="credential",
                key="hmac:abc123",
                target="httpbin.org",
            ),
            details={"rule": "openai", "fingerprint": "hmac:abc123"},
        )
        assert e.decision == Decision.DENY
        assert e.approval.required is True
        assert e.details["rule"] == "openai"

    def test_extra_fields_forbidden(self):
        with pytest.raises(Exception):  # ValidationError
            AuditEvent(
                event="security.test",
                kind=EventKind.SECURITY,
                severity=Severity.HIGH,
                summary="test",
                unknown_spine_field="should fail",
            )

    def test_to_jsonl(self):
        e = AuditEvent(
            event="traffic.request",
            kind=EventKind.TRAFFIC,
            severity=Severity.LOW,
            summary="GET example.com/",
            host="example.com",
        )
        d = e.to_jsonl()
        assert isinstance(d, dict)
        assert d["event"] == "traffic.request"
        assert d["kind"] == "traffic"
        assert d["severity"] == "low"
        assert d["schema_version"] == 1
        assert "ts" in d
        # None fields should be excluded
        assert "request_id" not in d
        assert "agent" not in d
        assert "decision" not in d
        assert "approval" not in d

    def test_to_jsonl_is_json_serializable(self):
        e = AuditEvent(
            event="ops.memory",
            kind=EventKind.OPS,
            severity=Severity.LOW,
            summary="RSS 100MB",
            details={"rss_mb": 100.5, "connections": 42},
        )
        d = e.to_jsonl()
        json_str = json.dumps(d)
        parsed = json.loads(json_str)
        assert parsed["event"] == "ops.memory"
        assert parsed["details"]["rss_mb"] == 100.5

    def test_details_default_empty_dict(self):
        e = AuditEvent(
            event="ops.startup",
            kind=EventKind.OPS,
            severity=Severity.LOW,
            summary="started",
        )
        assert e.details == {}

    def test_timestamp_auto_generated(self):
        e = AuditEvent(
            event="ops.startup",
            kind=EventKind.OPS,
            severity=Severity.LOW,
            summary="started",
        )
        assert e.ts.tzinfo is not None  # timezone aware

    def test_gateway_event(self):
        e = AuditEvent(
            event="gateway.allow",
            kind=EventKind.GATEWAY,
            severity=Severity.LOW,
            summary="Gateway injected gmail/reader for claude",
            decision=Decision.ALLOW,
            host="gmail.googleapis.com",
            agent="claude",
            addon="service-gateway",
        )
        assert e.kind == EventKind.GATEWAY

    def test_round_trip_serialization(self):
        """Test that to_jsonl output can reconstruct the event."""
        original = AuditEvent(
            event="security.network_guard",
            kind=EventKind.SECURITY,
            severity=Severity.HIGH,
            summary="Access denied to evil.com",
            decision=Decision.DENY,
            host="evil.com",
            request_id="req-123",
            addon="network-guard",
            details={"reason": "not in allowlist"},
        )
        d = original.to_jsonl()
        json_str = json.dumps(d)
        parsed = json.loads(json_str)
        reconstructed = AuditEvent.model_validate(parsed)
        assert reconstructed.event == original.event
        assert reconstructed.kind == original.kind
        assert reconstructed.decision == original.decision
        assert reconstructed.host == original.host
        assert reconstructed.details == original.details
