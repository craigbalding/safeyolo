"""Tests for audit_schema — the shared audit event contract.

Organised by contract area:
- Enums (closed sets)
- sanitize_for_log (canonical implementation)
- ApprovalRequest
- AuditEvent construction (valid)
- AuditEvent validation (fail-closed: naive ts, empty summary, wrong version,
  kind/event mismatch, extra fields)
- Round-trip equality (full-dict)
- parse_audit_event reader helper
"""

import copy
import json
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest
from pydantic import ValidationError

from audit_schema import (
    SCHEMA_VERSION,
    ApprovalRequest,
    ApprovalType,
    AuditEvent,
    Decision,
    EventKind,
    InvalidAuditEvent,
    Severity,
    parse_audit_event,
    sanitize_for_log,
)

# =========================================================================
# Enums — closed sets
# =========================================================================


class TestEventKind:
    def test_value_set(self):
        assert {k.value for k in EventKind} == {
            "security", "gateway", "traffic", "ops", "admin", "agent"
        }

    def test_string_inheritance(self):
        """StrEnum: members compare equal to their string value."""
        assert EventKind.SECURITY == "security"


class TestSeverity:
    def test_value_set(self):
        assert {s.value for s in Severity} == {"critical", "high", "medium", "low"}


class TestDecision:
    def test_value_set(self):
        """Decision does NOT include 'block' — SafeYolo uses 'deny' everywhere."""
        assert {d.value for d in Decision} == {
            "allow", "deny", "warn", "require_approval", "budget_exceeded", "log"
        }
        assert "block" not in {d.value for d in Decision}


class TestApprovalType:
    def test_value_set(self):
        assert {a.value for a in ApprovalType} == {
            "credential", "network_egress", "gateway_route", "service", "contract_binding"
        }


# =========================================================================
# sanitize_for_log — canonical implementation, previously untested here
# =========================================================================


class TestSanitizeForLog:
    def test_none_returns_empty_string(self):
        assert sanitize_for_log(None) == ""

    def test_empty_string_returns_empty(self):
        assert sanitize_for_log("") == ""

    def test_non_string_coerced_via_str(self):
        assert sanitize_for_log(42) == "42"
        assert sanitize_for_log(True) == "True"

    def test_plain_ascii_preserved(self):
        assert sanitize_for_log("hello world") == "hello world"

    def test_control_chars_blocked(self):
        """Newline, tab, CR, NUL, 0x1f, 0x7f are replaced with '?'."""
        for ch in ["\n", "\t", "\r", "\x00", "\x1f", "\x7f"]:
            assert "?" in sanitize_for_log(f"a{ch}b")

    def test_line_separator_u2028_blocked(self):
        """U+2028 (LINE SEPARATOR) and U+2029 (PARAGRAPH SEPARATOR) are blocked
        log-injection vectors."""
        out = sanitize_for_log("a\u2028b")
        assert "\u2028" not in out

    def test_paragraph_separator_u2029_blocked(self):
        out = sanitize_for_log("a\u2029b")
        assert "\u2029" not in out

    def test_ansi_csi_sequences_replaced(self):
        """ANSI color escapes are replaced with '?'."""
        out = sanitize_for_log("\x1b[31mred\x1b[0m")
        assert "\x1b" not in out
        assert "red" in out

    def test_unicode_letters_preserved(self):
        assert sanitize_for_log("héllo") == "héllo"

    def test_emoji_preserved(self):
        """Emojis (Unicode So category) are preserved."""
        assert "🔒" in sanitize_for_log("hello 🔒")

    def test_consecutive_replacements_collapsed(self):
        """Multiple blocked chars in a row collapse into a single '?'."""
        out = sanitize_for_log("\x00\x01\x02x")
        assert out == "?x"

    def test_truncation_at_max_len_suffixes_with_ellipsis(self):
        out = sanitize_for_log("a" * 250, max_len=200)
        assert len(out) == 203  # 200 + "..."
        assert out.endswith("...")

    def test_short_string_not_truncated(self):
        assert sanitize_for_log("short", max_len=200) == "short"

    def test_custom_max_len_respected(self):
        out = sanitize_for_log("abcdef", max_len=3)
        assert out == "abc..."


# =========================================================================
# ApprovalRequest
# =========================================================================


class TestApprovalRequestConstruction:
    def test_minimal_valid(self):
        a = ApprovalRequest(
            required=True,
            approval_type=ApprovalType.CREDENTIAL,
            key="hmac:abc",
            target="api.openai.com",
        )
        assert a.required is True
        assert a.approval_type == ApprovalType.CREDENTIAL
        assert a.scope_hint == {}

    def test_string_coerced_to_enum(self):
        """StrEnum coercion: passing a raw string that matches a value works."""
        a = ApprovalRequest(
            required=True,
            approval_type="credential",
            key="k",
            target="t",
        )
        assert a.approval_type == ApprovalType.CREDENTIAL

    def test_with_scope_hint(self):
        a = ApprovalRequest(
            required=False,
            approval_type=ApprovalType.NETWORK_EGRESS,
            key="evil.com",
            target="evil.com",
            scope_hint={"rule": "default-deny"},
        )
        assert a.scope_hint["rule"] == "default-deny"


class TestApprovalRequestValidation:
    def test_unknown_approval_type_raises(self):
        with pytest.raises(ValidationError):
            ApprovalRequest(
                required=True,
                approval_type="made_up_type",
                key="k",
                target="t",
            )

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            ApprovalRequest(
                required=True,
                approval_type=ApprovalType.CREDENTIAL,
                key="k",
                target="t",
                unknown_field="nope",
            )


# =========================================================================
# AuditEvent — valid construction
# =========================================================================


def _valid_event(**overrides) -> AuditEvent:
    """Build a valid minimal AuditEvent; overrides replace individual fields."""
    kwargs = {
        "event": "ops.startup",
        "kind": EventKind.OPS,
        "severity": Severity.LOW,
        "summary": "started",
    }
    kwargs.update(overrides)
    return AuditEvent(**kwargs)


class TestAuditEventValid:
    def test_minimal_event_populates_defaults(self):
        e = _valid_event()
        assert e.schema_version == SCHEMA_VERSION
        assert e.ts.tzinfo is not None
        assert e.details == {}
        assert e.decision is None

    def test_full_event(self):
        e = AuditEvent(
            event="security.credential_guard",
            kind=EventKind.SECURITY,
            severity=Severity.CRITICAL,
            summary="OpenAI key blocked to wrong host",
            request_id="req-abc",
            agent="claude",
            addon="credential-guard",
            decision=Decision.DENY,
            host="httpbin.org",
            approval=ApprovalRequest(
                required=True,
                approval_type=ApprovalType.CREDENTIAL,
                key="hmac:abc",
                target="httpbin.org",
            ),
            details={"rule": "openai"},
        )
        assert e.decision == Decision.DENY
        assert e.approval.required is True

    def test_to_jsonl_excludes_none(self):
        """exclude_none=True: unset fields disappear from the output dict."""
        e = _valid_event()
        d = e.to_jsonl()
        assert "request_id" not in d
        assert "agent" not in d
        assert "decision" not in d
        assert "host" not in d
        assert "approval" not in d

    def test_to_jsonl_includes_required_fields(self):
        e = _valid_event(host="example.com")
        d = e.to_jsonl()
        assert d["event"] == "ops.startup"
        assert d["kind"] == "ops"
        assert d["severity"] == "low"
        assert d["schema_version"] == SCHEMA_VERSION
        assert d["host"] == "example.com"
        assert "ts" in d

    def test_to_jsonl_is_json_serializable(self):
        e = _valid_event(details={"rss_mb": 100.5})
        d = e.to_jsonl()
        parsed = json.loads(json.dumps(d))
        assert parsed["details"]["rss_mb"] == 100.5

    def test_details_default_is_independent_per_instance(self):
        e1 = _valid_event()
        e2 = _valid_event()
        e1.details["x"] = 1
        assert "x" not in e2.details


# =========================================================================
# AuditEvent — validation failures (fail-closed contract)
# =========================================================================


class TestAuditEventErrors:
    def test_wrong_schema_version_raises(self):
        with pytest.raises(ValidationError, match="schema_version"):
            _valid_event(schema_version=99)

    def test_naive_ts_raises(self):
        """Contract: timestamps must be timezone-aware."""
        with pytest.raises(ValidationError, match="timezone-aware"):
            _valid_event(ts=datetime(2026, 1, 1, 12, 0, 0))

    def test_tz_aware_non_utc_ts_accepted(self):
        """Any tz-aware datetime is fine; conversion to UTC happens downstream."""
        eastern = ZoneInfo("America/New_York")
        e = _valid_event(ts=datetime(2026, 1, 1, 12, 0, 0, tzinfo=eastern))
        assert e.ts.tzinfo is not None

    def test_empty_summary_raises(self):
        """Contract: summary must be a non-empty human-readable line."""
        with pytest.raises(ValidationError):
            _valid_event(summary="")

    def test_event_empty_string_raises(self):
        """Empty event fails the kind-prefix validator."""
        with pytest.raises(ValidationError):
            _valid_event(event="")

    def test_event_prefix_must_match_kind(self):
        """A security kind with a traffic event is drift and must be rejected."""
        with pytest.raises(ValidationError, match="does not match kind"):
            AuditEvent(
                event="traffic.request",
                kind=EventKind.SECURITY,
                severity=Severity.LOW,
                summary="mismatched",
            )

    def test_event_without_prefix_raises(self):
        with pytest.raises(ValidationError, match="does not match kind"):
            _valid_event(event="bare_name")

    def test_unknown_kind_raises(self):
        with pytest.raises(ValidationError):
            _valid_event(kind="not_a_kind")

    def test_extra_spine_fields_forbidden(self):
        with pytest.raises(ValidationError):
            _valid_event(unknown_spine="nope")


# =========================================================================
# Round-trip (full-dict equality) — pins the shared-contract promise
# =========================================================================


class TestAuditEventRoundTrip:
    def test_minimal_round_trip_full_dict_equality(self):
        original = _valid_event()
        restored = AuditEvent.model_validate(
            json.loads(json.dumps(original.to_jsonl()))
        )
        assert restored.to_jsonl() == original.to_jsonl()

    def test_full_round_trip_full_dict_equality(self):
        original = AuditEvent(
            event="security.network_guard",
            kind=EventKind.SECURITY,
            severity=Severity.HIGH,
            summary="Access denied to evil.com",
            decision=Decision.DENY,
            host="evil.com",
            request_id="req-123",
            addon="network-guard",
            agent="boris",
            approval=ApprovalRequest(
                required=True,
                approval_type=ApprovalType.NETWORK_EGRESS,
                key="evil.com",
                target="evil.com",
                scope_hint={"rule": "default-deny"},
            ),
            details={"reason": "not in allowlist", "attempts": 3},
        )
        restored = AuditEvent.model_validate(
            json.loads(json.dumps(original.to_jsonl()))
        )
        assert restored.to_jsonl() == original.to_jsonl()

    def test_every_event_kind_round_trips(self):
        """Each EventKind/event prefix pair survives a round trip."""
        for kind in EventKind:
            original = AuditEvent(
                event=f"{kind.value}.test",
                kind=kind,
                severity=Severity.LOW,
                summary="k",
            )
            restored = AuditEvent.model_validate(
                json.loads(json.dumps(original.to_jsonl()))
            )
            assert restored.kind == kind


# =========================================================================
# parse_audit_event — reader helper
# =========================================================================


class TestParseAuditEvent:
    def test_valid_dict_returns_audit_event(self):
        raw = _valid_event().to_jsonl()
        ev = parse_audit_event(raw)
        assert isinstance(ev, AuditEvent)
        assert ev.event == "ops.startup"

    def test_non_dict_raises_invalid_audit_event(self):
        with pytest.raises(InvalidAuditEvent):
            parse_audit_event("not a dict")  # type: ignore[arg-type]

    def test_missing_required_field_raises_invalid(self):
        raw = {"event": "ops.startup", "kind": "ops", "severity": "low"}
        # missing `summary`
        with pytest.raises(InvalidAuditEvent) as exc_info:
            parse_audit_event(raw)
        assert exc_info.value.raw == raw

    def test_wrong_schema_version_raises_invalid(self):
        raw = _valid_event().to_jsonl()
        raw["schema_version"] = 99
        with pytest.raises(InvalidAuditEvent):
            parse_audit_event(raw)

    def test_unknown_spine_field_raises_invalid(self):
        raw = _valid_event().to_jsonl()
        raw["unknown_field"] = "nope"
        with pytest.raises(InvalidAuditEvent):
            parse_audit_event(raw)

    def test_naive_ts_round_trip_raises_invalid(self):
        """A log line whose ts is naive fails the reader too (symmetric contract)."""
        raw = _valid_event().to_jsonl()
        raw["ts"] = "2026-01-01T12:00:00"  # no timezone
        with pytest.raises(InvalidAuditEvent):
            parse_audit_event(raw)

    def test_parse_does_not_mutate_input(self):
        raw = _valid_event().to_jsonl()
        snapshot = copy.deepcopy(raw)
        parse_audit_event(raw)
        assert raw == snapshot
