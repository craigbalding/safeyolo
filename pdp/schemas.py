"""
schemas.py - HttpEvent and PolicyDecision schemas for SafeYolo PDP

This module defines the canonical data contracts between sensors (mitmproxy addons)
and the Policy Decision Point (PDP) service.

Design principles:
- HttpEvent: Strict validation (extra="forbid") - fail fast on schema drift
- PolicyDecision: Lenient validation (extra="ignore") - forward compatible
- Sensor detects credentials, PDP evaluates policy (PDP never sees raw secrets)
- Metadata-first: bodies are optional, hashed, never raw

Schema version: 1
"""

from datetime import datetime
from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

# =============================================================================
# Enums
# =============================================================================

class EventKind(str, Enum):
    """Type of HTTP event."""
    HTTP_REQUEST = "http.request"
    HTTP_RESPONSE = "http.response"  # v2: for post-upstream evaluation


class EventPhase(str, Enum):
    """When in the request lifecycle this event was emitted."""
    PRE_UPSTREAM = "pre_upstream"    # Before request sent to upstream (can enforce)
    POST_UPSTREAM = "post_upstream"  # After response received (audit only)


class IdentitySource(str, Enum):
    """How principal identity was determined."""
    IPMAP = "ipmap"      # IP address mapping (current default)
    MTLS = "mtls"        # mTLS client certificate
    MANUAL = "manual"    # Manually configured
    UNKNOWN = "unknown"  # Could not determine


class CredentialType(str, Enum):
    """Known credential types (extensible)."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GITHUB = "github"
    UNKNOWN = "unknown"


class CredentialConfidence(str, Enum):
    """Confidence level of credential detection."""
    HIGH = "high"      # Matched known pattern with high specificity
    MEDIUM = "medium"  # Matched pattern but could be false positive
    LOW = "low"        # Heuristic detection (e.g., high entropy string)


class BodyObserved(str, Enum):
    """How much of the body was observed by the sensor."""
    METADATA = "metadata"  # Only presence/size/content-type
    FULL = "full"          # Entire body read
    TRUNCATED = "truncated"  # Body read but truncated to limit


class Effect(str, Enum):
    """Policy decision effect."""
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    BUDGET_EXCEEDED = "budget_exceeded"
    ERROR = "error"  # PDP internal error


# =============================================================================
# HttpEvent - Request Schema (sensor -> PDP)
# =============================================================================

class EventBlock(BaseModel):
    """Event identification and provenance."""
    model_config = ConfigDict(extra="forbid")

    # REQUIRED: Correlation IDs
    event_id: str = Field(..., description="Unique event ID (e.g., evt_...)")
    trace_id: str = Field(..., description="Trace ID for request correlation (= event_id for v1)")

    # REQUIRED: Event classification
    kind: EventKind = Field(..., description="Type of event")
    phase: EventPhase = Field(..., description="Request lifecycle phase")

    # REQUIRED: Provenance
    timestamp: datetime = Field(..., description="When event was created (ISO 8601)")
    sensor_id: str = Field(..., description="Which sensor produced this event")

    # OPTIONAL: Correlation with prior events
    parent_event_id: str | None = Field(None, description="For response events, points to request event")
    retry_of_event_id: str | None = Field(None, description="If this is a retry of a prior request")

    # OPTIONAL: Error from sensor
    sensor_error: str | None = Field(None, description="Sensor-level error (timeout, connection_refused, etc.)")


class PrincipalBlock(BaseModel):
    """Identity of the requester."""
    model_config = ConfigDict(extra="forbid")

    # REQUIRED
    principal_id: str = Field(..., description="Stable identity (e.g., agent:claude-dev, project:team-a)")
    identity_source: IdentitySource = Field(..., description="How identity was determined")

    # OPTIONAL: Attributes for policy matching
    attributes: dict[str, str] = Field(default_factory=dict, description="Labels (team, repo, tool)")


class HttpBlock(BaseModel):
    """HTTP request metadata."""
    model_config = ConfigDict(extra="forbid")

    # REQUIRED
    method: str = Field(..., description="HTTP method (GET, POST, etc.)")
    scheme: str = Field(..., description="URL scheme (http, https)")
    host: str = Field(..., description="Target host")
    port: int = Field(..., description="Target port")
    path: str = Field(..., description="Path WITHOUT query string")

    # REQUIRED: What headers are present (values not sent)
    headers_present: list[str] = Field(..., description="Lowercase header names that are present")

    # OPTIONAL
    query_string: str | None = Field(None, description="Raw query string (if any)")
    is_upgrade: bool = Field(False, description="WebSocket upgrade request")
    is_streaming_hint: bool = Field(False, description="Likely streaming (SSE, chunked)")


class CredentialBlock(BaseModel):
    """Credential detection results from sensor.

    IMPORTANT: Raw credential values are NEVER sent to PDP.
    Sensor detects and fingerprints credentials; PDP evaluates policy.
    """
    model_config = ConfigDict(extra="forbid")

    # REQUIRED
    detected: bool = Field(..., description="Whether any credential was detected")

    # Present only if detected=True
    type: CredentialType | None = Field(None, description="Detected credential type")
    fingerprint: str | None = Field(None, description="HMAC fingerprint (e.g., a1b2c3d4...)")
    confidence: CredentialConfidence | None = Field(None, description="Detection confidence")


class BodyBlock(BaseModel):
    """Request/response body metadata.

    Metadata-first: body bytes are NOT sent by default.
    """
    model_config = ConfigDict(extra="forbid")

    # REQUIRED
    present: bool = Field(..., description="Whether body exists")
    observed: BodyObserved = Field(BodyObserved.METADATA, description="How much was read")

    # OPTIONAL: Metadata (available even if body not read)
    size_bytes: int | None = Field(None, description="Content-Length if known")
    content_type: str | None = Field(None, description="Content-Type header value")

    # OPTIONAL: Only if observed != METADATA
    sha256: str | None = Field(None, description="SHA256 of decoded body bytes")


class ContextBlock(BaseModel):
    """Optional context for policy evaluation."""
    model_config = ConfigDict(extra="forbid")

    task_id: str | None = Field(None, description="Task ID for task-scoped policies")
    session_id: str | None = Field(None, description="Session ID for continuity")
    project_id: str | None = Field(None, description="Project ID if distinct from principal")


class HttpEvent(BaseModel):
    """
    Canonical HTTP event produced by sensor for PDP evaluation.

    Version: 1
    Direction: Sensor -> PDP
    Validation: Strict (extra="forbid")

    V1 scope:
    - Only pre_upstream/http.request events (enforcement)
    - Credential detection done by sensor, fingerprint only sent to PDP
    - Body metadata only (no bytes)
    - Response block reserved for v2 (post_upstream events)
    """
    model_config = ConfigDict(extra="forbid")

    # Schema version
    version: Annotated[int, Field(strict=True)] = Field(1, description="Schema version (must be 1)")

    # REQUIRED blocks
    event: EventBlock
    principal: PrincipalBlock
    http: HttpBlock
    credential: CredentialBlock
    body: BodyBlock

    # OPTIONAL
    context: ContextBlock | None = Field(None, description="Task/session context")


# =============================================================================
# PolicyDecision - Response Schema (PDP -> sensor)
# =============================================================================

class DecisionEventBlock(BaseModel):
    """Echo of event IDs plus policy metadata."""
    model_config = ConfigDict(extra="ignore")  # Forward compatible

    # REQUIRED: Echo input IDs
    event_id: str = Field(..., description="Echo of input event_id")
    trace_id: str | None = Field(None, description="Echo of input trace_id")

    # REQUIRED: Policy provenance
    policy_hash: str = Field(..., description="Hash of policy used for this decision")
    engine_version: str = Field(..., description="PDP version (e.g., pdp-0.3.1)")

    # OPTIONAL
    policy_version: str | None = Field(None, description="Human-readable policy version")


class ChecksBlock(BaseModel):
    """Capability model - which checks the sensor should perform.

    Decouples PDP API from internal addon names.
    """
    model_config = ConfigDict(extra="ignore")

    # V1: List of required checks (sensor must perform these)
    required: list[str] = Field(
        default_factory=list,
        description="Checks sensor must perform (credential_detection, credential_validation, rate_limit)"
    )

    # V1 OPTIONAL: Fine-grained modes per check
    modes: dict[str, str] = Field(
        default_factory=dict,
        description="Check name -> mode (required, optional, skip)"
    )


class BudgetBlock(BaseModel):
    """Rate limit / budget information."""
    model_config = ConfigDict(extra="ignore")

    # Present when rate_limit check was performed
    consumed: int = Field(0, description="Units consumed for this request")
    remaining: int | None = Field(None, description="Remaining budget in window")
    limit: int | None = Field(None, description="Total budget limit")
    window_seconds: int | None = Field(None, description="Budget window duration")
    retry_after_seconds: int | None = Field(None, description="Suggested wait time if exceeded")


class ImmediateResponseBlock(BaseModel):
    """Pre-built response for non-allow decisions.

    PDP provides consistent error responses; sensor enforces.
    """
    model_config = ConfigDict(extra="ignore")

    status_code: int = Field(..., description="HTTP status code (403, 428, 429, etc.)")
    headers: dict[str, str] = Field(default_factory=dict, description="Response headers")
    body_json: dict = Field(default_factory=dict, description="JSON response body")


class ApprovalBlock(BaseModel):
    """Information for require_approval flow."""
    model_config = ConfigDict(extra="ignore")

    event_id: str = Field(..., description="Approval event ID for tracking")
    suggested_scope: dict = Field(default_factory=dict, description="Suggested approval scope")
    expires_in_seconds: int = Field(3600, description="Suggested TTL for grants")


class CacheBlock(BaseModel):
    """Caching hints for sensor."""
    model_config = ConfigDict(extra="ignore")

    allowed: bool = Field(False, description="Whether this decision can be cached")
    ttl_seconds: int = Field(0, description="Cache TTL if allowed")
    vary_by: list[str] = Field(default_factory=list, description="Fields that affect caching")


class PolicyDecision(BaseModel):
    """
    Policy decision returned by PDP.

    Version: 1
    Direction: PDP -> Sensor
    Validation: Lenient (extra="ignore") for forward compatibility

    V1 scope:
    - Core decision (effect, reason, reason_codes)
    - Budget info when applicable
    - Pre-built error responses for enforcement
    - Checks block optional (sensor knows what to run today)
    """
    model_config = ConfigDict(extra="ignore")

    # Schema version
    version: int = Field(1, description="Schema version")

    # REQUIRED: Correlation
    event: DecisionEventBlock

    # REQUIRED: Decision
    effect: Effect = Field(..., description="Policy decision effect")
    reason: str = Field(..., description="Human-readable reason")
    reason_codes: list[str] = Field(default_factory=list, description="Stable codes for metrics/filtering")

    # OPTIONAL: Capability model (defer for v1 if sensor always runs same checks)
    checks: ChecksBlock | None = Field(None, description="Which checks sensor should perform")

    # OPTIONAL: Budget info (present if rate_limit relevant)
    budget: BudgetBlock | None = Field(None, description="Rate limit / budget status")

    # OPTIONAL: Pre-built response for non-allow decisions
    immediate_response: ImmediateResponseBlock | None = Field(
        None, description="Response for sensor to return on deny/require_approval"
    )

    # OPTIONAL: Approval flow info
    approval: ApprovalBlock | None = Field(None, description="For require_approval effect")

    # OPTIONAL: Caching hints
    cache: CacheBlock | None = Field(None, description="Caching guidance for sensor")


# =============================================================================
# Factory Functions (convenience for sensors)
# =============================================================================

def create_http_event(
    *,
    event_id: str,
    sensor_id: str,
    principal_id: str,
    method: str,
    host: str,
    port: int,
    path: str,
    headers_present: list[str],
    credential_detected: bool = False,
    credential_type: CredentialType | None = None,
    credential_fingerprint: str | None = None,
    credential_confidence: CredentialConfidence | None = None,
    body_present: bool = False,
    body_size: int | None = None,
    body_content_type: str | None = None,
    task_id: str | None = None,
    identity_source: IdentitySource = IdentitySource.IPMAP,
    scheme: str = "https",
    query_string: str | None = None,
    timestamp: datetime | None = None,
) -> HttpEvent:
    """Create an HttpEvent with sensible defaults for v1.

    This is the primary factory for sensors building events from request data.
    """
    return HttpEvent(
        version=1,
        event=EventBlock(
            event_id=event_id,
            trace_id=event_id,  # v1: trace_id = event_id
            kind=EventKind.HTTP_REQUEST,
            phase=EventPhase.PRE_UPSTREAM,
            timestamp=timestamp or datetime.utcnow(),
            sensor_id=sensor_id,
        ),
        principal=PrincipalBlock(
            principal_id=principal_id,
            identity_source=identity_source,
        ),
        http=HttpBlock(
            method=method.upper(),
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            headers_present=[h.lower() for h in headers_present],
            query_string=query_string,
        ),
        credential=CredentialBlock(
            detected=credential_detected,
            type=credential_type if credential_detected else None,
            fingerprint=credential_fingerprint if credential_detected else None,
            confidence=credential_confidence if credential_detected else None,
        ),
        body=BodyBlock(
            present=body_present,
            observed=BodyObserved.METADATA,
            size_bytes=body_size,
            content_type=body_content_type,
        ),
        context=ContextBlock(task_id=task_id) if task_id else None,
    )


def create_allow_decision(
    *,
    event_id: str,
    policy_hash: str,
    engine_version: str,
    reason: str = "Allowed by policy",
    reason_codes: list[str] | None = None,
    budget_remaining: int | None = None,
) -> PolicyDecision:
    """Create an ALLOW decision."""
    return PolicyDecision(
        version=1,
        event=DecisionEventBlock(
            event_id=event_id,
            policy_hash=policy_hash,
            engine_version=engine_version,
        ),
        effect=Effect.ALLOW,
        reason=reason,
        reason_codes=reason_codes or ["ALLOWED"],
        budget=BudgetBlock(remaining=budget_remaining) if budget_remaining is not None else None,
    )


def create_deny_decision(
    *,
    event_id: str,
    policy_hash: str,
    engine_version: str,
    reason: str,
    reason_codes: list[str],
    status_code: int = 403,
    response_body: dict | None = None,
) -> PolicyDecision:
    """Create a DENY decision with immediate response."""
    return PolicyDecision(
        version=1,
        event=DecisionEventBlock(
            event_id=event_id,
            policy_hash=policy_hash,
            engine_version=engine_version,
        ),
        effect=Effect.DENY,
        reason=reason,
        reason_codes=reason_codes,
        immediate_response=ImmediateResponseBlock(
            status_code=status_code,
            headers={"content-type": "application/json"},
            body_json=response_body or {
                "error": "Denied",
                "event_id": event_id,
                "reason": reason,
                "reason_codes": reason_codes,
            },
        ),
    )


def create_budget_exceeded_decision(
    *,
    event_id: str,
    policy_hash: str,
    engine_version: str,
    reason: str = "Rate limit exceeded",
    retry_after_seconds: int = 60,
) -> PolicyDecision:
    """Create a BUDGET_EXCEEDED decision."""
    return PolicyDecision(
        version=1,
        event=DecisionEventBlock(
            event_id=event_id,
            policy_hash=policy_hash,
            engine_version=engine_version,
        ),
        effect=Effect.BUDGET_EXCEEDED,
        reason=reason,
        reason_codes=["BUDGET_EXCEEDED"],
        budget=BudgetBlock(
            remaining=0,
            retry_after_seconds=retry_after_seconds,
        ),
        immediate_response=ImmediateResponseBlock(
            status_code=429,
            headers={
                "content-type": "application/json",
                "retry-after": str(retry_after_seconds),
            },
            body_json={
                "error": "Rate limit exceeded",
                "event_id": event_id,
                "retry_after_seconds": retry_after_seconds,
            },
        ),
    )
