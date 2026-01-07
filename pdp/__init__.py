"""
pdp - Policy Decision Point for SafeYolo

This package provides the PDP as both a library and a service.

Library usage (in-process, default):
    from pdp import PolicyClient, PolicyClientConfig, get_policy_client
    from pdp.schemas import HttpEvent, PolicyDecision, create_http_event

    # Create event from request data
    event = create_http_event(
        event_id="evt_123",
        sensor_id="mitmproxy@host",
        principal_id="agent:claude-dev",
        method="POST",
        host="api.openai.com",
        port=443,
        path="/v1/chat/completions",
        headers_present=["authorization", "content-type"],
        credential_detected=True,
        credential_type=CredentialType.OPENAI,
        credential_fingerprint="a1b2c3d4",
    )

    # Get client (defaults to local/in-process)
    client = get_policy_client()

    # Evaluate
    decision = client.evaluate(event)
    if decision.effect == Effect.ALLOW:
        # Allow request
        pass
    else:
        # Block with decision.immediate_response
        pass

Service usage (FastAPI):
    uvicorn pdp.app:app --host 0.0.0.0 --port 8080

HTTP client usage:
    from pdp import PolicyClientConfig, get_policy_client

    config = PolicyClientConfig(
        mode="http",
        endpoint="http://127.0.0.1:8080",
        timeout_ms=500,
    )
    client = get_policy_client(config)
    decision = client.evaluate(event)
"""

from .admin_client import (
    AdminClientConfig,
    HttpPDPAdminClient,
    LocalPDPAdminClient,
    PDPAdminClient,
    get_admin_client,
    reset_admin_client,
)
from .client import (
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
from .core import (
    ENGINE_VERSION,
    PDPCore,
    get_pdp,
    reset_pdp,
)
from .schemas import (
    ApprovalBlock,
    BodyBlock,
    BodyObserved,
    BudgetBlock,
    CacheBlock,
    ChecksBlock,
    ContextBlock,
    CredentialBlock,
    CredentialConfidence,
    CredentialType,
    # Decision blocks
    DecisionEventBlock,
    Effect,
    # Event blocks
    EventBlock,
    # Enums
    EventKind,
    EventPhase,
    HttpBlock,
    HttpEvent,
    IdentitySource,
    ImmediateResponseBlock,
    PolicyDecision,
    PrincipalBlock,
    create_allow_decision,
    create_budget_exceeded_decision,
    create_deny_decision,
    # Factory functions
    create_http_event,
)

__all__ = [
    # Enums
    "EventKind",
    "EventPhase",
    "IdentitySource",
    "CredentialType",
    "CredentialConfidence",
    "BodyObserved",
    "Effect",
    # Event schema
    "EventBlock",
    "PrincipalBlock",
    "HttpBlock",
    "CredentialBlock",
    "BodyBlock",
    "ContextBlock",
    "HttpEvent",
    # Decision schema
    "DecisionEventBlock",
    "ChecksBlock",
    "BudgetBlock",
    "ImmediateResponseBlock",
    "ApprovalBlock",
    "CacheBlock",
    "PolicyDecision",
    # Factory functions
    "create_http_event",
    "create_allow_decision",
    "create_deny_decision",
    "create_budget_exceeded_decision",
    # Client interface
    "PolicyClient",
    "PolicyClientConfig",
    "LocalPolicyClient",
    "HttpPolicyClient",
    "UnavailableMode",
    "configure_policy_client",
    "get_policy_client",
    "is_policy_client_configured",
    "reset_policy_client",
    # Core
    "PDPCore",
    "get_pdp",
    "reset_pdp",
    "ENGINE_VERSION",
    # Admin client
    "PDPAdminClient",
    "AdminClientConfig",
    "LocalPDPAdminClient",
    "HttpPDPAdminClient",
    "get_admin_client",
    "reset_admin_client",
]
