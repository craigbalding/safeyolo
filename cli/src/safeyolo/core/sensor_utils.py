"""
sensor_utils.py - Shared utilities for SafeYolo sensor addons

This module provides common functionality for sensors (mitmproxy addons)
that need to interact with the PDP.

Key function:
- build_http_event_from_flow(): Convert mitmproxy flow to HttpEvent

Design:
- Mitmproxy-specific code lives here, not in pdp/
- PDP package remains sensor-agnostic (could work with Envoy, etc.)
"""

import sys
import uuid
from pathlib import Path

from mitmproxy import http

# Add pdp to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from pdp import (
    CredentialConfidence,
    CredentialType,
    HttpEvent,
    create_http_event,
)

# Map rule names to CredentialType enum
RULE_TO_CREDENTIAL_TYPE = {
    "openai": CredentialType.OPENAI,
    "anthropic": CredentialType.ANTHROPIC,
    "github": CredentialType.GITHUB,
}

# Map confidence strings to enum
CONFIDENCE_MAP = {
    "high": CredentialConfidence.HIGH,
    "medium": CredentialConfidence.MEDIUM,
    "low": CredentialConfidence.LOW,
}


def build_http_event_from_flow(
    flow: http.HTTPFlow,
    principal_id: str,
    *,
    credential_detected: bool = False,
    credential_type: str | CredentialType | None = None,
    credential_fingerprint: str | None = None,
    credential_confidence: str | CredentialConfidence | None = None,
    task_id: str | None = None,
    agent: str | None = None,
) -> HttpEvent:
    """Build HttpEvent from mitmproxy flow.

    This is the canonical way for sensors to create HttpEvents for PDP evaluation.
    Credential detection is done by the sensor; PDP never sees raw credentials.

    Args:
        flow: mitmproxy HTTPFlow object
        principal_id: Identity of the requester (e.g., "project:team-a", "agent:claude")
        credential_detected: Whether a credential was found in this request
        credential_type: Type of credential (string like "openai" or CredentialType enum)
        credential_fingerprint: HMAC fingerprint of credential (not the raw value!)
        credential_confidence: Detection confidence ("high"/"medium"/"low" or enum)
        task_id: Optional task ID for task-scoped policies

    Returns:
        HttpEvent ready for PDP evaluation
    """
    # Generate or get request ID
    request_id = flow.metadata.get("request_id")
    if not request_id:
        request_id = f"req_{uuid.uuid4().hex[:12]}"

    # Get client IP for sensor_id
    client_ip = "unknown"
    if flow.client_conn and flow.client_conn.peername:
        client_ip = flow.client_conn.peername[0]

    # Map credential type string to enum if needed
    cred_type_enum = None
    if credential_detected and credential_type:
        if isinstance(credential_type, CredentialType):
            cred_type_enum = credential_type
        else:
            cred_type_enum = RULE_TO_CREDENTIAL_TYPE.get(
                credential_type.lower(), CredentialType.UNKNOWN
            )

    # Map confidence string to enum if needed
    confidence_enum = None
    if credential_detected and credential_confidence:
        if isinstance(credential_confidence, CredentialConfidence):
            confidence_enum = credential_confidence
        else:
            confidence_enum = CONFIDENCE_MAP.get(
                credential_confidence.lower(), CredentialConfidence.MEDIUM
            )

    # Per-flow cached derivations. These are the three reads that
    # previously cost every caller an iteration / split — the helpers
    # memoize on flow.metadata so the Nth call on the same flow is a
    # dict lookup. Raw request fields (method/host/scheme) are left
    # as direct reads; mitmproxy already caches them.
    from safeyolo.core.flow_cache import headers_present_lower
    from safeyolo.core.flow_cache import path_no_query as _path_no_query
    headers_present = headers_present_lower(flow)
    path_no_query = _path_no_query(flow)

    # Determine port
    port = flow.request.port
    if port is None:
        port = 443 if flow.request.scheme == "https" else 80

    # Query string: prefer the suffix we just split from path_no_query
    # (covers the case where mitmproxy's path includes `?…`); fall
    # back to request.query.urlencode() otherwise.
    full_path = flow.request.path
    query_string = None
    if "?" in full_path:
        query_string = full_path.split("?", 1)[1]
    elif flow.request.query:
        query_string = flow.request.query.urlencode()

    return create_http_event(
        event_id=f"evt_{request_id}",
        sensor_id=f"mitmproxy@{client_ip}",
        principal_id=principal_id,
        method=flow.request.method,
        host=flow.request.host,
        port=port,
        path=path_no_query,
        headers_present=headers_present,
        credential_detected=credential_detected,
        credential_type=cred_type_enum,
        credential_fingerprint=credential_fingerprint,
        credential_confidence=confidence_enum,
        body_present=bool(flow.request.content),
        body_size=len(flow.request.content) if flow.request.content else 0,
        body_content_type=flow.request.headers.get("content-type"),
        scheme=flow.request.scheme,
        query_string=query_string,
        task_id=task_id,
        agent=agent,
    )
