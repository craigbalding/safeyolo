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
    HttpEvent,
    CredentialType,
    CredentialConfidence,
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

    # Extract headers present (lowercase names only, not values)
    headers_present = [h.lower() for h in flow.request.headers.keys()]

    # Determine port
    port = flow.request.port
    if port is None:
        port = 443 if flow.request.scheme == "https" else 80

    # Split path from query string
    path_parts = flow.request.path.split("?", 1)
    path_no_query = path_parts[0]

    # Get query string
    query_string = None
    if len(path_parts) > 1:
        query_string = path_parts[1]
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
    )
