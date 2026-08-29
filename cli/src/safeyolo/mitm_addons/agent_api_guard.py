"""Early request containment for the host-local Agent API destination.

This addon is deliberately separate from both the normal ``agent_api``
handler and the final transport guard.  It is loaded immediately after the
handler, before policy, credential, and observability addons can inspect an
unhandled internal request.  Only a response explicitly marked by AgentAPI is
accepted as handled; absent, disabled, import-failed, or uncaught handler
states receive a local diagnostic response.

The final ``transport_guard`` remains the independent server-connect
backstop.  This module imports only shared core identity and request helpers,
never the handler it is designed to survive.
"""

from __future__ import annotations

import json
import logging

from mitmproxy import http

from safeyolo.core.audit_schema import Decision, EventKind, Severity
from safeyolo.core.flow_cache import path_no_query
from safeyolo.core.internal_api import (
    AGENT_API_HOST,
    AGENT_API_RESPONSE_METADATA,
    AGENT_API_UNAVAILABLE_REASON,
    is_agent_api_host,
)
from safeyolo.core.utils import sanitize_for_log, write_event
from safeyolo.mitm_addons.request_id import ensure_request_id, recover_trusted_agent

log = logging.getLogger("safeyolo.agent-api-guard")


class AgentAPIRequestGuard:
    """Contain an Agent API request unless the normal handler owned it."""

    name = "agent-api-request-guard"

    @staticmethod
    def _handler_responded(flow: http.HTTPFlow) -> bool:
        return (
            flow.response is not None
            and flow.metadata.get(AGENT_API_RESPONSE_METADATA) is True
        )

    def request(self, flow: http.HTTPFlow) -> None:
        if not is_agent_api_host(flow.request.host):
            return
        if self._handler_responded(flow):
            return

        request_id = ensure_request_id(flow)
        path = path_no_query(flow)
        if not flow.metadata.get("agent"):
            trusted_agent = recover_trusted_agent(flow)
            if trusted_agent:
                flow.metadata["agent"] = trusted_agent

        # The handler is unavailable, so no downstream addon needs either the
        # bearer token or query.  Scrub both before yielding the request hook;
        # this makes the containment safe even if a downstream observer does
        # not honour flow.response/blocked_by.
        flow.request.headers.pop("authorization", None)
        flow.request.headers.pop("proxy-authorization", None)
        flow.request.path = path

        flow.response = http.Response.make(
            503,
            json.dumps(
                {
                    "error": "SafeYolo Agent API handler unavailable",
                    "reason_code": AGENT_API_UNAVAILABLE_REASON,
                    "handler": "agent-api",
                    "host": AGENT_API_HOST,
                    "path": path,
                    "request_id": request_id,
                }
            ).encode(),
            {
                "Content-Type": "application/json",
                "X-SafeYolo-Agent-API": "true",
                "X-SafeYolo-Request-Id": request_id,
            },
        )
        flow.metadata["blocked_by"] = self.name

        log.error(
            "AGENT API UNAVAILABLE — contained %s locally "
            "(handler=agent-api, path=%s, rid=%s, reason=%s).",
            AGENT_API_HOST,
            sanitize_for_log(path),
            request_id,
            AGENT_API_UNAVAILABLE_REASON,
        )
        try:
            write_event(
                "security.agent_api_unavailable",
                kind=EventKind.SECURITY,
                severity=Severity.HIGH,
                summary="Agent API handler unavailable; request contained locally",
                decision=Decision.DENY,
                host=AGENT_API_HOST,
                request_id=request_id,
                agent=flow.metadata.get("agent"),
                addon=self.name,
                details={
                    "reason_code": AGENT_API_UNAVAILABLE_REASON,
                    "handler": "agent-api",
                    "method": flow.request.method,
                    "path": path,
                },
            )
        except Exception as exc:
            # Response and scrubbing are already committed.  Observability
            # failure cannot weaken containment or restore credentials.
            log.error(
                "Agent API containment audit failed (rid=%s): %s",
                request_id,
                type(exc).__name__,
            )


addons = [AgentAPIRequestGuard()]
