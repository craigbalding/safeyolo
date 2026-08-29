"""Shared identity for the host-local Agent API virtual destination.

The Agent API handler and its structurally independent transport backstop both
need this value. Keeping it below ``mitm_addons`` means the backstop never has
to import the handler it is designed to survive.
"""

from __future__ import annotations

AGENT_API_HOST = "_safeyolo.proxy.internal"
AGENT_API_UNAVAILABLE_REASON = "agent_api_unavailable"
AGENT_API_REACHED_UPSTREAM_REASON = "agent_api_reached_upstream"
# Set only by AgentAPI after it installs a synthetic response.  The adjacent
# request guard uses explicit ownership rather than trusting an arbitrary
# response produced by an earlier addon.
AGENT_API_RESPONSE_METADATA = "safeyolo_agent_api_response"


def is_agent_api_host(host: str | None) -> bool:
    """Return whether ``host`` is the Agent API destination.

    DNS hostnames are case-insensitive. This matcher is used for both request
    routing and the transport backstop so casing cannot change the boundary.
    """
    if not host:
        return False
    return host.lower() == AGENT_API_HOST


__all__ = [
    "AGENT_API_HOST",
    "AGENT_API_REACHED_UPSTREAM_REASON",
    "AGENT_API_RESPONSE_METADATA",
    "AGENT_API_UNAVAILABLE_REASON",
    "is_agent_api_host",
]
