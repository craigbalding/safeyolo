"""
sse_streaming.py - Native mitmproxy addon for SSE/streaming response support

mitmproxy buffers responses by default, which breaks SSE (Server-Sent Events)
and other streaming protocols. This addon enables streaming for responses that
need it, based on Content-Type or policy configuration.

Security note: Only the response BODY bypasses inspection. Request headers/body
(including credentials) are still fully inspected by credential_guard and other
addons. This is the correct tradeoff - we care about outbound leakage, not
inbound streaming data.

Usage:
    mitmdump -s addons/sse_streaming.py

Policy configuration (in policy.yaml):
    domains:
      "ntfy.sh":
        addons:
          sse_streaming:
            enabled: true
            stream_json: true  # Also stream JSON endpoints

      "mcp.apify.com":
        addons:
          sse_streaming:
            enabled: true

See: https://github.com/mitmproxy/mitmproxy/issues/4469
"""

import logging
from typing import Optional

from mitmproxy import ctx, http

log = logging.getLogger("safeyolo.sse_streaming")

# Content types that indicate SSE/streaming
SSE_CONTENT_TYPES = [
    "text/event-stream",
    "application/x-ndjson",  # Newline-delimited JSON
]


class SSEStreaming:
    """
    Native mitmproxy addon for SSE streaming support.

    Enables response streaming for SSE and other streaming protocols
    so they pass through unbuffered.
    """

    name = "sse_streaming"

    def __init__(self):
        # Stats
        self.streams_enabled = 0
        self.streams_by_domain: dict[str, int] = {}
        self.streams_by_content_type: dict[str, int] = {}

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="sse_streaming_enabled",
            typespec=bool,
            default=True,
            help="Enable SSE streaming support globally",
        )

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        """Check response headers and enable streaming if needed."""
        if not ctx.options.sse_streaming_enabled:
            return

        content_type = flow.response.headers.get("content-type", "")
        host = flow.request.host

        # Check policy first
        policy = flow.metadata.get("policy")
        if policy:
            if not policy.is_addon_enabled(self.name):
                return
            settings = policy.get_addon_settings(self.name)
        else:
            settings = {}

        should_stream = False
        stream_reason = None

        # Check for SSE content types
        for sse_type in SSE_CONTENT_TYPES:
            if content_type.startswith(sse_type):
                should_stream = True
                stream_reason = sse_type
                break

        # Check for JSON streaming if enabled in policy
        if not should_stream and settings.get("stream_json"):
            if content_type.startswith("application/json"):
                # Only stream JSON for long-lived connections (e.g., ntfy /json)
                should_stream = True
                stream_reason = "application/json (policy)"

        if should_stream:
            flow.response.stream = True
            self._record_stream(host, stream_reason)
            ctx.log.info(f"SSE streaming enabled: {host} ({stream_reason})")

    def _record_stream(self, domain: str, content_type: str) -> None:
        """Record streaming stats."""
        self.streams_enabled += 1
        self.streams_by_domain[domain] = self.streams_by_domain.get(domain, 0) + 1
        self.streams_by_content_type[content_type] = (
            self.streams_by_content_type.get(content_type, 0) + 1
        )

    def get_stats(self) -> dict:
        """Get streaming statistics."""
        return {
            "enabled": ctx.options.sse_streaming_enabled,
            "streams_enabled_total": self.streams_enabled,
            "streams_by_domain": dict(self.streams_by_domain),
            "streams_by_content_type": dict(self.streams_by_content_type),
        }


# mitmproxy addon instance
sse_streaming = SSEStreaming()
addons = [sse_streaming]
