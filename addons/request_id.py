"""
request_id.py - Request ID generator addon

Runs FIRST in the addon chain to assign a unique request_id to every request.
This enables event correlation across all downstream addons.

The request_id is stored in flow.metadata["request_id"] and should be included
in all logged events for traceability.
"""

import time
import uuid

from mitmproxy import http


class RequestIdGenerator:
    """
    Assigns unique request IDs to all incoming requests.

    Must run before any security addons to ensure request_id is available
    for logging decisions.
    """

    name = "request-id"

    def request(self, flow: http.HTTPFlow):
        """Assign request_id and start_time to incoming request."""
        # Use uuid4 prefix for uniqueness + timestamp suffix for ordering
        request_id = f"req-{uuid.uuid4().hex[:12]}"
        flow.metadata["request_id"] = request_id
        flow.metadata["start_time"] = time.time()


addons = [RequestIdGenerator()]
