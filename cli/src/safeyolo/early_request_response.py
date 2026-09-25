"""Respond to a denied request head before mitmproxy opens the origin.

mitmproxy 12.2.3 calls ``start_request_stream`` after ``requestheaders``.
Its stock method rejects an addon response for a streamed request and would
otherwise open the origin before ``request`` runs. This pinned integration
keeps the stock path for every flow without a request-head denial.
Review this private method integration when the locked mitmproxy changes.
"""

from __future__ import annotations

import time
from importlib.metadata import version

from mitmproxy.proxy import commands
from mitmproxy.proxy.layers.http import HttpResponseHeadersHook, HttpStream


def install_early_request_response() -> None:
    """Install the per-flow early denial path before the proxy starts."""
    if version("mitmproxy") != "12.2.3":
        raise RuntimeError("early request response requires reviewed mitmproxy 12.2.3")

    original = HttpStream.start_request_stream

    def start_request_stream(self):
        if not self.flow.metadata.get("request_head_denied"):
            yield from original(self)
            return

        # The request body has not been released. Never dial the origin; send
        # the addon response and close an HTTP/1 client so its pending body
        # cannot be parsed as the next request on a persistent connection.
        if self.flow.response is None:
            raise RuntimeError("request head marked denied without a response")
        self.client_state = self.state_done
        self.flow.response.timestamp_start = time.time()
        yield HttpResponseHeadersHook(self.flow)
        if (yield from self.check_killed(True)):
            return
        yield from self.send_response()
        if not (self.flow.request.is_http2 or self.flow.request.is_http3):
            yield commands.CloseConnection(self.context.client)

    HttpStream.start_request_stream = start_request_stream
