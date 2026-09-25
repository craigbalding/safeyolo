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

from mitmproxy import http
from mitmproxy.proxy import commands
from mitmproxy.proxy.layers.http import HttpResponseHeadersHook, HttpStream


def request_may_stream(request: http.Request) -> bool:
    """Select heads that can release body bytes before the request hook."""
    if request.method == "CONNECT":
        # Tunnel admission uses the dedicated http_connect hook.
        return False
    if request.stream:
        return True
    # Chunked HTTP/1 and HTTP/2 bodies can cross the buffering threshold
    # after requestheaders, even when HTTP/2 announces a smaller length.
    if request.is_http2 or request.is_http3:
        return True
    codings = request.headers.get("transfer-encoding", "").lower().split(",")
    return codings[-1].strip() == "chunked"


def deny_request_head(flow: http.HTTPFlow) -> None:
    """Use the pinned early-response path for a local head decision."""
    flow.metadata["request_head_denied"] = True
    flow.request.stream = True
    flow.request.headers.pop("expect", None)


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
