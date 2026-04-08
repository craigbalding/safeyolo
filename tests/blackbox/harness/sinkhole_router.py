"""mitmproxy addon: redirect upstream connections to the test sinkhole.

Loaded ONLY during blackbox tests via the SAFEYOLO_SINKHOLE env var.
Replaces Docker's DNS aliasing — instead of resolving api.openai.com
to the sinkhole container, we rewrite the upstream address after
all security addons have made their policy decisions.

This addon MUST be loaded last in the addon chain so that
credential_guard and network_guard see the original host/URL.

Environment variables:
    SAFEYOLO_SINKHOLE_HTTP_PORT:  Sinkhole HTTP port  (default: 18080)
    SAFEYOLO_SINKHOLE_HTTPS_PORT: Sinkhole HTTPS port (default: 18443)
    SAFEYOLO_SINKHOLE_HOST:       Sinkhole host       (default: 127.0.0.1)
"""

import logging
import os

log = logging.getLogger("safeyolo.sinkhole_router")

SINKHOLE_HOST = os.environ.get("SAFEYOLO_SINKHOLE_HOST", "127.0.0.1")
SINKHOLE_HTTP_PORT = int(os.environ.get("SAFEYOLO_SINKHOLE_HTTP_PORT", "18080"))
SINKHOLE_HTTPS_PORT = int(os.environ.get("SAFEYOLO_SINKHOLE_HTTPS_PORT", "18443"))


class SinkholeRouter:
    """Redirect all upstream connections to the local sinkhole.

    In the request hook (after all security addons have run), rewrites
    flow.request.host and flow.request.port so mitmproxy connects to
    the sinkhole instead of the real upstream.

    The original Host header is preserved by mitmproxy, so the sinkhole
    sees the correct hostname for routing and capture.
    """

    def request(self, flow):
        original_host = flow.request.host
        original_port = flow.request.port

        if flow.request.scheme == "https":
            flow.request.host = SINKHOLE_HOST
            flow.request.port = SINKHOLE_HTTPS_PORT
        else:
            flow.request.host = SINKHOLE_HOST
            flow.request.port = SINKHOLE_HTTP_PORT

        log.debug(
            "Routed %s:%d -> %s:%d",
            original_host, original_port,
            flow.request.host, flow.request.port,
        )


addons = [SinkholeRouter()]
