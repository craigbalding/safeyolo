"""mitmproxy addon: redirect test traffic to the local sinkhole.

Loaded ONLY during blackbox tests. Redirects upstream connections for
specific test hostnames to the sinkhole server. All other traffic
passes through to real upstreams normally.

This addon MUST be loaded last in the addon chain so that
credential_guard and network_guard see the original host/URL.

Environment variables:
    SAFEYOLO_SINKHOLE_HTTP_PORT:       Sinkhole HTTP port  (default: 18080)
    SAFEYOLO_SINKHOLE_HTTPS_PORT:      Sinkhole HTTPS port (default: 18443)
    SAFEYOLO_SINKHOLE_ECC_CHAIN_PORT:  HTTPS port for the cross-signed ECC
                                       chain (default: 18444)
    SAFEYOLO_SINKHOLE_HOST:            Sinkhole host       (default: 127.0.0.1)
"""

import logging
import os

log = logging.getLogger("safeyolo.sinkhole_router")

SINKHOLE_HOST = os.environ.get("SAFEYOLO_SINKHOLE_HOST", "127.0.0.1")
SINKHOLE_HTTP_PORT = int(os.environ.get("SAFEYOLO_SINKHOLE_HTTP_PORT", "18080"))
SINKHOLE_HTTPS_PORT = int(os.environ.get("SAFEYOLO_SINKHOLE_HTTPS_PORT", "18443"))
# Dedicated HTTPS port serving an ECC + cross-signed bridge chain that
# mirrors example.com's real-world shape. Used by the upstream-cert-
# validation tests so a chain-shape regression surfaces without having
# to hit the public internet.
SINKHOLE_ECC_CHAIN_PORT = int(
    os.environ.get("SAFEYOLO_SINKHOLE_ECC_CHAIN_PORT", "18444"),
)

# Only redirect these hostnames — must match sinkhole cert SANs.
# All other traffic passes through to real upstreams.
SINKHOLE_HOSTS = {
    "api.openai.com",
    "api.anthropic.com",
    "api.github.com",
    "evil.com",
    "attacker.com",
    "httpbin.org",
    "failing.test",
    "legitimate-api.com",
    "example-chain-test.test",
}

# Hostnames that get their HTTPS traffic steered to a non-default sinkhole
# HTTPS port (different cert chain served on each). Lets the cert-shape
# tests live side-by-side with the default-cert tests without breaking them.
SINKHOLE_HOST_HTTPS_PORTS = {
    "example-chain-test.test": SINKHOLE_ECC_CHAIN_PORT,
}


class SinkholeRouter:
    """Redirect test hostnames to the local sinkhole.

    In the request hook (after all security addons have run), rewrites
    flow.request.host and flow.request.port for test hostnames only.
    Non-test traffic (mise downloads, npm, etc.) passes through normally.
    """

    def request(self, flow):
        original_host = flow.request.host

        if original_host not in SINKHOLE_HOSTS:
            return

        original_port = flow.request.port

        if flow.request.scheme == "https":
            flow.request.host = SINKHOLE_HOST
            flow.request.port = SINKHOLE_HOST_HTTPS_PORTS.get(
                original_host, SINKHOLE_HTTPS_PORT,
            )
        else:
            flow.request.host = SINKHOLE_HOST
            flow.request.port = SINKHOLE_HTTP_PORT

        # Preserve the original Host header so the sinkhole can identify
        # which test hostname was requested. Setting flow.request.host
        # changes both the connection target AND the Host header —
        # we only want to change the connection target.
        flow.request.host_header = original_host

        log.debug(
            "Routed %s:%d -> %s:%d (Host: %s)",
            original_host, original_port,
            flow.request.host, flow.request.port,
            original_host,
        )


addons = [SinkholeRouter()]
