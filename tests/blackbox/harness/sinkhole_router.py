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

Per-chain HTTPS ports (each serves a different cert chain for the
upstream-cert-validation test suite):
    18444 ECC cross-signed bridge (example-chain-test.test)
    18445 RSA 4-deep chain        (rsa-deep-chain.test)
    18446 Name-constrained inter. (nc-constrained.test)
    18447 Extra unrelated inter.  (extra-intermediates.test)
    18448 Expired leaf            (expired-leaf.test)     [MUST fail]
    18449 Hostname/SAN mismatch   (wrong-san.test)        [MUST fail]
    18450 Self-signed leaf        (self-signed.test)      [MUST fail]
    18451 AIA-only (leaf alone)   (aia-only.test)         [MUST fail]
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
# Additional chain-shape ports. Each port serves a different chain from
# tests/blackbox/certs/generate-certs.sh and is targeted by a dedicated
# test class in tests/blackbox/host/proxy/test_upstream_cert_validation.py.
SINKHOLE_RSA_DEEP_PORT = int(os.environ.get("SAFEYOLO_SINKHOLE_RSA_DEEP_PORT", "18445"))
SINKHOLE_NC_PORT = int(os.environ.get("SAFEYOLO_SINKHOLE_NC_PORT", "18446"))
SINKHOLE_EXTRA_INTS_PORT = int(os.environ.get("SAFEYOLO_SINKHOLE_EXTRA_INTS_PORT", "18447"))
SINKHOLE_EXPIRED_PORT = int(os.environ.get("SAFEYOLO_SINKHOLE_EXPIRED_PORT", "18448"))
SINKHOLE_WRONG_SAN_PORT = int(os.environ.get("SAFEYOLO_SINKHOLE_WRONG_SAN_PORT", "18449"))
SINKHOLE_SELF_SIGNED_PORT = int(
    os.environ.get("SAFEYOLO_SINKHOLE_SELF_SIGNED_PORT", "18450"),
)
SINKHOLE_AIA_PORT = int(os.environ.get("SAFEYOLO_SINKHOLE_AIA_PORT", "18451"))

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
    "rsa-deep-chain.test",
    "nc-constrained.test",
    "extra-intermediates.test",
    "expired-leaf.test",
    "wrong-san.test",
    "self-signed.test",
    "aia-only.test",
}

# Hostnames that get their HTTPS traffic steered to a non-default sinkhole
# HTTPS port (different cert chain served on each). Lets the cert-shape
# tests live side-by-side with the default-cert tests without breaking them.
SINKHOLE_HOST_HTTPS_PORTS = {
    "example-chain-test.test": SINKHOLE_ECC_CHAIN_PORT,
    "rsa-deep-chain.test": SINKHOLE_RSA_DEEP_PORT,
    "nc-constrained.test": SINKHOLE_NC_PORT,
    "extra-intermediates.test": SINKHOLE_EXTRA_INTS_PORT,
    "expired-leaf.test": SINKHOLE_EXPIRED_PORT,
    "wrong-san.test": SINKHOLE_WRONG_SAN_PORT,
    "self-signed.test": SINKHOLE_SELF_SIGNED_PORT,
    "aia-only.test": SINKHOLE_AIA_PORT,
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
