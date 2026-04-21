"""Host-side upstream TLS certificate validation tests.

Exercises SafeYolo's `_merge_system_cas_into_certifi` + mitmproxy's
upstream TLS chain builder against a non-trivial cert chain shape.

Background (why this suite exists):
    The real-world example.com leaf is served by Cloudflare with a
    chain that terminates at an SSL.com 2022 ECC root, optionally
    cross-signed by Comodo AAA as a bridge for older trust stores.
    SafeYolo has regressed upstream validation of that exact shape
    twice -- the fix each time was in the CA-bundle merge, but the
    symptom was "example.com returns 000 / hangs / verify failed".

Ground-truth, internet-free: the sinkhole stands up a second HTTPS
endpoint on port 18444 presenting an equivalent synthetic chain
(ECC leaf + ECC intermediate + cross-signed bridge root), generated
by certs/generate-certs.sh. If SafeYolo's bundle merge breaks or
the chain builder regresses, the test below turns red.

Adding new cert-shape cases: generate another chain in
generate-certs.sh, add a `--extra-cert` entry in run-tests.sh, add
a hostname + port mapping to harness/sinkhole_router.py, and drop a
test class here that curls through the proxy to that hostname.
"""

import pytest


class TestEccCrossSignedChain:
    """Upstream validation of an ECC leaf whose chain reaches the
    trusted root via a cross-signed bridge.

    Why: Mirrors example.com's shape. If certifi's bundle lacks a root
    the merge was supposed to supply, or the chain builder fails to
    traverse the bridge cert, validation drops and the curl hangs
    (the failure surfaces as time-out or 502 from mitmproxy).
    """

    def test_chain_validates_end_to_end(
        self, proxy_client, sinkhole, clear_sinkhole, wait_for_services,
    ):
        """GET https://example-chain-test.test/ through the proxy returns 200.

        What: Route through SafeYolo's mitmproxy to the sinkhole's
        port-18444 HTTPS endpoint. The sinkhole presents the chain
        [ECC leaf, ECC intermediate, test-ca-b cross-signed by
        test-ca]. mitmproxy validates it against the merged bundle,
        accepts, MITMs, and forwards to us.
        Why: A green 200 confirms the chain-shape regression that
        has bitten us twice is not currently present. A red (timeout,
        502, or TLS verify error from mitmproxy) means something in
        `_merge_system_cas_into_certifi` or the upstream TLS context
        is broken.
        """
        response = proxy_client.get(
            "https://example-chain-test.test/",
            follow_redirects=False,
        )
        assert response.status_code == 200, (
            f"Expected 200 (sinkhole default), got {response.status_code}. "
            f"mitmproxy probably failed upstream chain validation -- check "
            f"~/.safeyolo-test/logs/mitmproxy.log for 'verify' / 'chain' errors."
        )

        # Confirm the sinkhole actually received it (guards against a
        # false positive where mitmproxy itself returned a non-upstream
        # response without forwarding).
        requests = sinkhole.get_requests(host="example-chain-test.test")
        assert len(requests) >= 1, (
            f"Sinkhole saw no requests for example-chain-test.test. "
            f"mitmproxy returned 200 without forwarding?"
        )
