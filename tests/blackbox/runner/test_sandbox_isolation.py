"""
Black box tests for Sandbox Mode network isolation.

Verifies that containers on internal-only networks cannot bypass the proxy.
This is THE critical security guarantee of Sandbox Mode.

The isolation-verifier container runs on the internal-only network and tests:
1. Direct internet access (should fail - no default gateway)
2. External DNS resolution (should fail - no DNS server reachable)
3. Proxy connectivity on internal network (should succeed)

Results are written to /security-results/isolation.json.

NOTE: These tests only run when using the security overlay:
  docker compose -f docker-compose.yml -f docker-compose.security.yml up
"""

import json
from pathlib import Path

import pytest

# Path to isolation test results (mounted from isolation-verifier container)
ISOLATION_RESULTS_PATH = Path("/security-results/isolation.json")


@pytest.fixture(scope="module")
def isolation_results():
    """Load network isolation test JSON results."""
    if not ISOLATION_RESULTS_PATH.exists():
        pytest.skip(
            "Isolation results not found - run with security overlay: "
            "docker compose -f docker-compose.yml -f docker-compose.security.yml up"
        )

    content = ISOLATION_RESULTS_PATH.read_text()
    return json.loads(content)


class TestNetworkIsolation:
    """Verify Sandbox Mode network isolation guarantees."""

    def test_direct_http_blocked(self, isolation_results):
        """Direct HTTP to external IPs must be blocked.

        Containers on the internal network should not have a default gateway,
        so direct HTTP connections to external IPs like 1.1.1.1 should fail.
        """
        assert isolation_results["direct_http_blocked"], (
            "SECURITY FAILURE: Direct HTTP to external IP succeeded! "
            "Agent containers can bypass the proxy via direct connections."
        )

    def test_direct_https_blocked(self, isolation_results):
        """Direct HTTPS to external IPs must be blocked.

        Same as HTTP - no route to external networks should exist.
        """
        assert isolation_results["direct_https_blocked"], (
            "SECURITY FAILURE: Direct HTTPS to external IP succeeded! "
            "Agent containers can bypass the proxy via direct connections."
        )

    def test_dns_blocked(self, isolation_results):
        """External DNS resolution must be blocked.

        Containers should not be able to resolve DNS via external servers
        like 8.8.8.8, as this would be a DNS leak.
        """
        assert isolation_results["dns_blocked"], (
            "SECURITY FAILURE: DNS resolution via external server succeeded! "
            "Agent containers have DNS leak - can exfiltrate data via DNS."
        )

    def test_proxy_reachable(self, isolation_results):
        """Proxy must be reachable on the internal network.

        The whole point of the internal network is that containers can
        reach the proxy but nothing else.
        """
        assert isolation_results["proxy_reachable"], (
            "Proxy not reachable on internal network! "
            "Check that safeyolo is correctly added to isolation-net."
        )

    def test_all_isolation_checks_passed(self, isolation_results):
        """Overall network isolation must be properly configured."""
        assert isolation_results["all_passed"], (
            "SECURITY FAILURE: Network isolation is incomplete. "
            "Review individual test failures for details."
        )
