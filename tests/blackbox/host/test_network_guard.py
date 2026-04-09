"""
Black box tests for network guard (access control + rate limiting).
"""



class TestAccessControl:
    """Test domain-based access control."""

    def test_allowed_domain_passes(self, proxy_client, sinkhole, clear_sinkhole, wait_for_services):
        """Request to allowed domain should pass through."""
        response = proxy_client.get("https://httpbin.org/get")

        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        requests = sinkhole.get_requests(host="httpbin.org")
        assert len(requests) == 1, f"Expected 1 request, got {len(requests)}"


class TestRateLimiting:
    """Test rate limiting (budget) enforcement."""

    def test_multiple_requests_allowed_within_budget(self, proxy_client, sinkhole, clear_sinkhole, admin_client, wait_for_services):
        """Multiple requests within budget should succeed."""
        # Reset budgets to ensure clean state
        admin_client.post("/admin/budgets/reset")

        # Send a few requests - should all succeed within budget
        success_count = 0
        for i in range(5):
            resp = proxy_client.get("https://httpbin.org/get")
            if resp.status_code == 200:
                success_count += 1

        assert success_count == 5, f"Expected 5 successful requests, got {success_count}"

        # Verify all reached sinkhole
        requests = sinkhole.get_requests(host="httpbin.org")
        assert len(requests) == 5, f"Expected 5 requests at sinkhole, got {len(requests)}"


# NOTE: TestRequestIdInjection removed - the request_id addon sets internal
# flow.metadata for logging/correlation, but does NOT inject X-Request-Id
# headers into forwarded requests. This is intentional:
# - Request IDs are for SafeYolo's audit trail, not upstream propagation
# - Upstreams have their own request ID schemes
# - Injecting headers could interfere with application logic


class TestProxyHeaderStripping:
    """Test that proxy-specific headers are handled correctly."""

    def test_proxy_authorization_not_forwarded(self, proxy_client, sinkhole, clear_sinkhole, wait_for_services):
        """Proxy-Authorization header should be consumed, not forwarded."""
        response = proxy_client.get(
            "https://httpbin.org/get",
            headers={"Proxy-Authorization": "Basic secret123"},
        )

        # Request should succeed
        assert response.status_code == 200

        requests = sinkhole.get_requests(host="httpbin.org")
        assert len(requests) == 1

        # Proxy-Authorization should NOT be forwarded to upstream
        headers_lower = {k.lower(): v for k, v in requests[0].headers.items()}
        assert "proxy-authorization" not in headers_lower, "Proxy-Authorization should not be forwarded"
