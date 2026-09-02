"""Blackbox tests for network_guard (access control + rate limiting)."""


class TestAccessControl:
    """Allowlisted domains pass through; blocked domains are stopped.

    Why: network_guard is the coarse-grained "what destinations is
    this agent allowed to reach at all" layer. Failure modes here
    are either over-permissive (agent reaches a blocked host, data
    leaks) or under-permissive (legitimate traffic fails, breaks
    real workflows).
    """

    def test_allowed_domain_passes(self, proxy_client, sinkhole, clear_sinkhole, wait_for_services):
        """Allowlisted httpbin.org receives a GET through the proxy.

        What: GET httpbin.org/get through the proxy; assert 200 and
        the sinkhole saw one request.
        Why: Positive-path check — if allowlisted hosts don't actually
        reach their upstream, the agent loses legitimate connectivity
        and users will disable network_guard to get work done.
        """
        response = proxy_client.get("https://httpbin.org/get")

        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        requests = sinkhole.get_requests(host="httpbin.org")
        assert len(requests) == 1, f"Expected 1 request, got {len(requests)}"


class TestResponseRequestId:
    """SafeYolo owns the correlation header returned to the agent.

    Why: An origin-controlled ID can misdirect diagnostics or point to no
    trace at all, breaking the proxy's downstream correlation contract.
    """

    def test_origin_header_is_replaced_and_resolves_to_trace(
        self,
        proxy_client,
        agent_headers,
        clear_sinkhole,
        wait_for_services,
    ):
        """Origin header is replaced by one canonical, traceable request ID.

        What: Send a traced request to a sinkhole route that returns its own
        X-SafeYolo-Request-Id; assert the client sees one different ID and
        that the returned value resolves through the agent-scoped /trace API.
        Why: Without this boundary check, unit tests could pass while the
        loaded proxy still returns an origin-controlled or untraceable ID.
        """
        origin_id = "req-33333333333333333333333333333333"
        response = proxy_client.get(
            "https://httpbin.org/origin-request-id",
            headers={"X-SafeYolo-Trace": "1"},
        )

        assert response.status_code == 200
        returned_ids = response.headers.get_list("X-SafeYolo-Request-Id")
        assert len(returned_ids) == 1
        assert returned_ids[0] != origin_id

        trace = proxy_client.get(
            "http://_safeyolo.proxy.internal/trace",
            params={"request_id": returned_ids[0]},
            headers=agent_headers,
        )
        assert trace.status_code == 200, trace.text
        assert trace.json()["request_id"] == returned_ids[0]


class TestRateLimiting:
    """Per-host request budgets are enforced without spurious denies.

    Why: network_guard caps total request volume to each host to
    contain runaway loops and cost spikes. If the accounting drops
    or double-counts, either budgets block legitimate traffic (false
    positive) or never fire (the cap is meaningless).
    """

    def test_multiple_requests_allowed_within_budget(self, proxy_client, sinkhole, clear_sinkhole, admin_client, wait_for_services):
        """Five requests inside the budget all succeed.

        What: Reset budgets; issue 5 GETs to httpbin.org; assert all
        5 returned 200 and the sinkhole saw 5.
        Why: Confirms the rate limiter isn't tripping on normal
        volumes. A false-positive rate limit at low call counts
        would make the proxy useless for any real workload.
        """
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
    """Proxy-specific headers are consumed, not forwarded upstream.

    Why: `Proxy-Authorization` (RFC 7235) is credentials for the proxy
    itself — not for the origin server. Forwarding it upstream leaks
    the proxy credential to every destination the agent talks to,
    and violates hop-by-hop header semantics.
    """

    def test_proxy_authorization_not_forwarded(self, proxy_client, sinkhole, clear_sinkhole, wait_for_services):
        """Proxy-Authorization header is stripped before reaching upstream.

        What: Send GET with Proxy-Authorization: Basic secret123;
        assert 200, and the sinkhole's received headers do NOT
        contain Proxy-Authorization.
        Why: Hop-by-hop header leak would expose the proxy credential
        to every upstream — a straight credential disclosure bug.
        """
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
