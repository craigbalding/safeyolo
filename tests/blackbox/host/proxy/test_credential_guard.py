"""Retained uncredentialed host control pending its native replacement review.

Provider destination/header and approval-body observations now live in the
independently verified native gateway-scope and guard-approval contracts.
"""


class TestCredentialRouting:
    """An uncredentialed allowed request reaches its owned origin."""


    def test_no_credentials_passes_through(self, proxy_client, sinkhole, clear_sinkhole, wait_for_services):
        """Requests without credentials are not blocked by credential_guard.

        What: GET httpbin.org/get with no Authorization headers;
        assert 200 and sinkhole saw the request.
        Why: credential_guard only triggers on credential presence.
        A broken implementation that blocks any request to a
        non-allowlisted host would be network_guard's job, not this
        addon's — confirm the boundaries are respected.
        """
        response = proxy_client.get("https://httpbin.org/get")

        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        requests = sinkhole.get_requests(host="httpbin.org")
        assert len(requests) == 1, f"Expected 1 request, got {len(requests)}"
