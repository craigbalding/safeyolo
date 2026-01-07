"""
Tests for the request_id addon.

The request_id addon runs first in the addon chain and assigns a unique
request_id to every request for event correlation.
"""

import re
import time

import pytest
from mitmproxy.test import tflow


class TestRequestIdGenerator:
    """Tests for RequestIdGenerator addon."""

    @pytest.fixture
    def addon(self):
        """Create a fresh RequestIdGenerator instance."""
        from request_id import RequestIdGenerator
        return RequestIdGenerator()

    def test_request_id_assigned(self, addon):
        """Request ID is assigned to flow.metadata."""
        flow = tflow.tflow()
        assert "request_id" not in flow.metadata

        addon.request(flow)

        assert "request_id" in flow.metadata
        assert flow.metadata["request_id"] is not None

    def test_request_id_format(self, addon):
        """Request ID follows expected format: req-{12 hex chars}."""
        flow = tflow.tflow()
        addon.request(flow)

        request_id = flow.metadata["request_id"]
        # Format: req-{12 hex characters from uuid4}
        assert request_id.startswith("req-")
        hex_part = request_id[4:]
        assert len(hex_part) == 12
        assert re.match(r'^[0-9a-f]+$', hex_part), f"Not hex: {hex_part}"

    def test_start_time_assigned(self, addon):
        """start_time is assigned to flow.metadata."""
        flow = tflow.tflow()
        before = time.time()

        addon.request(flow)

        after = time.time()
        start_time = flow.metadata.get("start_time")
        assert start_time is not None
        assert before <= start_time <= after

    def test_unique_request_ids(self, addon):
        """Each request gets a unique ID."""
        flows = [tflow.tflow() for _ in range(100)]

        for flow in flows:
            addon.request(flow)

        ids = [f.metadata["request_id"] for f in flows]
        assert len(ids) == len(set(ids)), "Duplicate request IDs found"

    def test_does_not_overwrite_existing(self, addon):
        """If request_id already exists, it should still work."""
        flow = tflow.tflow()
        # Pre-set a request_id (shouldn't happen in practice, but test robustness)
        flow.metadata["request_id"] = "req-existing123"

        addon.request(flow)

        # The addon overwrites - this is by design since it runs first
        assert flow.metadata["request_id"] != "req-existing123"

    def test_addon_name(self, addon):
        """Addon has correct name attribute."""
        assert addon.name == "request-id"


class TestHopByHopHeaderStripping:
    """Tests for hop-by-hop header stripping (RFC 7230 Section 6.1)."""

    @pytest.fixture
    def addon(self):
        """Create a fresh RequestIdGenerator instance."""
        from request_id import RequestIdGenerator
        return RequestIdGenerator()

    def test_proxy_authorization_stripped(self, addon):
        """Proxy-Authorization header must be stripped (security)."""
        flow = tflow.tflow()
        flow.request.headers["Proxy-Authorization"] = "Basic secret123"
        flow.request.headers["Authorization"] = "Bearer keep-this"

        addon.request(flow)

        assert "Proxy-Authorization" not in flow.request.headers
        assert "proxy-authorization" not in flow.request.headers
        # Regular Authorization should be preserved
        assert flow.request.headers.get("Authorization") == "Bearer keep-this"

    def test_all_hop_by_hop_headers_stripped(self, addon):
        """All RFC 7230 hop-by-hop headers must be stripped."""
        flow = tflow.tflow()
        # Add all hop-by-hop headers
        flow.request.headers["Connection"] = "keep-alive"
        flow.request.headers["Keep-Alive"] = "timeout=5"
        flow.request.headers["Proxy-Authenticate"] = "Basic"
        flow.request.headers["Proxy-Authorization"] = "Basic secret"
        flow.request.headers["TE"] = "trailers"
        flow.request.headers["Trailer"] = "Expires"
        flow.request.headers["Transfer-Encoding"] = "chunked"
        flow.request.headers["Upgrade"] = "websocket"
        # Also add a regular header that should be preserved
        flow.request.headers["X-Custom"] = "keep-me"

        addon.request(flow)

        # All hop-by-hop headers should be gone
        for header in ["Connection", "Keep-Alive", "Proxy-Authenticate",
                       "Proxy-Authorization", "TE", "Trailer",
                       "Transfer-Encoding", "Upgrade"]:
            assert header not in flow.request.headers, f"{header} should be stripped"

        # Regular headers preserved
        assert flow.request.headers.get("X-Custom") == "keep-me"

    def test_connection_header_specified_headers_stripped(self, addon):
        """Headers listed in Connection header should also be stripped."""
        flow = tflow.tflow()
        # Connection header can list additional hop-by-hop headers
        flow.request.headers["Connection"] = "X-Custom-Hop, close"
        flow.request.headers["X-Custom-Hop"] = "should-be-stripped"
        flow.request.headers["X-Regular"] = "keep-me"

        addon.request(flow)

        # Connection itself and headers it lists should be stripped
        assert "Connection" not in flow.request.headers
        assert "X-Custom-Hop" not in flow.request.headers
        # Regular headers preserved
        assert flow.request.headers.get("X-Regular") == "keep-me"

    def test_case_insensitive_stripping(self, addon):
        """Header stripping should be case-insensitive."""
        flow = tflow.tflow()
        flow.request.headers["PROXY-AUTHORIZATION"] = "Basic secret"
        flow.request.headers["proxy-authorization"] = "Basic secret2"

        addon.request(flow)

        # Both case variants should be stripped
        headers_lower = {k.lower() for k in flow.request.headers.keys()}
        assert "proxy-authorization" not in headers_lower


class TestRequestIdIntegration:
    """Integration tests for request_id with other addons."""

    def test_request_id_available_for_credential_guard(self):
        """Request ID is available when credential_guard runs."""
        from credential_guard import CredentialGuard
        from request_id import RequestIdGenerator

        rid = RequestIdGenerator()
        _ = CredentialGuard()  # Verify it can be instantiated

        flow = tflow.tflow()
        flow.request.headers["Authorization"] = "Bearer sk-test123"

        # Simulate addon chain order
        rid.request(flow)

        # Verify request_id is set before credential_guard runs
        assert "request_id" in flow.metadata

        # Now credential_guard can use it
        request_id = flow.metadata["request_id"]
        assert request_id.startswith("req-")

    def test_request_id_available_for_network_guard(self):
        """Request ID is available when network_guard runs."""
        from network_guard import NetworkGuard
        from request_id import RequestIdGenerator

        rid = RequestIdGenerator()
        _ = NetworkGuard()  # Verify it can be instantiated

        flow = tflow.tflow()
        rid.request(flow)

        assert "request_id" in flow.metadata
        # Network guard can now log with request_id correlation
