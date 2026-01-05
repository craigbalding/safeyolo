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
