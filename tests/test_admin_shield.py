"""
Tests for admin_shield.py addon.

Contract:
  C1. Requests to a blocked port on a local host get a 403 response.
  C2. The 403 response is JSON with exact body, Content-Type, and X-Blocked-By headers.
  C3. Blocked flows get metadata: blocked_by="admin-shield", block_reason="admin_port_access".
  C4. Requests to a blocked port on a non-local host pass through (no response set).
  C5. Requests to a non-blocked port on a local host pass through (no response set).
  C6. Allowed flows have no metadata pollution (no blocked_by/block_reason keys).
  C7. _LOCAL_HOSTS contains: localhost, 127.0.0.1, ::1, 0.0.0.0,
      host.docker.internal, safeyolo. Host matching is case-insensitive.
  C8. Any host ending in ".localhost" is treated as local (case-insensitive).
  C9. shield_extra_ports adds additional ports to the block set.
  C10. shield_extra_ports handles whitespace, ignores non-digit entries, handles empty string.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from admin_shield import AdminShield

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_shield(admin_port=9090, extra_ports=""):
    """Create an AdminShield with mocked ctx.options."""
    return AdminShield(), admin_port, extra_ports


def _make_flow(host="127.0.0.1", port=9090):
    """Create a mock flow targeting the given host:port."""
    flow = MagicMock()
    flow.request.host = host
    flow.request.port = port
    flow.client_conn.peername = ("172.30.0.100", 54321)
    flow.metadata = {}
    flow.response = None
    return flow


def _call_request(shield, flow, admin_port=9090, extra_ports=""):
    """Call shield.request(flow) with ctx patched to the given options."""
    with patch("admin_shield.ctx") as mock_ctx:
        mock_ctx.options.admin_port = admin_port
        mock_ctx.options.shield_extra_ports = extra_ports
        shield.request(flow)


# ---------------------------------------------------------------------------
# C1 + C2 + C3: Blocked request — status, headers, body, metadata
# ---------------------------------------------------------------------------

class TestBlockedResponse:
    """A blocked request gets a complete, well-formed 403 response."""

    def test_blocked_request_returns_403(self):
        shield = AdminShield()
        flow = _make_flow(host="127.0.0.1", port=9090)

        _call_request(shield, flow)

        assert flow.response.status_code == 403

    def test_blocked_response_has_x_blocked_by_header(self):
        shield = AdminShield()
        flow = _make_flow(host="localhost", port=9090)

        _call_request(shield, flow)

        assert flow.response.headers["X-Blocked-By"] == "admin-shield"

    def test_blocked_response_has_content_type_json(self):
        shield = AdminShield()
        flow = _make_flow(host="localhost", port=9090)

        _call_request(shield, flow)

        assert flow.response.headers["Content-Type"] == "application/json"

    def test_blocked_response_body_is_exact_json(self):
        shield = AdminShield()
        flow = _make_flow(host="localhost", port=9090)

        _call_request(shield, flow)

        body = json.loads(flow.response.content)
        assert body == {
            "error": "Forbidden",
            "message": "Admin API not accessible through proxy",
        }

    def test_blocked_flow_metadata_blocked_by(self):
        shield = AdminShield()
        flow = _make_flow(host="localhost", port=9090)

        _call_request(shield, flow)

        assert flow.metadata["blocked_by"] == "admin-shield"

    def test_blocked_flow_metadata_block_reason(self):
        shield = AdminShield()
        flow = _make_flow(host="localhost", port=9090)

        _call_request(shield, flow)

        assert flow.metadata["block_reason"] == "admin_port_access"


# ---------------------------------------------------------------------------
# C4 + C5 + C6: Allowed flows — no response, no metadata
# ---------------------------------------------------------------------------

class TestAllowedFlows:
    """Flows that don't match the block criteria pass through untouched."""

    def test_non_blocked_port_passes_through(self):
        shield = AdminShield()
        flow = _make_flow(host="localhost", port=8080)

        _call_request(shield, flow)

        assert flow.response is None

    def test_remote_host_on_admin_port_passes_through(self):
        shield = AdminShield()
        flow = _make_flow(host="172.30.0.10", port=9090)

        _call_request(shield, flow)

        assert flow.response is None

    def test_public_hostname_on_admin_port_passes_through(self):
        shield = AdminShield()
        flow = _make_flow(host="api.example.com", port=9090)

        _call_request(shield, flow)

        assert flow.response is None

    def test_allowed_flow_has_no_blocked_by_metadata(self):
        shield = AdminShield()
        flow = _make_flow(host="172.30.0.10", port=9090)

        _call_request(shield, flow)

        assert "blocked_by" not in flow.metadata

    def test_allowed_flow_has_no_block_reason_metadata(self):
        shield = AdminShield()
        flow = _make_flow(host="172.30.0.10", port=9090)

        _call_request(shield, flow)

        assert "block_reason" not in flow.metadata

    def test_non_local_host_on_non_blocked_port_passes_through(self):
        shield = AdminShield()
        flow = _make_flow(host="api.example.com", port=443)

        _call_request(shield, flow)

        assert flow.response is None


# ---------------------------------------------------------------------------
# C7: Every host in _LOCAL_HOSTS is blocked (parametrized)
# ---------------------------------------------------------------------------

class TestLocalHosts:
    """Every entry in _LOCAL_HOSTS triggers a block on the admin port."""

    @pytest.mark.parametrize("host", [
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "host.docker.internal",
        "safeyolo",
    ])
    def test_local_host_is_blocked(self, host):
        shield = AdminShield()
        flow = _make_flow(host=host, port=9090)

        _call_request(shield, flow)

        assert flow.response.status_code == 403

    @pytest.mark.parametrize("host", [
        "LOCALHOST",
        "Localhost",
        "HOST.DOCKER.INTERNAL",
        "Host.Docker.Internal",
        "SAFEYOLO",
        "SafeYolo",
    ])
    def test_local_host_matching_is_case_insensitive(self, host):
        shield = AdminShield()
        flow = _make_flow(host=host, port=9090)

        _call_request(shield, flow)

        assert flow.response.status_code == 403


# ---------------------------------------------------------------------------
# C8: .localhost suffix matching
# ---------------------------------------------------------------------------

class TestLocalhostSuffix:
    """Hosts ending in .localhost are treated as local."""

    @pytest.mark.parametrize("host", [
        "foo.localhost",
        "admin.safeyolo.localhost",
        "a.b.c.localhost",
    ])
    def test_dot_localhost_suffix_is_blocked(self, host):
        shield = AdminShield()
        flow = _make_flow(host=host, port=9090)

        _call_request(shield, flow)

        assert flow.response.status_code == 403

    def test_dot_localhost_suffix_case_insensitive(self):
        shield = AdminShield()
        flow = _make_flow(host="Admin.SafeYolo.LOCALHOST", port=9090)

        _call_request(shield, flow)

        assert flow.response.status_code == 403

    def test_bare_localhost_is_not_suffix_match(self):
        """'localhost' itself is matched by _LOCAL_HOSTS, not the suffix rule.
        But 'notlocalhost' should NOT match — the suffix check is '.localhost'."""
        shield = AdminShield()
        flow = _make_flow(host="notlocalhost", port=9090)

        _call_request(shield, flow)

        assert flow.response is None


# ---------------------------------------------------------------------------
# C9: shield_extra_ports
# ---------------------------------------------------------------------------

class TestExtraPorts:
    """shield_extra_ports adds ports to the block set."""

    def test_extra_port_is_blocked(self):
        shield = AdminShield()
        flow = _make_flow(host="localhost", port=9091)

        _call_request(shield, flow, extra_ports="9091,9092")

        assert flow.response.status_code == 403

    def test_admin_port_still_blocked_with_extra_ports(self):
        shield = AdminShield()
        flow = _make_flow(host="localhost", port=9090)

        _call_request(shield, flow, extra_ports="9091")

        assert flow.response.status_code == 403

    def test_unlisted_port_allowed_with_extra_ports(self):
        shield = AdminShield()
        flow = _make_flow(host="localhost", port=8080)

        _call_request(shield, flow, extra_ports="9091,9092")

        assert flow.response is None


# ---------------------------------------------------------------------------
# C10: _get_blocked_ports parsing edge cases
# ---------------------------------------------------------------------------

class TestGetBlockedPorts:
    """Port parsing from shield_extra_ports option."""

    def test_default_returns_admin_port_only(self):
        shield = AdminShield()

        with patch("admin_shield.ctx") as mock_ctx:
            mock_ctx.options.admin_port = 9090
            mock_ctx.options.shield_extra_ports = ""

            assert shield._get_blocked_ports() == {9090}

    def test_extra_ports_parsed(self):
        shield = AdminShield()

        with patch("admin_shield.ctx") as mock_ctx:
            mock_ctx.options.admin_port = 9090
            mock_ctx.options.shield_extra_ports = "9091,9092"

            assert shield._get_blocked_ports() == {9090, 9091, 9092}

    def test_whitespace_is_stripped(self):
        shield = AdminShield()

        with patch("admin_shield.ctx") as mock_ctx:
            mock_ctx.options.admin_port = 9090
            mock_ctx.options.shield_extra_ports = " 9091 , 9092 "

            assert shield._get_blocked_ports() == {9090, 9091, 9092}

    def test_non_digit_entries_are_ignored(self):
        shield = AdminShield()

        with patch("admin_shield.ctx") as mock_ctx:
            mock_ctx.options.admin_port = 9090
            mock_ctx.options.shield_extra_ports = "9091,invalid,9092"

            assert shield._get_blocked_ports() == {9090, 9091, 9092}

    def test_negative_number_is_ignored(self):
        """'-1' is not all digits, so isdigit() rejects it."""
        shield = AdminShield()

        with patch("admin_shield.ctx") as mock_ctx:
            mock_ctx.options.admin_port = 9090
            mock_ctx.options.shield_extra_ports = "-1,9091"

            assert shield._get_blocked_ports() == {9090, 9091}

    def test_empty_entries_from_trailing_comma_are_ignored(self):
        shield = AdminShield()

        with patch("admin_shield.ctx") as mock_ctx:
            mock_ctx.options.admin_port = 9090
            mock_ctx.options.shield_extra_ports = "9091,,9092,"

            assert shield._get_blocked_ports() == {9090, 9091, 9092}

    def test_whitespace_only_string_returns_admin_port_only(self):
        shield = AdminShield()

        with patch("admin_shield.ctx") as mock_ctx:
            mock_ctx.options.admin_port = 9090
            mock_ctx.options.shield_extra_ports = "   "

            assert shield._get_blocked_ports() == {9090}

    def test_single_extra_port(self):
        shield = AdminShield()

        with patch("admin_shield.ctx") as mock_ctx:
            mock_ctx.options.admin_port = 9090
            mock_ctx.options.shield_extra_ports = "8443"

            assert shield._get_blocked_ports() == {9090, 8443}


# ---------------------------------------------------------------------------
# Module-level addons list
# ---------------------------------------------------------------------------

class TestModuleExports:
    """The module exports an addons list for mitmproxy to load."""

    def test_addons_list_contains_admin_shield_instance(self):
        from admin_shield import addons

        assert len(addons) == 1
        assert isinstance(addons[0], AdminShield)
