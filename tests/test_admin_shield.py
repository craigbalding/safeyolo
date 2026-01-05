"""
Tests for admin_shield.py addon.

Tests that the admin API port is blocked from proxy access.
"""

import pytest
from unittest.mock import MagicMock, patch


class TestAdminShield:
    """Tests for AdminShield addon."""

    @pytest.fixture
    def shield(self):
        """Create AdminShield instance with mocked ctx."""
        with patch("admin_shield.ctx") as mock_ctx:
            mock_ctx.options.admin_port = 9090
            mock_ctx.options.shield_extra_ports = ""

            from admin_shield import AdminShield
            return AdminShield()

    @pytest.fixture
    def mock_flow(self):
        """Create mock HTTP flow."""
        flow = MagicMock()
        flow.request.host = "172.30.0.10"
        flow.request.port = 9090
        flow.client_conn.peername = ("172.30.0.100", 54321)
        flow.metadata = {}
        flow.response = None  # Not blocked initially
        return flow

    def test_blocks_admin_port(self, shield, mock_flow):
        """Test that requests to admin port are blocked."""
        with patch("admin_shield.ctx") as mock_ctx:
            mock_ctx.options.admin_port = 9090
            mock_ctx.options.shield_extra_ports = ""

            shield.request(mock_flow)

            # Should have set a 403 response
            assert mock_flow.response is not None
            assert mock_flow.response.status_code == 403
            assert mock_flow.metadata["blocked_by"] == "admin-shield"

    def test_allows_other_ports(self, shield, mock_flow):
        """Test that requests to other ports are allowed."""
        mock_flow.request.port = 8080  # Different port

        with patch("admin_shield.ctx") as mock_ctx:
            mock_ctx.options.admin_port = 9090
            mock_ctx.options.shield_extra_ports = ""

            shield.request(mock_flow)

            # Should NOT have set a response
            assert mock_flow.response is None

    def test_blocks_extra_ports(self, shield, mock_flow):
        """Test that extra configured ports are also blocked."""
        mock_flow.request.port = 9091

        with patch("admin_shield.ctx") as mock_ctx:
            mock_ctx.options.admin_port = 9090
            mock_ctx.options.shield_extra_ports = "9091, 9092"

            shield.request(mock_flow)

            assert mock_flow.response is not None
            assert mock_flow.response.status_code == 403

    def test_blocks_localhost_admin(self, shield, mock_flow):
        """Test blocking admin port on localhost."""
        mock_flow.request.host = "localhost"
        mock_flow.request.port = 9090

        with patch("admin_shield.ctx") as mock_ctx:
            mock_ctx.options.admin_port = 9090
            mock_ctx.options.shield_extra_ports = ""

            shield.request(mock_flow)

            assert mock_flow.response is not None
            assert mock_flow.response.status_code == 403

    def test_blocks_127_0_0_1_admin(self, shield, mock_flow):
        """Test blocking admin port on 127.0.0.1."""
        mock_flow.request.host = "127.0.0.1"
        mock_flow.request.port = 9090

        with patch("admin_shield.ctx") as mock_ctx:
            mock_ctx.options.admin_port = 9090
            mock_ctx.options.shield_extra_ports = ""

            shield.request(mock_flow)

            assert mock_flow.response is not None
            assert mock_flow.response.status_code == 403

    def test_response_is_json(self, shield, mock_flow):
        """Test that blocked response is valid JSON."""
        import json

        with patch("admin_shield.ctx") as mock_ctx:
            mock_ctx.options.admin_port = 9090
            mock_ctx.options.shield_extra_ports = ""

            shield.request(mock_flow)

            # Parse the response body
            body = mock_flow.response.content
            data = json.loads(body)

            assert "error" in data
            assert data["error"] == "Forbidden"
            assert "message" in data


class TestGetBlockedPorts:
    """Tests for _get_blocked_ports helper."""

    def test_default_port_only(self):
        """Test with no extra ports configured."""
        with patch("admin_shield.ctx") as mock_ctx:
            mock_ctx.options.admin_port = 9090
            mock_ctx.options.shield_extra_ports = ""

            from admin_shield import AdminShield
            shield = AdminShield()

            ports = shield._get_blocked_ports()
            assert ports == {9090}

    def test_with_extra_ports(self):
        """Test with extra ports configured."""
        with patch("admin_shield.ctx") as mock_ctx:
            mock_ctx.options.admin_port = 9090
            mock_ctx.options.shield_extra_ports = "9091,9092"

            from admin_shield import AdminShield
            shield = AdminShield()

            ports = shield._get_blocked_ports()
            assert ports == {9090, 9091, 9092}

    def test_handles_whitespace(self):
        """Test that whitespace in extra ports is handled."""
        with patch("admin_shield.ctx") as mock_ctx:
            mock_ctx.options.admin_port = 9090
            mock_ctx.options.shield_extra_ports = " 9091 , 9092 "

            from admin_shield import AdminShield
            shield = AdminShield()

            ports = shield._get_blocked_ports()
            assert ports == {9090, 9091, 9092}

    def test_ignores_invalid_ports(self):
        """Test that invalid port strings are ignored."""
        with patch("admin_shield.ctx") as mock_ctx:
            mock_ctx.options.admin_port = 9090
            mock_ctx.options.shield_extra_ports = "9091,invalid,9092"

            from admin_shield import AdminShield
            shield = AdminShield()

            ports = shield._get_blocked_ports()
            assert ports == {9090, 9091, 9092}
