"""
Tests for service_discovery.py - IP to project mapping.

Tests static service registry for project isolation.
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch


class TestServiceEntry:
    """Tests for ServiceEntry dataclass."""

    def test_creates_entry_with_ip(self):
        """Test creating entry with exact IP."""
        from addons.service_discovery import ServiceEntry

        entry = ServiceEntry(name="my-service", project="my-project", ip="10.0.0.5")
        assert entry.name == "my-service"
        assert entry.project == "my-project"
        assert entry.ip == "10.0.0.5"
        assert entry.ip_range is None

    def test_creates_entry_with_range(self):
        """Test creating entry with IP range."""
        from addons.service_discovery import ServiceEntry

        entry = ServiceEntry(
            name="services", project="multi-project", ip_range="10.0.0.0/24"
        )
        assert entry.name == "services"
        assert entry.project == "multi-project"
        assert entry.ip is None
        assert entry.ip_range == "10.0.0.0/24"


class TestServiceDiscovery:
    """Tests for ServiceDiscovery addon."""

    def test_addon_name(self):
        """Test addon has correct name."""
        from addons.service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()
        assert discovery.name == "service-discovery"

    def test_default_project_when_no_config(self):
        """Test returns 'default' project when no config."""
        from addons.service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()
        project = discovery.get_project_for_ip("192.168.1.100")
        assert project == "default"


class TestServiceDiscoveryLoading:
    """Tests for config loading."""

    def test_loads_exact_ip_mapping(self):
        """Test loading exact IP mappings from config."""
        from addons.service_discovery import ServiceDiscovery

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "services.yaml"
            config_path.write_text("""
services:
  claude-agent:
    project: my-project
    ip: 10.0.0.5
  other-agent:
    project: other-project
    ip: 10.0.0.10
""")

            discovery = ServiceDiscovery()
            discovery._config_path = config_path

            # Simulate loading via internal method
            with patch.object(discovery, '_find_config', return_value=config_path):
                discovery._load_config()

            assert discovery.get_project_for_ip("10.0.0.5") == "my-project"
            assert discovery.get_project_for_ip("10.0.0.10") == "other-project"
            assert discovery.get_project_for_ip("10.0.0.99") == "default"

    def test_loads_ip_range_mapping(self):
        """Test loading IP range mappings from config."""
        from addons.service_discovery import ServiceDiscovery

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "services.yaml"
            config_path.write_text("""
services:
  dev-agents:
    project: development
    ip_range: 10.0.1.0/24
  prod-agents:
    project: production
    ip_range: 10.0.2.0/24
""")

            discovery = ServiceDiscovery()

            with patch.object(discovery, '_find_config', return_value=config_path):
                discovery._load_config()

            assert discovery.get_project_for_ip("10.0.1.50") == "development"
            assert discovery.get_project_for_ip("10.0.1.255") == "development"
            assert discovery.get_project_for_ip("10.0.2.1") == "production"
            assert discovery.get_project_for_ip("10.0.3.1") == "default"

    def test_exact_ip_takes_precedence(self):
        """Test exact IP match takes precedence over range."""
        from addons.service_discovery import ServiceDiscovery

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "services.yaml"
            config_path.write_text("""
services:
  special-agent:
    project: special
    ip: 10.0.1.5
  dev-agents:
    project: development
    ip_range: 10.0.1.0/24
""")

            discovery = ServiceDiscovery()

            with patch.object(discovery, '_find_config', return_value=config_path):
                discovery._load_config()

            # Exact IP should match special, not the range
            assert discovery.get_project_for_ip("10.0.1.5") == "special"
            # Other IPs in range should match development
            assert discovery.get_project_for_ip("10.0.1.10") == "development"

    def test_handles_missing_config(self):
        """Test graceful handling of missing config file."""
        from addons.service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        with patch.object(discovery, '_find_config', return_value=None):
            discovery._load_config()

        # Should work but return default for everything
        assert discovery.get_project_for_ip("10.0.0.5") == "default"

    def test_handles_invalid_ip_range(self):
        """Test handling of invalid IP range in config."""
        from addons.service_discovery import ServiceDiscovery

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "services.yaml"
            config_path.write_text("""
services:
  good-service:
    project: valid
    ip: 10.0.0.5
  bad-service:
    project: invalid
    ip_range: not-a-valid-range
""")

            discovery = ServiceDiscovery()

            with patch.object(discovery, '_find_config', return_value=config_path):
                # Should not raise, just log warning
                discovery._load_config()

            # Valid service should work
            assert discovery.get_project_for_ip("10.0.0.5") == "valid"

    def test_handles_invalid_client_ip(self):
        """Test handling of invalid client IP."""
        from addons.service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()
        # Should not raise, just return default
        project = discovery.get_project_for_ip("not-an-ip")
        assert project == "default"


class TestServiceDiscoveryStats:
    """Tests for stats tracking."""

    def test_get_stats_returns_dict(self):
        """Test get_stats returns proper structure."""
        from addons.service_discovery import ServiceDiscovery

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "services.yaml"
            config_path.write_text("""
services:
  my-service:
    project: my-project
    ip: 10.0.0.5
  my-range:
    project: range-project
    ip_range: 10.0.1.0/24
""")

            discovery = ServiceDiscovery()
            discovery._config_path = config_path

            with patch.object(discovery, '_find_config', return_value=config_path):
                discovery._load_config()

            stats = discovery.get_stats()

            assert stats["services_count"] == 2
            assert stats["ip_mappings"] == 1
            assert stats["range_mappings"] == 1
            assert "services" in stats
            assert "my-service" in stats["services"]


class TestServiceDiscoveryReload:
    """Tests for config reload."""

    def test_reload_clears_and_reloads(self):
        """Test reload clears existing data and reloads."""
        from addons.service_discovery import ServiceDiscovery

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "services.yaml"
            config_path.write_text("""
services:
  old-service:
    project: old
    ip: 10.0.0.5
""")

            discovery = ServiceDiscovery()

            with patch.object(discovery, '_find_config', return_value=config_path):
                discovery._load_config()

            assert discovery.get_project_for_ip("10.0.0.5") == "old"

            # Update config
            config_path.write_text("""
services:
  new-service:
    project: new
    ip: 10.0.0.10
""")

            with patch.object(discovery, '_find_config', return_value=config_path):
                discovery.reload()

            # Old mapping should be gone
            assert discovery.get_project_for_ip("10.0.0.5") == "default"
            # New mapping should work
            assert discovery.get_project_for_ip("10.0.0.10") == "new"


class TestGetServiceDiscovery:
    """Tests for global accessor."""

    def test_get_service_discovery_returns_instance(self):
        """Test get_service_discovery returns the global instance."""
        from addons.service_discovery import get_service_discovery, _discovery

        result = get_service_discovery()
        assert result is _discovery
