"""
Tests for service_discovery.py - IP to project mapping with hot reload.

Tests dynamic service registry for project isolation.
"""

import tempfile
import time
from pathlib import Path
from threading import Thread
from unittest.mock import patch


class TestServiceEntry:
    """Tests for ServiceEntry dataclass."""

    def test_creates_entry_with_ip(self):
        """Test creating entry with exact IP."""
        from service_discovery import ServiceEntry

        entry = ServiceEntry(name="my-service", project="my-project", ip="10.0.0.5")
        assert entry.name == "my-service"
        assert entry.project == "my-project"
        assert entry.ip == "10.0.0.5"
        assert entry.ip_range is None

    def test_creates_entry_with_range(self):
        """Test creating entry with IP range."""
        from service_discovery import ServiceEntry

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
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()
        assert discovery.name == "service-discovery"

    def test_unknown_project_when_no_config(self):
        """Test returns 'unknown' project when no config."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()
        project = discovery.get_project_for_ip("192.168.1.100")
        assert project == "unknown"


class TestServiceDiscoveryOptions:
    """Tests for mitmproxy option registration."""

    def test_load_registers_options(self):
        """Test load() registers expected mitmproxy options."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()
        registered_options = []

        # Mock loader that captures option registrations
        class MockLoader:
            def add_option(self, name, typespec, default, help):
                registered_options.append({
                    "name": name,
                    "typespec": typespec,
                    "default": default,
                })

        discovery.load(MockLoader())

        option_names = [opt["name"] for opt in registered_options]
        assert "discovery_network" in option_names
        assert "discovery_watch" in option_names
        assert "discovery_watch_interval" in option_names

        # Verify defaults
        watch_opt = next(o for o in registered_options if o["name"] == "discovery_watch")
        assert watch_opt["default"] is True
        assert watch_opt["typespec"] is bool

        interval_opt = next(o for o in registered_options if o["name"] == "discovery_watch_interval")
        assert interval_opt["default"] == 5
        assert interval_opt["typespec"] is int


class TestServiceDiscoveryLoading:
    """Tests for config loading."""

    def test_loads_exact_ip_mapping(self):
        """Test loading exact IP mappings from config."""
        from service_discovery import ServiceDiscovery

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
            assert discovery.get_project_for_ip("10.0.0.99") == "unknown"

    def test_loads_ip_range_mapping(self):
        """Test loading IP range mappings from config."""
        from service_discovery import ServiceDiscovery

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
            assert discovery.get_project_for_ip("10.0.3.1") == "unknown"

    def test_exact_ip_takes_precedence(self):
        """Test exact IP match takes precedence over range."""
        from service_discovery import ServiceDiscovery

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
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        with patch.object(discovery, '_find_config', return_value=None):
            discovery._load_config()

        # Should work but return unknown for everything
        assert discovery.get_project_for_ip("10.0.0.5") == "unknown"

    def test_handles_invalid_ip_range(self):
        """Test handling of invalid IP range in config."""
        from service_discovery import ServiceDiscovery

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
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()
        # Should not raise, just return unknown
        project = discovery.get_project_for_ip("not-an-ip")
        assert project == "unknown"


class TestServiceDiscoveryStats:
    """Tests for stats tracking."""

    def test_get_stats_returns_dict(self):
        """Test get_stats returns proper structure."""
        from service_discovery import ServiceDiscovery

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

    def test_get_stats_includes_watch_status(self):
        """Test stats include watching status and interval."""
        from service_discovery import DEFAULT_WATCH_INTERVAL_SECONDS, ServiceDiscovery

        discovery = ServiceDiscovery()
        stats = discovery.get_stats()

        # Before starting watcher
        assert "watching" in stats
        assert stats["watching"] is False
        assert "watch_interval" in stats
        assert stats["watch_interval"] == DEFAULT_WATCH_INTERVAL_SECONDS

    def test_get_stats_shows_watching_true_when_active(self):
        """Test stats show watching=True when watcher is running."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()
        discovery._watch_interval = 1
        discovery._start_watching()

        try:
            stats = discovery.get_stats()
            assert stats["watching"] is True
        finally:
            discovery._stop_watching = True
            discovery._watch_thread.join(timeout=2)


class TestServiceDiscoveryReload:
    """Tests for config reload."""

    def test_reload_clears_and_reloads(self):
        """Test reload clears existing data and reloads."""
        from service_discovery import ServiceDiscovery

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
            assert discovery.get_project_for_ip("10.0.0.5") == "unknown"
            # New mapping should work
            assert discovery.get_project_for_ip("10.0.0.10") == "new"


class TestServiceDiscoveryStaleDetection:
    """Tests for stale file detection."""

    def test_detects_stale_marker(self):
        """Test that stale marker clears mappings."""
        from service_discovery import ServiceDiscovery

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "services.yaml"
            config_path.write_text("""# SafeYolo stopped - services.yaml is stale
services:
  old-service:
    project: old
    ip: 10.0.0.5
""")

            discovery = ServiceDiscovery()

            with patch.object(discovery, '_find_config', return_value=config_path):
                discovery._load_config()

            # Stale file should result in no mappings
            assert discovery.get_project_for_ip("10.0.0.5") == "unknown"
            assert discovery.get_stats()["services_count"] == 0


class TestServiceDiscoveryFileWatching:
    """Tests for file watching functionality."""

    def test_check_file_changed_detects_modification(self):
        """Test _check_file_changed detects when file is modified."""
        from service_discovery import ServiceDiscovery

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "services.yaml"
            config_path.write_text("services: {}")

            discovery = ServiceDiscovery()
            discovery._config_path = config_path
            discovery._file_mtime = config_path.stat().st_mtime

            # Initially no change
            assert discovery._check_file_changed() is False

            # Modify file
            time.sleep(0.1)  # Ensure mtime difference
            config_path.write_text("services:\n  new: {ip: 10.0.0.1}")

            # Now should detect change
            assert discovery._check_file_changed() is True

    def test_check_file_changed_handles_deleted_file(self):
        """Test _check_file_changed handles deleted config file."""
        from service_discovery import ServiceDiscovery

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "services.yaml"
            config_path.write_text("services:\n  test: {ip: 10.0.0.1}")

            discovery = ServiceDiscovery()
            discovery._config_path = config_path

            with patch.object(discovery, '_find_config', return_value=config_path):
                discovery._load_config()

            assert discovery.get_stats()["services_count"] == 1

            # Delete file
            config_path.unlink()

            # Check should handle missing file and clear mappings
            discovery._check_file_changed()

            # Services should be cleared
            assert discovery.get_stats()["services_count"] == 0

    def test_check_file_changed_handles_stat_oserror(self):
        """Test _check_file_changed catches OSError during stat (e.g., permission denied)."""
        from service_discovery import ServiceDiscovery

        # Fake path that passes exists() but fails stat()
        class PathThatFailsStat:
            def exists(self):
                return True
            def stat(self):
                raise OSError("Permission denied")

        discovery = ServiceDiscovery()
        discovery._config_path = PathThatFailsStat()

        # Should catch OSError and return False (not raise)
        result = discovery._check_file_changed()
        assert result is False

    def test_start_watching_creates_thread(self):
        """Test _start_watching creates and starts a daemon thread."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()
        discovery._watch_interval = 1

        assert discovery._watch_thread is None

        discovery._start_watching()

        assert discovery._watch_thread is not None
        assert discovery._watch_thread.is_alive()
        assert discovery._watch_thread.daemon is True
        assert discovery._watch_thread.name == "discovery-watcher"

        # Cleanup
        discovery._stop_watching = True
        discovery._watch_thread.join(timeout=2)

    def test_done_stops_watch_thread(self):
        """Test done() signals thread to stop and joins it."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()
        discovery._watch_interval = 1
        discovery._start_watching()

        assert discovery._watch_thread.is_alive()

        # Call done() to cleanup - this joins the thread internally
        discovery.done()

        assert discovery._stop_watching is True
        # Thread should have stopped - join again with timeout to verify
        discovery._watch_thread.join(timeout=3)
        assert not discovery._watch_thread.is_alive()


class TestServiceDiscoveryUnknownIPs:
    """Tests for unknown IP tracking."""

    def test_logs_unknown_ip_once(self):
        """Test unknown IPs are only logged once."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        # First lookup should add to unknown set
        discovery.get_project_for_ip("192.168.1.100")
        assert "192.168.1.100" in discovery._unknown_ips

        # Same IP shouldn't be re-added (set behavior)
        initial_count = len(discovery._unknown_ips)
        discovery.get_project_for_ip("192.168.1.100")
        assert len(discovery._unknown_ips) == initial_count

    def test_unknown_ips_in_stats(self):
        """Test unknown IPs are included in stats."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()
        discovery.get_project_for_ip("192.168.1.100")
        discovery.get_project_for_ip("192.168.1.101")

        stats = discovery.get_stats()
        assert stats["unknown_ips_count"] == 2
        assert "192.168.1.100" in stats["unknown_ips"]

    def test_unknown_ips_capped(self):
        """Test unknown IPs set is capped to prevent memory growth."""
        from service_discovery import MAX_UNKNOWN_IPS_TRACKED, ServiceDiscovery

        discovery = ServiceDiscovery()

        # Add more than the cap
        for i in range(MAX_UNKNOWN_IPS_TRACKED + 100):
            discovery.get_project_for_ip(f"10.0.{i // 256}.{i % 256}")

        # Should be capped
        assert len(discovery._unknown_ips) <= MAX_UNKNOWN_IPS_TRACKED


class TestServiceDiscoveryThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_reads_during_reload(self):
        """Test that reads are safe during config reload."""
        from service_discovery import ServiceDiscovery

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "services.yaml"
            config_path.write_text("""
services:
  agent-1:
    project: project-1
    ip: 10.0.0.1
""")

            discovery = ServiceDiscovery()

            with patch.object(discovery, '_find_config', return_value=config_path):
                discovery._load_config()

            results = []
            errors = []

            def reader():
                try:
                    for _ in range(100):
                        project = discovery.get_project_for_ip("10.0.0.1")
                        results.append(project)
                except Exception as e:
                    errors.append(e)

            def writer():
                try:
                    for i in range(10):
                        config_path.write_text(f"""
services:
  agent-{i}:
    project: project-{i}
    ip: 10.0.0.1
""")
                        with patch.object(discovery, '_find_config', return_value=config_path):
                            discovery._load_config()
                except Exception as e:
                    errors.append(e)

            # Start concurrent threads
            threads = [Thread(target=reader) for _ in range(5)]
            threads.append(Thread(target=writer))

            for t in threads:
                t.start()
            for t in threads:
                t.join()

            # No errors should occur
            assert len(errors) == 0
            # All results should be valid project names
            assert all(r.startswith("project-") or r == "unknown" for r in results)

    def test_concurrent_unknown_ip_tracking(self):
        """Test that concurrent unknown IP lookups respect the cap strictly.

        The race condition we're protecting against:
        - Thread A: checks len < MAX, passes
        - Thread B: checks len < MAX, passes (before A adds)
        - Both threads add, potentially exceeding MAX

        Without the lock, this could slightly exceed MAX_UNKNOWN_IPS_TRACKED.
        With the lock, we should never exceed it.
        """
        from service_discovery import MAX_UNKNOWN_IPS_TRACKED, ServiceDiscovery

        discovery = ServiceDiscovery()
        errors = []

        def lookup_unknown_ips(thread_id: int):
            try:
                for i in range(200):
                    # Each thread uses different IPs to maximize contention
                    discovery.get_project_for_ip(f"10.{thread_id}.{i // 256}.{i % 256}")
            except Exception as e:
                errors.append(e)

        # Flood with more unique IPs than the cap allows
        # 10 threads * 200 IPs = 2000 unique IPs, but cap is 1000
        threads = [Thread(target=lookup_unknown_ips, args=(t,)) for t in range(10)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # No exceptions
        assert len(errors) == 0

        # Strict bound - must be exactly at cap, not over
        # (Without lock, race could allow 1000+ entries)
        assert len(discovery._unknown_ips) == MAX_UNKNOWN_IPS_TRACKED

        # All entries should be valid IP strings
        for ip in discovery._unknown_ips:
            assert ip.startswith("10."), f"Invalid IP in set: {ip}"


class TestGetServiceDiscovery:
    """Tests for global accessor."""

    def test_get_service_discovery_returns_instance(self):
        """Test get_service_discovery returns the global instance."""
        from service_discovery import _discovery, get_service_discovery

        result = get_service_discovery()
        assert result is _discovery


class TestCanonicalPath:
    """Tests for canonical config path."""

    def test_find_config_returns_canonical_path(self):
        """Test _find_config returns only the canonical path."""
        from service_discovery import ServiceDiscovery

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create file at non-canonical location
            wrong_path = Path(tmpdir) / "wrong" / "services.yaml"
            wrong_path.parent.mkdir(parents=True)
            wrong_path.write_text("services: {}")

            discovery = ServiceDiscovery()

            # Should not find file at wrong location
            result = discovery._find_config()

            # Result should be None (canonical path /app/data/services.yaml won't exist in test)
            assert result is None

    def test_uses_canonical_path_when_exists(self):
        """Test uses /app/data/services.yaml when it exists."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        # Mock the canonical path existing
        with patch('pathlib.Path.exists', return_value=True):
            result = discovery._find_config()
            assert result == Path("/app/data/services.yaml")
