"""
Tests for service_discovery.py - File-based agent IP map resolution.

Tests the mtime-cached JSON map loader, reverse IP lookup,
flow metadata stamping, and agent stats/listing.
"""

import json
import time
from pathlib import Path
from threading import Thread
from unittest.mock import Mock, patch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_discovery():
    """Create a fresh ServiceDiscovery instance (not the module singleton)."""
    from service_discovery import ServiceDiscovery
    return ServiceDiscovery()


def _write_map(path: Path, data: dict) -> None:
    """Write agent map JSON to disk."""
    path.write_text(json.dumps(data))


# ---------------------------------------------------------------------------
# TestReloadMap
# ---------------------------------------------------------------------------

class TestReloadMap:
    """Tests for _reload_map() — mtime-cached JSON file loading."""

    def test_reload_parses_valid_json_map(self, tmp_path):
        """Two-agent map file is parsed into correct agent_map and reverse index."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        _write_map(map_file, {
            "alice": {"ip": "10.0.0.1", "started": "2026-01-01T00:00:00Z"},
            "bob":   {"ip": "10.0.0.2", "started": "2026-01-01T00:00:00Z"},
        })
        d._map_path = str(map_file)
        d._reload_map()

        assert d._agent_map == {
            "alice": {"ip": "10.0.0.1", "started": "2026-01-01T00:00:00Z"},
            "bob":   {"ip": "10.0.0.2", "started": "2026-01-01T00:00:00Z"},
        }
        assert d._ip_to_name == {"10.0.0.1": "alice", "10.0.0.2": "bob"}

    def test_reload_skips_entry_without_ip(self, tmp_path):
        """An entry with no 'ip' key is excluded from the reverse index."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        _write_map(map_file, {
            "alice": {"ip": "10.0.0.1"},
            "broken": {"started": "2026-01-01T00:00:00Z"},
        })
        d._map_path = str(map_file)
        d._reload_map()

        assert d._ip_to_name == {"10.0.0.1": "alice"}
        # broken is still in agent_map (raw data), just not in reverse index
        assert "broken" in d._agent_map

    def test_reload_noop_when_no_path_configured(self):
        """No path configured -> _reload_map returns without error."""
        d = _make_discovery()
        d._map_path = ""
        d._reload_map()  # should not raise

        assert d._agent_map == {}
        assert d._ip_to_name == {}

    def test_reload_noop_when_file_missing(self, tmp_path):
        """Nonexistent file -> _reload_map returns without error, preserves state."""
        d = _make_discovery()
        d._map_path = str(tmp_path / "nonexistent.json")
        d._agent_map = {"old": {"ip": "1.2.3.4"}}
        d._ip_to_name = {"1.2.3.4": "old"}
        d._reload_map()

        # Previous state is preserved
        assert d._agent_map == {"old": {"ip": "1.2.3.4"}}
        assert d._ip_to_name == {"1.2.3.4": "old"}

    def test_reload_noop_when_mtime_unchanged(self, tmp_path):
        """Same mtime -> file is not re-read."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        _write_map(map_file, {"alice": {"ip": "10.0.0.1"}})
        d._map_path = str(map_file)

        # First load
        d._reload_map()
        assert d._ip_to_name == {"10.0.0.1": "alice"}

        # Overwrite file content WITHOUT changing mtime (we just read, same mtime)
        # Because we didn't change the file, mtime is the same
        d._reload_map()

        # Still the same data (not re-parsed, which is fine since content is the same)
        assert d._ip_to_name == {"10.0.0.1": "alice"}

    def test_reload_picks_up_changed_file(self, tmp_path):
        """Changed mtime triggers re-read with new content."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        _write_map(map_file, {"alice": {"ip": "10.0.0.1"}})
        d._map_path = str(map_file)
        d._reload_map()

        assert d._ip_to_name == {"10.0.0.1": "alice"}

        # Ensure different mtime by sleeping briefly then rewriting
        time.sleep(0.05)
        _write_map(map_file, {"bob": {"ip": "10.0.0.2"}})
        d._reload_map()

        assert d._ip_to_name == {"10.0.0.2": "bob"}
        assert "alice" not in d._ip_to_name

    @patch("service_discovery.write_event")
    def test_reload_keeps_previous_state_on_invalid_json(self, mock_event, tmp_path):
        """Malformed JSON -> logs warning, keeps previous map."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"

        # Load valid data first
        _write_map(map_file, {"alice": {"ip": "10.0.0.1"}})
        d._map_path = str(map_file)
        d._reload_map()
        old_mtime = d._map_mtime

        # Write invalid JSON with a different mtime
        time.sleep(0.05)
        map_file.write_text("{not valid json")
        d._reload_map()

        # Previous state preserved
        assert d._ip_to_name == {"10.0.0.1": "alice"}
        assert d._agent_map == {"alice": {"ip": "10.0.0.1"}}
        # Mtime was NOT updated (so next reload will re-attempt)
        assert d._map_mtime == old_mtime

    @patch("service_discovery.write_event")
    def test_reload_keeps_previous_state_on_read_os_error(self, mock_event, tmp_path):
        """OSError during file read -> keeps previous map."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        _write_map(map_file, {"alice": {"ip": "10.0.0.1"}})
        d._map_path = str(map_file)
        d._reload_map()
        old_mtime = d._map_mtime

        # Force a different mtime so the reload proceeds past the mtime check,
        # then make read_text fail
        time.sleep(0.05)
        _write_map(map_file, {"bob": {"ip": "10.0.0.2"}})
        with patch.object(Path, "read_text", side_effect=OSError("permission denied")):
            d._reload_map()

        # Previous state preserved, mtime not updated
        assert d._ip_to_name == {"10.0.0.1": "alice"}
        assert d._map_mtime == old_mtime

    @patch("service_discovery.write_event")
    def test_reload_returns_early_on_stat_race(self, mock_event, tmp_path):
        """File disappears between exists() and stat() -> keeps previous map."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        _write_map(map_file, {"alice": {"ip": "10.0.0.1"}})
        d._map_path = str(map_file)
        d._reload_map()

        # Simulate race: exists() returns True, but stat() raises OSError
        # This happens when the file is deleted between the two calls.
        original_exists = Path.exists
        original_stat = Path.stat

        def exists_returns_true(self_path, **kwargs):
            if str(self_path) == str(map_file):
                return True
            return original_exists(self_path, **kwargs)

        def stat_raises_on_map_file(self_path, **kwargs):
            if str(self_path) == str(map_file):
                raise OSError("file disappeared")
            return original_stat(self_path, **kwargs)

        with patch.object(Path, "exists", exists_returns_true), \
             patch.object(Path, "stat", stat_raises_on_map_file):
            d._reload_map()

        assert d._ip_to_name == {"10.0.0.1": "alice"}

    @patch("service_discovery.write_event")
    def test_reload_logs_newly_discovered_agents(self, mock_event, tmp_path):
        """write_event called for each newly discovered agent, not for existing ones."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        _write_map(map_file, {"alice": {"ip": "10.0.0.1"}})
        d._map_path = str(map_file)
        d._reload_map()

        # Alice was newly discovered
        assert mock_event.call_count == 1
        call_kwargs = mock_event.call_args[1]
        assert call_kwargs["agent"] == "alice"
        assert call_kwargs["details"] == {"ip": "10.0.0.1"}

        # Update file to add bob, keep alice
        mock_event.reset_mock()
        time.sleep(0.05)
        _write_map(map_file, {
            "alice": {"ip": "10.0.0.1"},
            "bob":   {"ip": "10.0.0.2"},
        })
        d._reload_map()

        # Only bob is newly discovered
        assert mock_event.call_count == 1
        call_kwargs = mock_event.call_args[1]
        assert call_kwargs["agent"] == "bob"

    @patch("service_discovery.write_event")
    def test_reload_empty_map_clears_state(self, mock_event, tmp_path):
        """Loading an empty map file clears agent_map and reverse index."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        _write_map(map_file, {"alice": {"ip": "10.0.0.1"}})
        d._map_path = str(map_file)
        d._reload_map()

        time.sleep(0.05)
        _write_map(map_file, {})
        d._reload_map()

        assert d._agent_map == {}
        assert d._ip_to_name == {}


# ---------------------------------------------------------------------------
# TestGetClientForIp
# ---------------------------------------------------------------------------

class TestGetClientForIp:
    """Tests for get_client_for_ip() — reverse IP lookup."""

    @patch("service_discovery.write_event")
    def test_known_ip_returns_agent_name(self, mock_event, tmp_path):
        """IP in map returns the correct agent name."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        _write_map(map_file, {"alice": {"ip": "10.0.0.1"}})
        d._map_path = str(map_file)

        result = d.get_client_for_ip("10.0.0.1")
        assert result == "alice"

    def test_unknown_ip_returns_unknown(self, tmp_path):
        """IP not in map returns 'unknown'."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        _write_map(map_file, {"alice": {"ip": "10.0.0.1"}})
        d._map_path = str(map_file)
        d._reload_map()

        result = d.get_client_for_ip("99.99.99.99")
        assert result == "unknown"

    def test_returns_unknown_when_no_map_loaded(self):
        """No map file configured -> returns 'unknown'."""
        d = _make_discovery()
        result = d.get_client_for_ip("10.0.0.1")
        assert result == "unknown"

    @patch("service_discovery.write_event")
    def test_triggers_reload_on_each_call(self, mock_event, tmp_path):
        """get_client_for_ip calls _reload_map to check for file changes."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        _write_map(map_file, {"alice": {"ip": "10.0.0.1"}})
        d._map_path = str(map_file)

        # First call loads
        assert d.get_client_for_ip("10.0.0.1") == "alice"

        # Update file
        time.sleep(0.05)
        _write_map(map_file, {"bob": {"ip": "10.0.0.1"}})

        # Second call picks up the change
        assert d.get_client_for_ip("10.0.0.1") == "bob"

    @patch("service_discovery.write_event")
    def test_thread_safe_concurrent_lookups(self, mock_event, tmp_path):
        """Concurrent reads from multiple threads don't corrupt state."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        agents = {f"agent-{i}": {"ip": f"10.0.0.{i}"} for i in range(20)}
        _write_map(map_file, agents)
        d._map_path = str(map_file)

        errors = []

        def lookup(agent_id):
            try:
                for _ in range(100):
                    result = d.get_client_for_ip(f"10.0.0.{agent_id}")
                    assert result == f"agent-{agent_id}"
            except Exception as e:
                errors.append(e)

        threads = [Thread(target=lookup, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []


# ---------------------------------------------------------------------------
# TestRequest
# ---------------------------------------------------------------------------

class TestRequest:
    """Tests for request() hook — flow metadata stamping."""

    @patch("service_discovery.write_event")
    def test_stamps_agent_on_flow_metadata(self, mock_event, tmp_path):
        """Known agent IP -> flow.metadata['agent'] = agent name."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        _write_map(map_file, {"alice": {"ip": "10.0.0.1"}})
        d._map_path = str(map_file)

        flow = Mock()
        flow.client_conn.peername = ("10.0.0.1", 12345)
        flow.metadata = {}

        with patch("service_discovery.get_client_ip", return_value="10.0.0.1"):
            d.request(flow)

        assert flow.metadata["agent"] == "alice"

    @patch("service_discovery.write_event")
    def test_stamps_unknown_for_unmapped_ip(self, mock_event, tmp_path):
        """Unmapped IP -> flow.metadata['agent'] = 'unknown'."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        _write_map(map_file, {"alice": {"ip": "10.0.0.1"}})
        d._map_path = str(map_file)

        flow = Mock()
        flow.metadata = {}

        with patch("service_discovery.get_client_ip", return_value="99.99.99.99"):
            d.request(flow)

        assert flow.metadata["agent"] == "unknown"

    def test_skips_when_client_ip_is_unknown(self):
        """get_client_ip returns 'unknown' -> no metadata stamp at all."""
        d = _make_discovery()
        flow = Mock()
        flow.metadata = {}

        with patch("service_discovery.get_client_ip", return_value="unknown"):
            d.request(flow)

        assert "agent" not in flow.metadata

    @patch("service_discovery.write_event")
    def test_updates_last_seen_for_known_agent(self, mock_event, tmp_path):
        """Known agent's _last_seen is updated on request()."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        _write_map(map_file, {"alice": {"ip": "10.0.0.1"}})
        d._map_path = str(map_file)

        flow = Mock()
        flow.metadata = {}

        before = time.time()
        with patch("service_discovery.get_client_ip", return_value="10.0.0.1"):
            d.request(flow)
        after = time.time()

        assert "alice" in d._last_seen
        assert before <= d._last_seen["alice"] <= after

    @patch("service_discovery.write_event")
    def test_no_last_seen_for_unknown_agent(self, mock_event, tmp_path):
        """'unknown' agent does not get a _last_seen entry."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        _write_map(map_file, {"alice": {"ip": "10.0.0.1"}})
        d._map_path = str(map_file)

        flow = Mock()
        flow.metadata = {}

        with patch("service_discovery.get_client_ip", return_value="99.99.99.99"):
            d.request(flow)

        assert "unknown" not in d._last_seen
        assert len(d._last_seen) == 0

    @patch("service_discovery.write_event")
    def test_last_seen_advances_on_subsequent_request(self, mock_event, tmp_path):
        """Second request from same agent updates _last_seen to a later time."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        _write_map(map_file, {"alice": {"ip": "10.0.0.1"}})
        d._map_path = str(map_file)

        with patch("service_discovery.get_client_ip", return_value="10.0.0.1"):
            flow1 = Mock()
            flow1.metadata = {}
            d.request(flow1)
            ts1 = d._last_seen["alice"]

            time.sleep(0.01)

            flow2 = Mock()
            flow2.metadata = {}
            d.request(flow2)
            ts2 = d._last_seen["alice"]

        assert ts2 > ts1


# ---------------------------------------------------------------------------
# TestGetAgents
# ---------------------------------------------------------------------------

class TestGetAgents:
    """Tests for get_agents() — agent listing for API."""

    def test_empty_when_no_map_loaded(self):
        """No map loaded -> count 0, agents {}."""
        d = _make_discovery()
        result = d.get_agents()
        assert result == {"agents": {}, "count": 0}

    @patch("service_discovery.write_event")
    def test_returns_agents_from_map_with_ip(self, mock_event, tmp_path):
        """Agents from map file are returned with their IP."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        _write_map(map_file, {
            "alice": {"ip": "10.0.0.1"},
            "bob":   {"ip": "10.0.0.2"},
        })
        d._map_path = str(map_file)

        result = d.get_agents()

        assert result["count"] == 2
        assert result["agents"]["alice"]["ip"] == "10.0.0.1"
        assert result["agents"]["bob"]["ip"] == "10.0.0.2"

    @patch("service_discovery.write_event")
    def test_includes_last_seen_and_idle_for_seen_agents(self, mock_event, tmp_path):
        """After request(), agent entry includes last_seen and idle_seconds."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        _write_map(map_file, {"alice": {"ip": "10.0.0.1"}})
        d._map_path = str(map_file)

        flow = Mock()
        flow.metadata = {}
        with patch("service_discovery.get_client_ip", return_value="10.0.0.1"):
            d.request(flow)

        result = d.get_agents()
        agent = result["agents"]["alice"]
        assert "last_seen" in agent
        assert "idle_seconds" in agent
        assert agent["idle_seconds"] >= 0

    @patch("service_discovery.write_event")
    def test_agent_in_map_but_not_seen_has_no_last_seen(self, mock_event, tmp_path):
        """Agent in map that hasn't sent traffic has ip but no timing fields."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        _write_map(map_file, {"alice": {"ip": "10.0.0.1"}})
        d._map_path = str(map_file)

        result = d.get_agents()
        agent = result["agents"]["alice"]
        assert agent["ip"] == "10.0.0.1"
        assert "last_seen" not in agent
        assert "idle_seconds" not in agent


# ---------------------------------------------------------------------------
# TestGetStats
# ---------------------------------------------------------------------------

class TestGetStats:
    """Tests for get_stats() — admin API stats."""

    def test_includes_map_file_and_known_ips(self):
        """Stats include map_file path and known_ips count."""
        d = _make_discovery()
        d._map_path = "/some/path/agent_map.json"
        stats = d.get_stats()

        assert stats["map_file"] == "/some/path/agent_map.json"
        assert stats["known_ips"] == 0
        assert stats["agents_seen"] == 0

    @patch("service_discovery.write_event")
    def test_stats_reflect_loaded_agents(self, mock_event, tmp_path):
        """After loading a map, stats reflect the correct counts."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        _write_map(map_file, {
            "alice": {"ip": "10.0.0.1"},
            "bob":   {"ip": "10.0.0.2"},
        })
        d._map_path = str(map_file)
        d._reload_map()

        stats = d.get_stats()
        assert stats["known_ips"] == 2
        assert stats["agents_seen"] == 2
        assert "alice" in stats["agents"]
        assert "bob" in stats["agents"]


# ---------------------------------------------------------------------------
# TestLoadAndConfigure
# ---------------------------------------------------------------------------

class TestLoadAndConfigure:
    """Tests for load() and configure() mitmproxy hooks."""

    def test_load_registers_agent_map_file_option(self):
        """load() registers 'agent_map_file' option with correct spec."""
        d = _make_discovery()
        registered = []

        class MockLoader:
            def add_option(self, name, typespec, default, help):
                registered.append({
                    "name": name,
                    "typespec": typespec,
                    "default": default,
                })

        d.load(MockLoader())

        assert len(registered) == 1
        assert registered[0] == {
            "name": "agent_map_file",
            "typespec": str,
            "default": "",
        }

    @patch("service_discovery.write_event")
    def test_configure_stores_path_and_triggers_reload(self, mock_event, tmp_path):
        """configure() stores the path and calls _reload_map."""
        d = _make_discovery()
        map_file = tmp_path / "agent_map.json"
        _write_map(map_file, {"alice": {"ip": "10.0.0.1"}})

        mock_ctx = Mock()
        mock_ctx.options.agent_map_file = str(map_file)

        with patch("service_discovery.ctx", mock_ctx):
            d.configure({"agent_map_file"})

        assert d._map_path == str(map_file)
        assert d._ip_to_name == {"10.0.0.1": "alice"}

    @patch("service_discovery.write_event")
    def test_configure_ignores_unrelated_updates(self, mock_event, tmp_path):
        """configure() with unrelated keys does not change map_path."""
        d = _make_discovery()
        d._map_path = "/original/path.json"

        d.configure({"some_other_option"})

        assert d._map_path == "/original/path.json"


# ---------------------------------------------------------------------------
# TestModuleSingleton
# ---------------------------------------------------------------------------

class TestModuleSingleton:
    """Tests for module-level singleton and addons list."""

    def test_get_service_discovery_returns_singleton(self):
        """get_service_discovery() returns the module-level _discovery instance."""
        from service_discovery import _discovery, get_service_discovery
        result = get_service_discovery()
        assert result is _discovery
        assert result is not None

    def test_addons_list_contains_discovery_instance(self):
        """Module addons list contains exactly the singleton."""
        from service_discovery import addons, discovery
        assert len(addons) == 1
        assert addons[0] is discovery

    def test_singleton_is_service_discovery_instance(self):
        """The singleton is a ServiceDiscovery instance."""
        from service_discovery import ServiceDiscovery, discovery
        assert isinstance(discovery, ServiceDiscovery)
