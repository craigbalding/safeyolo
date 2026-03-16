"""
Tests for service_discovery.py - DNS-based IP to client mapping.

Tests automatic service discovery via Docker's embedded DNS.
"""

import socket
import time
from threading import Thread
from unittest.mock import Mock, patch


class TestServiceDiscovery:
    """Tests for ServiceDiscovery addon."""

    def test_addon_name(self):
        """Test addon has correct name."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()
        assert discovery.name == "service-discovery"

    def test_unknown_client_when_no_dns(self):
        """Test returns 'unknown' when DNS can't resolve."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns:
            mock_dns.side_effect = socket.herror("Host not found")
            client = discovery.get_client_for_ip("192.168.1.100")

        assert client == "unknown"


class TestServiceDiscoveryOptions:
    """Tests for mitmproxy option registration."""

    def test_load_registers_options(self):
        """Test load() registers expected mitmproxy options."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()
        registered_options = []

        class MockLoader:
            def add_option(self, name, typespec, default, help):
                registered_options.append({"name": name})

        discovery.load(MockLoader())

        option_names = [opt["name"] for opt in registered_options]
        assert "discovery_network" in option_names


class TestServiceDiscoveryDNS:
    """Tests for reverse DNS discovery."""

    def test_dns_resolves_unknown_ip(self):
        """Test reverse DNS resolves an unknown IP to a client name."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns, \
             patch("service_discovery.write_event"):
            mock_dns.return_value = ("boris.safeyolo_internal", [], ["172.20.0.5"])
            client = discovery.get_client_for_ip("172.20.0.5")

        assert client == "boris"

    def test_dns_strips_network_suffix(self):
        """Test network suffix is stripped from DNS result."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()
        discovery.network = "my_custom_network"

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns, \
             patch("service_discovery.write_event"):
            mock_dns.return_value = ("agent.my_custom_network", [], ["10.0.0.5"])
            client = discovery.get_client_for_ip("10.0.0.5")

        assert client == "agent"

    def test_dns_result_is_cached(self):
        """Test DNS result is cached and not re-queried on subsequent calls."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns, \
             patch("service_discovery.write_event"):
            mock_dns.return_value = ("boris.safeyolo_internal", [], ["172.20.0.5"])

            discovery.get_client_for_ip("172.20.0.5")
            discovery.get_client_for_ip("172.20.0.5")
            discovery.get_client_for_ip("172.20.0.5")

            assert mock_dns.call_count == 1

    def test_dns_cache_expires(self):
        """Test DNS cache entry expires after TTL."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns, \
             patch("service_discovery.write_event"):
            mock_dns.return_value = ("boris.safeyolo_internal", [], ["172.20.0.5"])

            discovery.get_client_for_ip("172.20.0.5")
            assert mock_dns.call_count == 1

            # Expire the cache entry
            with discovery._lock:
                ip, (name, _) = next(iter(discovery._dns_cache.items()))
                discovery._dns_cache[ip] = (name, time.time() - 1)

            discovery.get_client_for_ip("172.20.0.5")
            assert mock_dns.call_count == 2

    def test_dns_failure_returns_unknown(self):
        """Test DNS failure falls through to 'unknown'."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns:
            mock_dns.side_effect = socket.herror("Host not found")
            client = discovery.get_client_for_ip("172.20.0.99")

        assert client == "unknown"

    def test_dns_negative_cache_prevents_repeated_lookups(self):
        """Test failed DNS lookups are cached to avoid hammering DNS."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns:
            mock_dns.side_effect = socket.herror("Host not found")

            discovery.get_client_for_ip("172.20.0.99")
            discovery.get_client_for_ip("172.20.0.99")
            discovery.get_client_for_ip("172.20.0.99")

            assert mock_dns.call_count == 1

    def test_dns_negative_cache_expires(self):
        """Test negative cache entry expires and allows retry."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns:
            mock_dns.side_effect = socket.herror("Host not found")
            discovery.get_client_for_ip("172.20.0.99")
            assert mock_dns.call_count == 1

            # Expire the negative cache entry
            with discovery._lock:
                discovery._dns_negative_cache["172.20.0.99"] = time.time() - 1

            discovery.get_client_for_ip("172.20.0.99")
            assert mock_dns.call_count == 2

    def test_dns_skips_proxy_container(self):
        """Test DNS resolution skips the 'safeyolo' proxy container."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns:
            mock_dns.return_value = ("safeyolo.safeyolo_internal", [], ["172.20.0.2"])
            client = discovery.get_client_for_ip("172.20.0.2")

        assert client == "unknown"

    def test_dns_handles_hostname_without_suffix(self):
        """Test DNS works when hostname has no network suffix."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns, \
             patch("service_discovery.write_event"):
            mock_dns.return_value = ("boris", [], ["172.20.0.5"])
            client = discovery.get_client_for_ip("172.20.0.5")

        assert client == "boris"

    def test_dns_cache_evicts_expired_at_capacity(self):
        """Test DNS cache evicts expired entries when reaching max size."""
        from service_discovery import DNS_CACHE_MAX_SIZE, ServiceDiscovery

        discovery = ServiceDiscovery()

        # Fill cache to capacity with expired entries
        expired = time.time() - 1
        with discovery._lock:
            for i in range(DNS_CACHE_MAX_SIZE):
                discovery._dns_cache[f"10.0.{i // 256}.{i % 256}"] = (f"agent-{i}", expired)

        # New lookup should succeed (expired entries evicted)
        with patch("service_discovery.socket.gethostbyaddr") as mock_dns, \
             patch("service_discovery.write_event"):
            mock_dns.return_value = ("new-agent.safeyolo_internal", [], ["172.20.0.99"])
            client = discovery.get_client_for_ip("172.20.0.99")

        assert client == "new-agent"
        assert len(discovery._dns_cache) == 1


class TestServiceDiscoveryStats:
    """Tests for stats tracking."""

    def test_get_stats_returns_dict(self):
        """Test get_stats returns proper structure."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()
        stats = discovery.get_stats()

        assert "dns_cache_size" in stats
        assert "dns_cached_clients" in stats
        assert "dns_negative_cache_size" in stats
        assert "unresolved_ips_count" in stats
        assert "agents_seen" in stats
        assert "agents" in stats

    def test_dns_stats_populated_after_lookup(self):
        """Test get_stats includes DNS cache information after lookups."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns, \
             patch("service_discovery.write_event"):
            mock_dns.return_value = ("boris.safeyolo_internal", [], ["172.20.0.5"])
            discovery.get_client_for_ip("172.20.0.5")

        stats = discovery.get_stats()
        assert stats["dns_cache_size"] == 1
        assert "172.20.0.5" in stats["dns_cached_clients"]
        assert stats["dns_cached_clients"]["172.20.0.5"] == "boris"

    def test_stats_include_agents_after_request(self):
        """Test get_stats includes agent details after request() flows."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        flow = Mock()
        flow.client_conn.peername = ("172.20.0.5", 12345)
        flow.metadata = {}

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns, \
             patch("service_discovery.write_event"):
            mock_dns.return_value = ("boris.safeyolo_internal", [], ["172.20.0.5"])
            discovery.request(flow)

        stats = discovery.get_stats()
        assert stats["agents_seen"] == 1
        assert "boris" in stats["agents"]
        assert stats["agents"]["boris"]["ip"] == "172.20.0.5"
        assert "last_seen" in stats["agents"]["boris"]
        assert "idle_seconds" in stats["agents"]["boris"]


class TestServiceDiscoveryThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_dns_lookups(self):
        """Test concurrent DNS lookups are thread-safe."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()
        errors = []

        def dns_side_effect(ip):
            """Deterministic mock: derive hostname from IP."""
            parts = ip.split(".")
            thread_id, i = parts[2], parts[3]
            return (f"agent-{thread_id}-{i}.safeyolo_internal", [], [ip])

        def lookup(thread_id):
            try:
                for i in range(50):
                    ip = f"172.20.{thread_id}.{i}"
                    client = discovery.get_client_for_ip(ip)
                    assert client == f"agent-{thread_id}-{i}"
            except Exception as e:
                errors.append(e)

        # Patch once outside threads to avoid mock races
        with patch("service_discovery.socket.gethostbyaddr", side_effect=dns_side_effect), \
             patch("service_discovery.write_event"):
            threads = [Thread(target=lookup, args=(t,)) for t in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        assert len(errors) == 0


class TestServiceDiscoveryRequestHook:
    """Tests for the request() hook that stamps flow.metadata['agent']."""

    def test_request_stamps_agent_on_flow(self):
        """Test request() stamps agent name on flow metadata."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        flow = Mock()
        flow.client_conn.peername = ("172.20.0.5", 12345)
        flow.metadata = {}

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns, \
             patch("service_discovery.write_event"):
            mock_dns.return_value = ("boris.safeyolo_internal", [], ["172.20.0.5"])
            discovery.request(flow)

        assert flow.metadata["agent"] == "boris"

    def test_request_skips_unknown_client_ip(self):
        """Test request() does not stamp agent when client IP is unknown."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        flow = Mock()
        flow.client_conn.peername = None
        flow.metadata = {}

        discovery.request(flow)

        assert "agent" not in flow.metadata

    def test_request_uses_cached_agent(self):
        """Test request() uses cached DNS result (no extra lookups)."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns, \
             patch("service_discovery.write_event"):
            mock_dns.return_value = ("boris.safeyolo_internal", [], ["172.20.0.5"])

            flow1 = Mock()
            flow1.client_conn.peername = ("172.20.0.5", 12345)
            flow1.metadata = {}
            discovery.request(flow1)

            flow2 = Mock()
            flow2.client_conn.peername = ("172.20.0.5", 23456)
            flow2.metadata = {}
            discovery.request(flow2)

            assert mock_dns.call_count == 1

        assert flow1.metadata["agent"] == "boris"
        assert flow2.metadata["agent"] == "boris"


class TestServiceDiscoveryAgentEvent:
    """Tests for agent.discovered event emission."""

    def test_emits_agent_discovered_on_first_dns_resolution(self):
        """Test write_event('agent.discovered') is called on first DNS hit."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns, \
             patch("service_discovery.write_event") as mock_event:
            mock_dns.return_value = ("boris.safeyolo_internal", [], ["172.20.0.5"])
            discovery.get_client_for_ip("172.20.0.5")

            mock_event.assert_called_once_with(
                "agent.discovered", agent="boris", ip="172.20.0.5"
            )

    def test_no_event_on_valid_cache_hit(self):
        """Test no event emitted when result comes from non-expired cache."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns, \
             patch("service_discovery.write_event") as mock_event:
            mock_dns.return_value = ("boris.safeyolo_internal", [], ["172.20.0.5"])
            discovery.get_client_for_ip("172.20.0.5")
            discovery.get_client_for_ip("172.20.0.5")

            # Only one event on first resolution, not on cache hits
            assert mock_event.call_count == 1

    def test_no_event_on_cache_refresh(self):
        """Test no event emitted when expired cache entry is re-resolved."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns, \
             patch("service_discovery.write_event") as mock_event:
            mock_dns.return_value = ("boris.safeyolo_internal", [], ["172.20.0.5"])

            # First resolution — should emit event
            discovery.get_client_for_ip("172.20.0.5")
            assert mock_event.call_count == 1

            # Expire the cache entry
            with discovery._lock:
                ip, (name, _) = next(iter(discovery._dns_cache.items()))
                discovery._dns_cache[ip] = (name, time.time() - 1)

            # Re-resolve after expiry — should NOT emit event
            discovery.get_client_for_ip("172.20.0.5")
            assert mock_event.call_count == 1


class TestServiceDiscoveryLastSeen:
    """Tests for last-seen timestamp tracking."""

    def test_request_updates_last_seen(self):
        """Test request() updates _last_seen for resolved agents."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        flow = Mock()
        flow.client_conn.peername = ("172.20.0.5", 12345)
        flow.metadata = {}

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns, \
             patch("service_discovery.write_event"):
            mock_dns.return_value = ("boris.safeyolo_internal", [], ["172.20.0.5"])
            discovery.request(flow)

        assert "boris" in discovery._last_seen
        assert discovery._last_seen["boris"] <= time.time()

    def test_last_seen_updates_on_each_request(self):
        """Test last_seen timestamp advances with each flow."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns, \
             patch("service_discovery.write_event"):
            mock_dns.return_value = ("boris.safeyolo_internal", [], ["172.20.0.5"])

            flow1 = Mock()
            flow1.client_conn.peername = ("172.20.0.5", 12345)
            flow1.metadata = {}
            discovery.request(flow1)
            ts1 = discovery._last_seen["boris"]

            flow2 = Mock()
            flow2.client_conn.peername = ("172.20.0.5", 23456)
            flow2.metadata = {}
            discovery.request(flow2)
            ts2 = discovery._last_seen["boris"]

        assert ts2 >= ts1

    def test_no_last_seen_for_unknown_agent(self):
        """Test _last_seen is not updated for unresolved IPs."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        flow = Mock()
        flow.client_conn.peername = ("192.168.1.100", 12345)
        flow.metadata = {}

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns:
            mock_dns.side_effect = socket.herror("Host not found")
            discovery.request(flow)

        assert len(discovery._last_seen) == 0

    def test_last_seen_tracks_multiple_agents(self):
        """Test _last_seen tracks each agent independently."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns, \
             patch("service_discovery.write_event"):
            mock_dns.return_value = ("boris.safeyolo_internal", [], ["172.20.0.5"])
            flow1 = Mock()
            flow1.client_conn.peername = ("172.20.0.5", 12345)
            flow1.metadata = {}
            discovery.request(flow1)

            mock_dns.return_value = ("claude.safeyolo_internal", [], ["172.20.0.6"])
            flow2 = Mock()
            flow2.client_conn.peername = ("172.20.0.6", 12345)
            flow2.metadata = {}
            discovery.request(flow2)

        assert "boris" in discovery._last_seen
        assert "claude" in discovery._last_seen


class TestServiceDiscoveryGetAgents:
    """Tests for get_agents() method."""

    def test_get_agents_empty(self):
        """Test get_agents returns empty when no agents discovered."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()
        result = discovery.get_agents()

        assert result["count"] == 0
        assert result["agents"] == {}

    def test_get_agents_after_request(self):
        """Test get_agents returns agent with IP and last_seen."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        flow = Mock()
        flow.client_conn.peername = ("172.20.0.5", 12345)
        flow.metadata = {}

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns, \
             patch("service_discovery.write_event"):
            mock_dns.return_value = ("boris.safeyolo_internal", [], ["172.20.0.5"])
            discovery.request(flow)

        result = discovery.get_agents()
        assert result["count"] == 1
        assert "boris" in result["agents"]
        agent = result["agents"]["boris"]
        assert agent["ip"] == "172.20.0.5"
        assert "last_seen" in agent
        assert "idle_seconds" in agent
        assert agent["idle_seconds"] >= 0

    def test_get_agents_multiple(self):
        """Test get_agents returns all discovered agents."""
        from service_discovery import ServiceDiscovery

        discovery = ServiceDiscovery()

        with patch("service_discovery.socket.gethostbyaddr") as mock_dns, \
             patch("service_discovery.write_event"):
            mock_dns.return_value = ("boris.safeyolo_internal", [], ["172.20.0.5"])
            flow1 = Mock()
            flow1.client_conn.peername = ("172.20.0.5", 12345)
            flow1.metadata = {}
            discovery.request(flow1)

            mock_dns.return_value = ("claude.safeyolo_internal", [], ["172.20.0.6"])
            flow2 = Mock()
            flow2.client_conn.peername = ("172.20.0.6", 12345)
            flow2.metadata = {}
            discovery.request(flow2)

        result = discovery.get_agents()
        assert result["count"] == 2
        assert "boris" in result["agents"]
        assert "claude" in result["agents"]


class TestGetServiceDiscovery:
    """Tests for global accessor."""

    def test_get_service_discovery_returns_instance(self):
        """Test get_service_discovery returns the global instance."""
        from service_discovery import _discovery, get_service_discovery

        result = get_service_discovery()
        assert result is _discovery
