"""
Tests for rate_limiter.py addon.

Tests GCRA algorithm, per-domain rate limiting, and 429 responses.
"""

import pytest
import time


class TestGCRAAlgorithm:
    """
    Tests for GCRA (Generic Cell Rate Algorithm).

    Note: GCRA differs from token bucket. With burst_capacity=N, you can make
    N+1 requests instantly (N burst credits + 1 "on time" request). After that,
    requests are rate limited to the steady-state rate.
    """

    def test_allows_burst(self):
        """Test that burst capacity is respected."""
        from addons.rate_limiter import InMemoryGCRA, RateLimitConfig

        gcra = InMemoryGCRA()
        # burst_capacity=3 means 3+1=4 requests allowed instantly
        config = RateLimitConfig(requests_per_second=1.0, burst_capacity=3)

        # First 4 requests should be allowed (3 burst + 1 on-time)
        for i in range(4):
            result = gcra.check("test.com", config)
            assert result.allowed, f"Request {i+1} should be allowed"

        # 5th request should be rate limited
        result = gcra.check("test.com", config)
        assert not result.allowed
        assert result.wait_ms > 0

    def test_recovers_over_time(self):
        """Test that rate limit recovers after waiting."""
        from addons.rate_limiter import InMemoryGCRA, RateLimitConfig

        gcra = InMemoryGCRA()
        # burst_capacity=1 means 2 requests allowed instantly
        config = RateLimitConfig(requests_per_second=10.0, burst_capacity=1)

        # First two requests allowed (1 burst + 1 on-time)
        result = gcra.check("test.com", config)
        assert result.allowed
        result = gcra.check("test.com", config)
        assert result.allowed

        # Third immediate request blocked
        result = gcra.check("test.com", config)
        assert not result.allowed

        # Wait for recovery (100ms at 10 rps)
        time.sleep(0.15)

        # Should be allowed again
        result = gcra.check("test.com", config)
        assert result.allowed

    def test_domains_are_independent(self):
        """Test that rate limits are per-domain."""
        from addons.rate_limiter import InMemoryGCRA, RateLimitConfig

        gcra = InMemoryGCRA()
        # burst_capacity=1 means 2 requests allowed
        config = RateLimitConfig(requests_per_second=1.0, burst_capacity=1)

        # Exhaust limit for domain A (2 allowed, 3rd blocked)
        gcra.check("domain-a.com", config)
        gcra.check("domain-a.com", config)
        result = gcra.check("domain-a.com", config)
        assert not result.allowed

        # Domain B should still be allowed
        result = gcra.check("domain-b.com", config)
        assert result.allowed

    def test_wait_ms_is_accurate(self):
        """Test that wait_ms gives reasonable time to wait."""
        from addons.rate_limiter import InMemoryGCRA, RateLimitConfig

        gcra = InMemoryGCRA()
        # burst_capacity=1 means 2 requests allowed
        config = RateLimitConfig(requests_per_second=1.0, burst_capacity=1)

        # Exhaust limit (2 requests)
        gcra.check("test.com", config)
        gcra.check("test.com", config)

        # Get wait time on 3rd request
        result = gcra.check("test.com", config)
        assert not result.allowed
        assert 900 < result.wait_ms < 1100  # ~1000ms for 1 rps


class TestRateLimiterConfig:
    """Tests for rate limiter configuration."""

    def test_default_config(self, rate_limiter):
        """Test default conservative rate limits."""
        assert rate_limiter._default_config.requests_per_second == 0.5
        assert rate_limiter._default_config.burst_capacity == 3

    def test_get_config_exact_match(self, rate_limiter):
        """Test per-domain config exact match."""
        from addons.rate_limiter import RateLimitConfig

        rate_limiter._configs["api.openai.com"] = RateLimitConfig(
            requests_per_second=1.0,
            burst_capacity=5,
        )

        config = rate_limiter._get_config("api.openai.com")
        assert config.requests_per_second == 1.0
        assert config.burst_capacity == 5

    def test_get_config_wildcard_match(self, rate_limiter):
        """Test per-domain config wildcard match."""
        from addons.rate_limiter import RateLimitConfig

        rate_limiter._configs["*.googleapis.com"] = RateLimitConfig(
            requests_per_second=2.0,
            burst_capacity=10,
        )

        config = rate_limiter._get_config("storage.googleapis.com")
        assert config.requests_per_second == 2.0

        config = rate_limiter._get_config("random.com")
        assert config.requests_per_second == 0.5  # Default

    def test_get_config_fallback_to_default(self, rate_limiter):
        """Test fallback to default config."""
        config = rate_limiter._get_config("unknown-domain.com")
        assert config.requests_per_second == rate_limiter._default_config.requests_per_second


class TestRateLimiterBlocking:
    """Tests for rate limiter blocking behavior."""

    def test_allows_requests_within_limit(self, rate_limiter, make_flow):
        """Test that requests within limit are allowed."""
        # Set high limit for testing
        rate_limiter._default_config.requests_per_second = 100.0
        rate_limiter._default_config.burst_capacity = 10

        flow = make_flow(url="http://test.com/api")
        rate_limiter.request(flow)

        assert flow.response is None
        assert flow.metadata.get("ratelimit_remaining") is not None

    def test_blocks_requests_over_limit(self, rate_limiter, make_flow):
        """Test that requests over limit are blocked with 429."""
        # Set low limit (burst=1 means 2 requests allowed)
        rate_limiter._default_config.requests_per_second = 100.0
        rate_limiter._default_config.burst_capacity = 1

        # First two requests allowed (burst + on-time)
        flow1 = make_flow(url="http://test.com/api")
        rate_limiter.request(flow1)
        assert flow1.response is None

        flow2 = make_flow(url="http://test.com/api")
        rate_limiter.request(flow2)
        assert flow2.response is None

        # Third request blocked
        flow3 = make_flow(url="http://test.com/api")
        rate_limiter.request(flow3)

        assert flow3.response is not None
        assert flow3.response.status_code == 429
        assert "Retry-After" in flow3.response.headers
        assert flow3.metadata.get("blocked_by") == "rate-limiter"

    def test_429_response_has_retry_after(self, rate_limiter, make_flow):
        """Test that 429 response includes Retry-After header."""
        rate_limiter._default_config.requests_per_second = 1.0
        rate_limiter._default_config.burst_capacity = 1

        # Exhaust limit (2 requests with burst=1)
        flow1 = make_flow(url="http://test.com/api")
        rate_limiter.request(flow1)
        flow2 = make_flow(url="http://test.com/api")
        rate_limiter.request(flow2)

        # Get 429 on 3rd request
        flow3 = make_flow(url="http://test.com/api")
        rate_limiter.request(flow3)

        assert flow3.response.status_code == 429
        retry_after = int(flow3.response.headers["Retry-After"])
        assert retry_after >= 1


class TestRateLimiterStats:
    """Tests for rate limiter statistics."""

    def test_stats_tracking(self, rate_limiter, make_flow):
        """Test that stats are tracked correctly."""
        rate_limiter._default_config.requests_per_second = 100.0
        rate_limiter._default_config.burst_capacity = 1

        assert rate_limiter.checks_total == 0
        assert rate_limiter.allowed_total == 0
        assert rate_limiter.limited_total == 0

        # First two requests - allowed (burst=1 means 2 allowed)
        flow1 = make_flow(url="http://test.com/api")
        rate_limiter.request(flow1)

        assert rate_limiter.checks_total == 1
        assert rate_limiter.allowed_total == 1
        assert rate_limiter.limited_total == 0

        flow2 = make_flow(url="http://test.com/api")
        rate_limiter.request(flow2)

        assert rate_limiter.checks_total == 2
        assert rate_limiter.allowed_total == 2
        assert rate_limiter.limited_total == 0

        # Third request - limited
        flow3 = make_flow(url="http://test.com/api")
        rate_limiter.request(flow3)

        assert rate_limiter.checks_total == 3
        assert rate_limiter.allowed_total == 2
        assert rate_limiter.limited_total == 1

    def test_get_stats_returns_dict(self, rate_limiter):
        """Test that get_stats returns proper structure."""
        stats = rate_limiter.get_stats()

        assert "checks_total" in stats
        assert "allowed_total" in stats
        assert "limited_total" in stats
        assert "reloads_total" in stats
        assert "default_rps" in stats
        assert "default_burst" in stats
        assert "configured_domains" in stats


class TestRateLimiterHotReload:
    """Tests for rate limiter hot reload functionality."""

    def test_reload_config_updates_limits(self, rate_limiter, tmp_path):
        """Test that _reload_config updates rate limits from file."""
        # Create initial config file
        config_file = tmp_path / "rates.json"
        config_file.write_text('{"default": {"rps": 5.0, "burst": 10}, "domains": {}}')

        rate_limiter.config_path = config_file

        # Initial values
        assert rate_limiter._default_config.requests_per_second == 0.5
        assert rate_limiter.reloads_total == 0

        # Reload
        result = rate_limiter._reload_config()

        assert result is True
        assert rate_limiter._default_config.requests_per_second == 5.0
        assert rate_limiter._default_config.burst_capacity == 10
        assert rate_limiter.reloads_total == 1

    def test_reload_config_updates_domain_configs(self, rate_limiter, tmp_path):
        """Test that _reload_config updates per-domain configs."""
        config_file = tmp_path / "rates.json"
        config_file.write_text('''{
            "default": {"rps": 1.0, "burst": 3},
            "domains": {
                "api.openai.com": {"rps": 30.0, "burst": 100},
                "*.googleapis.com": {"rps": 2.0, "burst": 10}
            }
        }''')

        rate_limiter.config_path = config_file
        rate_limiter._reload_config()

        assert "api.openai.com" in rate_limiter._configs
        assert "*.googleapis.com" in rate_limiter._configs
        assert rate_limiter._configs["api.openai.com"].requests_per_second == 30.0
        assert rate_limiter._configs["*.googleapis.com"].burst_capacity == 10

    def test_reload_config_handles_missing_file(self, rate_limiter, tmp_path):
        """Test that _reload_config handles missing file gracefully."""
        rate_limiter.config_path = tmp_path / "nonexistent.json"

        result = rate_limiter._reload_config()

        assert result is False
        assert rate_limiter.reloads_total == 0

    def test_reload_config_handles_invalid_json(self, rate_limiter, tmp_path):
        """Test that _reload_config handles invalid JSON gracefully."""
        config_file = tmp_path / "invalid.json"
        config_file.write_text("not valid json {{{")

        rate_limiter.config_path = config_file

        result = rate_limiter._reload_config()

        assert result is False
        assert rate_limiter.reloads_total == 0

    def test_reload_increments_counter(self, rate_limiter, tmp_path):
        """Test that successful reloads increment the counter."""
        config_file = tmp_path / "rates.json"
        config_file.write_text('{"default": {"rps": 1.0, "burst": 3}}')

        rate_limiter.config_path = config_file

        rate_limiter._reload_config()
        assert rate_limiter.reloads_total == 1

        rate_limiter._reload_config()
        assert rate_limiter.reloads_total == 2

    def test_load_config_sets_mtime(self, rate_limiter, tmp_path):
        """Test that _load_config sets _last_mtime for watcher."""
        config_file = tmp_path / "rates.json"
        config_file.write_text('{"default": {"rps": 1.0, "burst": 3}}')

        assert rate_limiter._last_mtime == 0

        rate_limiter._load_config(str(config_file))

        assert rate_limiter._last_mtime > 0
        assert rate_limiter._last_mtime == config_file.stat().st_mtime

    def test_watcher_thread_lifecycle(self, rate_limiter, tmp_path):
        """Test that watcher thread can be started and stopped."""
        config_file = tmp_path / "rates.json"
        config_file.write_text('{"default": {"rps": 1.0, "burst": 3}}')

        rate_limiter.config_path = config_file
        rate_limiter._load_config(str(config_file))

        # Start watcher
        assert rate_limiter._watcher_thread is None
        rate_limiter._start_watcher()
        assert rate_limiter._watcher_thread is not None
        assert rate_limiter._watcher_thread.is_alive()

        # Stop watcher
        rate_limiter._stop_watcher()
        assert rate_limiter._watcher_thread is None

    def test_watcher_detects_file_change(self, rate_limiter, tmp_path):
        """Test that watcher detects and reloads on file change."""
        import time

        config_file = tmp_path / "rates.json"
        config_file.write_text('{"default": {"rps": 1.0, "burst": 3}}')

        rate_limiter.config_path = config_file
        rate_limiter._load_config(str(config_file))

        assert rate_limiter._default_config.requests_per_second == 1.0
        assert rate_limiter.reloads_total == 0

        # Start watcher
        rate_limiter._start_watcher()

        try:
            # Modify the file
            time.sleep(0.1)  # Ensure mtime differs
            config_file.write_text('{"default": {"rps": 99.0, "burst": 50}}')

            # Wait for watcher to detect change (checks every 5s, wait a bit)
            time.sleep(6)

            # Verify reload happened
            assert rate_limiter.reloads_total >= 1
            assert rate_limiter._default_config.requests_per_second == 99.0
        finally:
            rate_limiter._stop_watcher()
