"""
Tests for metrics.py - Per-domain statistics collection.

Tests request/response tracking and metrics output.
"""

import time
from unittest.mock import Mock


class TestDomainStats:
    """Tests for DomainStats dataclass."""

    def test_default_values_zero(self):
        """Test all stats start at zero."""
        from metrics import DomainStats

        stats = DomainStats()
        assert stats.requests == 0
        assert stats.successes == 0
        assert stats.blocked_credential == 0
        assert stats.upstream_429s == 0
        assert stats.latency_sum_ms == 0

    def test_success_rate_no_requests(self):
        """Test success rate is 1.0 when no requests."""
        from metrics import DomainStats

        stats = DomainStats()
        assert stats.success_rate == 1.0

    def test_success_rate_calculation(self):
        """Test success rate calculation."""
        from metrics import DomainStats

        stats = DomainStats(requests=100, successes=90)
        assert stats.success_rate == 0.9

    def test_avg_latency_no_data(self):
        """Test avg latency is 0 when no data."""
        from metrics import DomainStats

        stats = DomainStats()
        assert stats.avg_latency_ms == 0

    def test_avg_latency_calculation(self):
        """Test avg latency calculation."""
        from metrics import DomainStats

        stats = DomainStats(latency_sum_ms=1000, latency_count=10)
        assert stats.avg_latency_ms == 100

    def test_to_dict_structure(self):
        """Test to_dict returns correct structure."""
        from metrics import DomainStats

        stats = DomainStats(
            requests=50,
            successes=45,
            blocked_credential=3,
            blocked_yara=1,
            upstream_429s=5,
            latency_sum_ms=4500,
            latency_count=45,
            latency_max_ms=200,
        )

        result = stats.to_dict()

        assert result["requests"] == 50
        assert result["successes"] == 45
        assert result["success_rate"] == 0.9
        assert result["blocked"]["credential"] == 3
        assert result["blocked"]["yara"] == 1
        assert result["upstream_errors"]["429s"] == 5
        assert result["latency_ms"]["avg"] == 100
        assert result["latency_ms"]["max"] == 200


class TestMetricsCollector:
    """Tests for MetricsCollector addon."""

    def test_addon_name(self):
        """Test addon has correct name."""
        from metrics import MetricsCollector

        collector = MetricsCollector()
        assert collector.name == "metrics"

    def test_initial_counters_zero(self):
        """Test counters start at zero."""
        from metrics import MetricsCollector

        collector = MetricsCollector()
        assert collector.requests_total == 0
        assert collector.requests_success == 0
        assert collector.requests_blocked == 0
        assert collector.requests_error == 0


class TestMetricsCollectorRequest:
    """Tests for request tracking."""

    def test_request_increments_total(self):
        """Test request increments total counter."""
        from metrics import MetricsCollector

        collector = MetricsCollector()

        flow = Mock()
        flow.request.host = "api.example.com"
        flow.metadata = {}

        collector.request(flow)
        collector.request(flow)
        collector.request(flow)

        assert collector.requests_total == 3

    def test_request_tracks_per_domain(self):
        """Test requests are tracked per domain."""
        from metrics import MetricsCollector

        collector = MetricsCollector()

        for host in ["api.example.com", "api.example.com", "other.com"]:
            flow = Mock()
            flow.request.host = host
            flow.metadata = {}
            collector.request(flow)

        stats = collector._domain_stats
        assert stats["api.example.com"].requests == 2
        assert stats["other.com"].requests == 1

    def test_request_sets_start_time(self):
        """Test request sets metrics start time in metadata."""
        from metrics import MetricsCollector

        collector = MetricsCollector()

        flow = Mock()
        flow.request.host = "api.example.com"
        flow.metadata = {}

        collector.request(flow)

        assert "metrics_start_time" in flow.metadata
        assert isinstance(flow.metadata["metrics_start_time"], float)


class TestMetricsCollectorResponse:
    """Tests for response tracking."""

    def test_success_response_increments_success(self):
        """Test successful response increments success counter."""
        from metrics import MetricsCollector

        collector = MetricsCollector()

        flow = Mock()
        flow.request.host = "api.example.com"
        flow.metadata = {"metrics_start_time": time.time()}
        flow.response.status_code = 200

        collector.response(flow)

        assert collector.requests_success == 1

    def test_blocked_response_increments_blocked(self):
        """Test blocked response increments blocked counter."""
        from metrics import MetricsCollector

        collector = MetricsCollector()

        flow = Mock()
        flow.request.host = "api.example.com"
        flow.metadata = {"blocked_by": "credential-guard"}

        collector.response(flow)

        assert collector.requests_blocked == 1
        stats = collector._domain_stats["api.example.com"]
        assert stats.blocked_credential == 1

    def test_tracks_different_block_sources(self):
        """Test different block sources are tracked separately."""
        from metrics import MetricsCollector

        collector = MetricsCollector()

        block_sources = [
            "credential-guard",
            "yara-scanner",
            "pattern-scanner",
            "prompt-injection",
        ]

        for source in block_sources:
            flow = Mock()
            flow.request.host = "api.example.com"
            flow.metadata = {"blocked_by": source}
            collector.response(flow)

        stats = collector._domain_stats["api.example.com"]
        assert stats.blocked_credential == 1
        assert stats.blocked_yara == 1
        assert stats.blocked_pattern == 1
        assert stats.blocked_injection == 1

    def test_tracks_upstream_429s(self):
        """Test upstream 429 responses are tracked."""
        from metrics import MetricsCollector

        collector = MetricsCollector()

        flow = Mock()
        flow.request.host = "api.example.com"
        flow.metadata = {}
        flow.response.status_code = 429

        collector.response(flow)

        stats = collector._domain_stats["api.example.com"]
        assert stats.upstream_429s == 1

    def test_tracks_upstream_5xx(self):
        """Test upstream 5xx responses are tracked."""
        from metrics import MetricsCollector

        collector = MetricsCollector()

        for status in [500, 502, 503]:
            flow = Mock()
            flow.request.host = "api.example.com"
            flow.metadata = {}
            flow.response.status_code = status
            collector.response(flow)

        stats = collector._domain_stats["api.example.com"]
        assert stats.upstream_5xx == 3

    def test_tracks_latency(self):
        """Test latency is tracked for successful requests."""
        from metrics import MetricsCollector

        collector = MetricsCollector()

        # Simulate request/response with known timing
        start_time = time.time() - 0.1  # 100ms ago

        flow = Mock()
        flow.request.host = "api.example.com"
        flow.metadata = {"metrics_start_time": start_time}
        flow.response.status_code = 200

        collector.response(flow)

        stats = collector._domain_stats["api.example.com"]
        assert stats.latency_count == 1
        assert stats.latency_sum_ms >= 100  # At least 100ms
        assert stats.latency_max_ms >= 100


class TestMetricsCollectorOutput:
    """Tests for metrics output formats."""

    def test_get_json_structure(self):
        """Test get_json returns correct structure."""
        from metrics import MetricsCollector

        collector = MetricsCollector()
        collector.requests_total = 100
        collector.requests_success = 90
        collector.requests_blocked = 5
        collector.requests_error = 5

        # Add some domain data
        stats = collector._get_domain_stats("api.example.com")
        stats.requests = 50
        stats.successes = 45

        result = collector.get_json()

        assert "uptime_seconds" in result
        assert "summary" in result
        assert result["summary"]["requests_total"] == 100
        assert result["summary"]["requests_success"] == 90
        assert "domains" in result
        assert "api.example.com" in result["domains"]

    def test_get_json_identifies_problem_domains(self):
        """Test get_json identifies problem domains."""
        from metrics import MetricsCollector

        collector = MetricsCollector()

        # Create problem domain with low success rate
        stats = collector._get_domain_stats("problem.example.com")
        stats.requests = 100
        stats.successes = 50  # 50% success rate

        result = collector.get_json()

        assert len(result["problem_domains"]) >= 1
        problem = result["problem_domains"][0]
        assert problem["domain"] == "problem.example.com"
        assert any("low_success_rate" in issue for issue in problem["issues"])

    def test_get_prometheus_format(self):
        """Test get_prometheus returns valid format."""
        from metrics import MetricsCollector

        collector = MetricsCollector()
        collector.requests_total = 100
        collector.requests_success = 95
        collector.requests_blocked = 5

        # Add domain data
        stats = collector._get_domain_stats("api.example.com")
        stats.requests = 100

        result = collector.get_prometheus()

        assert "# HELP" in result
        assert "# TYPE" in result
        assert "safeyolo_requests_total 100" in result
        assert "safeyolo_requests_success 95" in result
        assert 'safeyolo_domain_requests_total{domain="api.example.com"}' in result

    def test_get_stats_for_admin_api(self):
        """Test get_stats returns simple dict for admin API."""
        from metrics import MetricsCollector

        collector = MetricsCollector()
        collector.requests_total = 50
        collector.requests_success = 45
        collector.requests_blocked = 3
        collector._get_domain_stats("a.com")
        collector._get_domain_stats("b.com")

        stats = collector.get_stats()

        assert stats["requests_total"] == 50
        assert stats["requests_success"] == 45
        assert stats["requests_blocked"] == 3
        assert stats["domains_tracked"] == 2
