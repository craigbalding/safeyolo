"""
metrics.py - Native mitmproxy addon for metrics collection

Collects per-domain statistics:
- Request counts, success rates
- Latency tracking
- Error categorization
- Block counts by source

Exposes metrics via admin API in JSON and Prometheus formats.

Usage:
    mitmdump -s addons/metrics.py
"""

import logging
import threading
import time
from dataclasses import dataclass

from mitmproxy import http

log = logging.getLogger("safeyolo.metrics")


@dataclass
class DomainStats:
    """Per-domain statistics."""
    requests: int = 0
    successes: int = 0
    blocked_credential: int = 0
    blocked_yara: int = 0
    blocked_pattern: int = 0
    blocked_injection: int = 0
    upstream_429s: int = 0
    upstream_5xx: int = 0
    timeouts: int = 0

    latency_sum_ms: float = 0
    latency_count: int = 0
    latency_max_ms: float = 0

    @property
    def success_rate(self) -> float:
        if self.requests == 0:
            return 1.0
        return self.successes / self.requests

    @property
    def avg_latency_ms(self) -> float:
        if self.latency_count == 0:
            return 0
        return self.latency_sum_ms / self.latency_count

    def to_dict(self) -> dict:
        return {
            "requests": self.requests,
            "successes": self.successes,
            "success_rate": round(self.success_rate, 3),
            "blocked": {
                "credential": self.blocked_credential,
                "yara": self.blocked_yara,
                "pattern": self.blocked_pattern,
                "injection": self.blocked_injection,
            },
            "upstream_errors": {
                "429s": self.upstream_429s,
                "5xx": self.upstream_5xx,
                "timeouts": self.timeouts,
            },
            "latency_ms": {
                "avg": round(self.avg_latency_ms, 1),
                "max": round(self.latency_max_ms, 1),
            },
        }


class MetricsCollector:
    """
    Native mitmproxy addon for metrics collection.

    Observes all requests/responses and tracks statistics per domain.
    """

    name = "metrics"

    def __init__(self):
        self._lock = threading.Lock()
        self._start_time = time.time()
        self._domain_stats: dict[str, DomainStats] = {}

        # Global counters
        self.requests_total = 0
        self.requests_success = 0
        self.requests_blocked = 0
        self.requests_error = 0

    def _get_domain_stats(self, domain: str) -> DomainStats:
        with self._lock:
            if domain not in self._domain_stats:
                self._domain_stats[domain] = DomainStats()
            return self._domain_stats[domain]

    def request(self, flow: http.HTTPFlow):
        """Record request."""
        self.requests_total += 1
        self._get_domain_stats(flow.request.host).requests += 1
        flow.metadata["metrics_start_time"] = time.time()

    def response(self, flow: http.HTTPFlow):
        """Record response metrics."""
        domain = flow.request.host
        stats = self._get_domain_stats(domain)

        # Calculate latency
        start_time = flow.metadata.get("metrics_start_time")
        latency_ms = 0.0
        if start_time:
            latency_ms = (time.time() - start_time) * 1000

        # Check if blocked
        blocked_by = flow.metadata.get("blocked_by")
        if blocked_by:
            self.requests_blocked += 1
            if blocked_by == "credential-guard":
                stats.blocked_credential += 1
            elif blocked_by == "yara-scanner":
                stats.blocked_yara += 1
            elif blocked_by == "pattern-scanner":
                stats.blocked_pattern += 1
            elif blocked_by == "prompt-injection":
                stats.blocked_injection += 1
            return

        if not flow.response:
            return

        # Check response status
        status = flow.response.status_code

        if status == 429:
            stats.upstream_429s += 1
        elif status >= 500:
            stats.upstream_5xx += 1
            if status == 504:
                stats.timeouts += 1
                self.requests_error += 1
        elif status < 400:
            self.requests_success += 1
            stats.successes += 1
            stats.latency_sum_ms += latency_ms
            stats.latency_count += 1
            stats.latency_max_ms = max(stats.latency_max_ms, latency_ms)

    def get_json(self) -> dict:
        """Get metrics as JSON."""
        uptime = time.time() - self._start_time

        # Copy under lock for thread safety
        with self._lock:
            domain_stats_copy = dict(self._domain_stats)

        # Sort domains by request count
        sorted_domains = sorted(
            domain_stats_copy.items(),
            key=lambda x: x[1].requests,
            reverse=True,
        )

        # Identify problem domains
        problem_domains = []
        for domain, stats in sorted_domains:
            issues = []
            if stats.success_rate < 0.9 and stats.requests > 10:
                issues.append(f"low_success_rate:{stats.success_rate:.1%}")
            if stats.upstream_429s > 5:
                issues.append(f"upstream_429s:{stats.upstream_429s}")
            if issues:
                problem_domains.append({"domain": domain, "issues": issues})

        return {
            "uptime_seconds": round(uptime, 1),
            "summary": {
                "requests_total": self.requests_total,
                "requests_success": self.requests_success,
                "requests_blocked": self.requests_blocked,
                "requests_error": self.requests_error,
                "success_rate": round(
                    self.requests_success / max(1, self.requests_total), 3
                ),
                "domains_tracked": len(domain_stats_copy),
            },
            "problem_domains": problem_domains,
            "domains": {
                domain: stats.to_dict() for domain, stats in sorted_domains[:20]
            },
        }

    def get_prometheus(self) -> str:
        """Get metrics in Prometheus format."""
        lines = []
        uptime = time.time() - self._start_time

        # Copy under lock for thread safety
        with self._lock:
            domain_stats_copy = dict(self._domain_stats)

        # Global metrics
        lines.append("# HELP safeyolo_uptime_seconds Proxy uptime")
        lines.append("# TYPE safeyolo_uptime_seconds gauge")
        lines.append(f"safeyolo_uptime_seconds {uptime:.1f}")

        lines.append("# HELP safeyolo_requests_total Total requests")
        lines.append("# TYPE safeyolo_requests_total counter")
        lines.append(f"safeyolo_requests_total {self.requests_total}")

        lines.append("# HELP safeyolo_requests_success Successful requests")
        lines.append("# TYPE safeyolo_requests_success counter")
        lines.append(f"safeyolo_requests_success {self.requests_success}")

        lines.append("# HELP safeyolo_requests_blocked Blocked requests")
        lines.append("# TYPE safeyolo_requests_blocked counter")
        lines.append(f"safeyolo_requests_blocked {self.requests_blocked}")

        # Per-domain metrics
        lines.append("")
        lines.append("# HELP safeyolo_domain_requests_total Requests per domain")
        lines.append("# TYPE safeyolo_domain_requests_total counter")
        for domain, stats in domain_stats_copy.items():
            lines.append(f'safeyolo_domain_requests_total{{domain="{domain}"}} {stats.requests}')

        lines.append("")
        lines.append("# HELP safeyolo_domain_success_rate Success rate per domain")
        lines.append("# TYPE safeyolo_domain_success_rate gauge")
        for domain, stats in domain_stats_copy.items():
            lines.append(f'safeyolo_domain_success_rate{{domain="{domain}"}} {stats.success_rate:.3f}')

        lines.append("")
        lines.append("# HELP safeyolo_domain_latency_avg_ms Average latency per domain")
        lines.append("# TYPE safeyolo_domain_latency_avg_ms gauge")
        for domain, stats in domain_stats_copy.items():
            lines.append(f'safeyolo_domain_latency_avg_ms{{domain="{domain}"}} {stats.avg_latency_ms:.1f}')

        return "\n".join(lines) + "\n"

    def get_stats(self) -> dict:
        """Get basic stats for admin API."""
        with self._lock:
            domains_tracked = len(self._domain_stats)
        return {
            "requests_total": self.requests_total,
            "requests_success": self.requests_success,
            "requests_blocked": self.requests_blocked,
            "domains_tracked": domains_tracked,
        }


# mitmproxy addon instance
addons = [MetricsCollector()]
