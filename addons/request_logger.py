"""
request_logger.py - Native mitmproxy addon for structured logging

Logs all requests/responses to JSONL for monitoring and debugging.
Captures metadata from other addons (e.g., blocked_by, credential_prefix).

Supports quiet_hosts config (from PDP) to suppress logging for chatty hosts.

Uses write_event() from utils for centralized logging to AUDIT_LOG_PATH.
"""

import fnmatch
import logging
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

from mitmproxy import http

# Add parent to path for pdp imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils import write_event

from pdp import get_policy_client

log = logging.getLogger("safeyolo.request-logger")


class RequestLogger:
    """
    Native mitmproxy addon for JSONL structured logging.

    Logs:
    - All requests with method, host, path, size
    - All responses with status, size, duration
    - Blocks with plugin, reason, credential info

    Loads quiet_hosts config from PDP to suppress logging for chatty hosts.
    """

    name = "request-logger"

    def __init__(self):
        self._lock = threading.Lock()
        self._quiet_hosts: set[str] = set()  # Exact host matches
        self._quiet_host_patterns: list[str] = []  # Wildcard patterns like *.example.com
        self._quiet_paths: dict[str, list[str]] = {}  # host -> [path patterns]
        self._last_policy_hash: str = ""
        self.requests_total = 0
        self.requests_quieted = 0
        self.responses_total = 0
        self.blocks_total = 0

    def _load_quiet_hosts_from_pdp(self, sensor_config: dict):
        """Load quiet_hosts from PDP sensor config.

        Args:
            sensor_config: Dict from PolicyClient.get_sensor_config()
        """
        rl = sensor_config.get("addons", {}).get("request_logger", {})
        qh = rl.get("quiet_hosts", {})

        hosts = set()
        host_patterns = []
        paths = {}

        # Parse hosts list
        for host in qh.get("hosts", []):
            if "*" in host:
                host_patterns.append(host.lower())
            else:
                hosts.add(host.lower())

        # Parse paths dict (host -> [path patterns])
        for host, path_list in qh.get("paths", {}).items():
            if isinstance(path_list, list):
                paths[host.lower()] = path_list

        with self._lock:
            self._quiet_hosts = hosts
            self._quiet_host_patterns = host_patterns
            self._quiet_paths = paths

        total = len(hosts) + len(host_patterns) + sum(len(p) for p in paths.values())
        if total > 0:
            log.info(f"Loaded {total} quiet host rules from policy")

    def _maybe_reload_config(self):
        """Reload quiet hosts config if policy changed."""
        try:
            client = get_policy_client()
            sensor_config = client.get_sensor_config()
            policy_hash = sensor_config.get("policy_hash", "")

            if policy_hash != self._last_policy_hash:
                self._load_quiet_hosts_from_pdp(sensor_config)
                self._last_policy_hash = policy_hash
        except RuntimeError:
            # PolicyClient not configured yet - skip reload
            pass
        except Exception as e:
            log.warning(f"Failed to reload quiet hosts config: {type(e).__name__}: {e}")

    def _should_quiet(self, host: str, path: str) -> bool:
        """Check if host/path should be suppressed from logging.

        Args:
            host: Request host (e.g., 'statsig.anthropic.com')
            path: Request path (e.g., '/v1/rgstr')

        Returns:
            True if this request should not be logged
        """
        host = host.lower()

        with self._lock:
            # Check exact host match
            if host in self._quiet_hosts:
                return True

            # Check host wildcard patterns
            for pattern in self._quiet_host_patterns:
                if fnmatch.fnmatch(host, pattern):
                    return True

            # Check host:path patterns
            if host in self._quiet_paths:
                for path_pattern in self._quiet_paths[host]:
                    if fnmatch.fnmatch(path, path_pattern):
                        return True

        return False

    def request(self, flow: http.HTTPFlow):
        """Log incoming request."""
        self.requests_total += 1

        # Reload quiet hosts config if policy changed
        self._maybe_reload_config()

        # request_id set by request_id.py addon (runs first in chain)
        request_id = flow.metadata.get("request_id")

        parsed = urlparse(flow.request.pretty_url)
        host = parsed.hostname or parsed.netloc
        path = parsed.path

        # Check if this host/path should be quieted
        if self._should_quiet(host, path):
            self.requests_quieted += 1
            flow.metadata["quieted"] = True
            return

        write_event(
            "traffic.request",
            request_id=request_id,
            method=flow.request.method,
            host=host,
            path=path,
            size=len(flow.request.content or b""),
            client=flow.client_conn.peername[0] if flow.client_conn.peername else None,
        )

    def response(self, flow: http.HTTPFlow):
        """Log response (or block)."""
        # Skip if request was quieted (unless it was blocked - always log blocks)
        blocked_by = flow.metadata.get("blocked_by")
        if flow.metadata.get("quieted") and not blocked_by:
            return

        request_id = flow.metadata.get("request_id")
        start_time = flow.metadata.get("start_time")

        if blocked_by:
            self.blocks_total += 1
        else:
            self.responses_total += 1

        duration_ms = None
        if start_time:
            duration_ms = round((time.time() - start_time) * 1000, 1)

        parsed = urlparse(flow.request.pretty_url)

        # Build kwargs for write_event
        kwargs = {
            "request_id": request_id,
            "host": parsed.netloc,
            "path": parsed.path,
            "status": flow.response.status_code if flow.response else None,
            "size": len(flow.response.content or b"") if flow.response else 0,
            "ms": duration_ms,
        }

        # Add block details if applicable
        if blocked_by:
            kwargs["blocked_by"] = blocked_by
            # Include credential fingerprint from credguard if available
            fingerprint = flow.metadata.get("credential_fingerprint")
            if fingerprint:
                kwargs["credential_fingerprint"] = fingerprint

        write_event("traffic.response", **kwargs)

    def get_stats(self) -> dict:
        """Get logger statistics."""
        return {
            "requests_total": self.requests_total,
            "requests_quieted": self.requests_quieted,
            "responses_total": self.responses_total,
            "blocks_total": self.blocks_total,
        }


# mitmproxy addon instance
addons = [RequestLogger()]
