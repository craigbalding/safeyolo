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
from pdp import get_policy_client
from safeyolo.core.audit_schema import EventKind, Severity
from safeyolo.core.utils import sanitize_for_log, write_event

log = logging.getLogger("safeyolo.request-logger")


class RequestLogger:
    """
    Native mitmproxy addon for JSONL structured logging.

    Logs:
    - All requests with method, host, path, size
    - All responses with status, size, duration
    - Blocks with plugin, reason, credential info

    Loads quiet_hosts config from PDP to suppress logging for chatty hosts.

    Counters (see get_stats): `requests_total` counts every request observed,
    INCLUDING those that were quieted. `requests_quieted` is a subset of
    `requests_total` — the number that produced no traffic.request event.
    `responses_total` counts non-blocked responses; `blocks_total` counts
    blocked responses. Quieted requests whose responses were also blocked
    ARE logged (security override) and counted in `blocks_total`.
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
        """Load quiet_hosts from PDP sensor config. Fails closed on malformed config.

        Args:
            sensor_config: Dict from PolicyClient.get_sensor_config()

        Raises:
            ValueError: if `quiet_hosts.hosts` is not a list, or any value in
                `quiet_hosts.paths` is not a list. Malformed config must fail
                the load loudly rather than silently drop rules.
        """
        rl = sensor_config.get("addons", {}).get("request_logger", {})
        qh = rl.get("quiet_hosts", {})

        hosts_raw = qh.get("hosts", [])
        if not isinstance(hosts_raw, list):
            raise ValueError(
                f"quiet_hosts.hosts must be a list, got {type(hosts_raw).__name__}. "
                f"Fix addons.request_logger.quiet_hosts.hosts in policy."
            )

        paths_raw = qh.get("paths", {})
        if not isinstance(paths_raw, dict):
            raise ValueError(
                f"quiet_hosts.paths must be a dict of host -> [path, ...], "
                f"got {type(paths_raw).__name__}. "
                f"Fix addons.request_logger.quiet_hosts.paths in policy."
            )

        hosts: set[str] = set()
        host_patterns: list[str] = []
        for host in hosts_raw:
            if "*" in host:
                host_patterns.append(host.lower())
            else:
                hosts.add(host.lower())

        paths: dict[str, list[str]] = {}
        for host, path_list in paths_raw.items():
            if not isinstance(path_list, list):
                raise ValueError(
                    f"quiet_hosts.paths['{host}'] must be a list of path patterns, "
                    f"got {type(path_list).__name__}. Fix policy."
                )
            # Copy the list so downstream mutations of the sensor_config cannot
            # propagate into our state via shared reference.
            paths[host.lower()] = list(path_list)

        with self._lock:
            self._quiet_hosts = hosts
            self._quiet_host_patterns = host_patterns
            self._quiet_paths = paths

        total = len(hosts) + len(host_patterns) + sum(len(p) for p in paths.values())
        if total > 0:
            log.info("Loaded %d quiet host rules from policy", total)

    def _maybe_reload_config(self):
        """Reload quiet hosts config if policy changed.

        Concurrent callers may both observe a stale `_last_policy_hash` and
        both trigger a reload; the inner state update is locked so the end
        state is consistent.
        """
        try:
            client = get_policy_client()
            sensor_config = client.get_sensor_config()
        except RuntimeError:
            # PolicyClient not configured yet - silent skip is the documented
            # startup path: the addon must still log with the current (empty)
            # quiet-host state.
            return
        except Exception as e:
            # Fail-transparent: a config reload error is itself an operational
            # event. Surface it in the audit log, not just the Python logger,
            # so operators who filter by `addon=request-logger` can see it.
            log.warning("Failed to reload quiet hosts config: %s: %s", type(e).__name__, e)
            write_event(
                "ops.config_error",
                kind=EventKind.OPS,
                severity=Severity.MEDIUM,
                summary=f"request-logger config reload failed: {type(e).__name__}",
                addon=self.name,
                details={
                    "error_type": type(e).__name__,
                    "error_message": sanitize_for_log(str(e)),
                },
            )
            return

        with self._lock:
            policy_hash = sensor_config.get("policy_hash", "")
            if policy_hash == self._last_policy_hash:
                return
            self._last_policy_hash = policy_hash

        # Load outside the outer critical section — _load_quiet_hosts_from_pdp
        # takes its own lock for the final state write.
        try:
            self._load_quiet_hosts_from_pdp(sensor_config)
        except ValueError as e:
            log.warning("Malformed quiet_hosts config: %s", e)
            write_event(
                "ops.config_error",
                kind=EventKind.OPS,
                severity=Severity.MEDIUM,
                summary="request-logger quiet_hosts config malformed",
                addon=self.name,
                details={"error": sanitize_for_log(str(e))},
            )

    def _should_quiet(self, host: str, path: str) -> bool:
        """Check if host/path should be suppressed from logging."""
        host = host.lower()

        with self._lock:
            if host in self._quiet_hosts:
                return True
            for pattern in self._quiet_host_patterns:
                if fnmatch.fnmatch(host, pattern):
                    return True
            if host in self._quiet_paths:
                for path_pattern in self._quiet_paths[host]:
                    if fnmatch.fnmatch(path, path_pattern):
                        return True

        return False

    def request(self, flow: http.HTTPFlow):
        """Log incoming request."""
        with self._lock:
            self.requests_total += 1

        # Reload quiet hosts config if policy changed
        self._maybe_reload_config()

        # request_id set by request_id.py addon
        request_id = flow.metadata.get("request_id")

        parsed = urlparse(flow.request.pretty_url)
        host = parsed.hostname or ""
        path = parsed.path

        # Check if this host/path should be quieted
        if self._should_quiet(host, path):
            with self._lock:
                self.requests_quieted += 1
            flow.metadata["quieted"] = True
            return

        write_event(
            "traffic.request",
            kind=EventKind.TRAFFIC,
            severity=Severity.LOW,
            summary=f"{flow.request.method} {sanitize_for_log(host)}{sanitize_for_log(path)}",
            host=host,
            request_id=request_id,
            agent=flow.metadata.get("agent"),
            addon=self.name,
            details={
                "method": flow.request.method,
                "path": path,
                "size": len(flow.request.content or b""),
                "client": flow.client_conn.peername[0] if flow.client_conn.peername else None,
            },
        )

    def response(self, flow: http.HTTPFlow):
        """Log response (or block)."""
        # Skip if request was quieted (unless blocked — always log blocks)
        blocked_by = flow.metadata.get("blocked_by")
        if flow.metadata.get("quieted") and not blocked_by:
            return

        request_id = flow.metadata.get("request_id")
        start_time = flow.metadata.get("start_time")

        # Missing response is an operational problem, not a traffic event.
        # Emit a distinct ops.response_missing and do not fake a traffic.response.
        if flow.response is None:
            parsed = urlparse(flow.request.pretty_url)
            host = parsed.hostname or ""
            write_event(
                "ops.response_missing",
                kind=EventKind.OPS,
                severity=Severity.MEDIUM,
                summary=f"no response for {flow.request.method} {sanitize_for_log(host)}{sanitize_for_log(parsed.path)}",
                host=host,
                request_id=request_id,
                agent=flow.metadata.get("agent"),
                addon=self.name,
                details={
                    "method": flow.request.method,
                    "path": parsed.path,
                },
            )
            return

        with self._lock:
            if blocked_by:
                self.blocks_total += 1
            else:
                self.responses_total += 1

        duration_ms = None
        if start_time:
            duration_ms = round((time.time() - start_time) * 1000, 1)

        parsed = urlparse(flow.request.pretty_url)
        host = parsed.hostname or ""

        resp_details = {
            "path": parsed.path,
            "status": flow.response.status_code,
            "size": len(flow.response.content or b""),
            "ms": duration_ms,
        }

        if blocked_by:
            resp_details["blocked_by"] = blocked_by
            fingerprint = flow.metadata.get("credential_fingerprint")
            if fingerprint:
                resp_details["credential_fingerprint"] = fingerprint

        status_code = flow.response.status_code
        sev = Severity.HIGH if blocked_by else Severity.LOW
        block_suffix = f" [blocked by {blocked_by}]" if blocked_by else ""

        write_event(
            "traffic.response",
            kind=EventKind.TRAFFIC,
            severity=sev,
            summary=f"{status_code} {sanitize_for_log(host)}{sanitize_for_log(parsed.path)}{block_suffix}",
            host=host,
            request_id=request_id,
            agent=flow.metadata.get("agent"),
            addon=self.name,
            details=resp_details,
        )

    def get_stats(self) -> dict:
        """Get logger statistics.

        Returns a snapshot dict. `requests_total` counts every request
        observed, INCLUDING quieted ones. `requests_logged = requests_total -
        requests_quieted`. `responses_total` counts non-blocked responses;
        `blocks_total` counts blocks.
        """
        with self._lock:
            return {
                "requests_total": self.requests_total,
                "requests_quieted": self.requests_quieted,
                "responses_total": self.responses_total,
                "blocks_total": self.blocks_total,
            }


# mitmproxy addon instance
addons = [RequestLogger()]
