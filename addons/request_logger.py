"""
request_logger.py - Native mitmproxy addon for structured logging

Logs all requests/responses to JSONL for monitoring and debugging.
Captures metadata from other addons (e.g., blocked_by, credential_prefix).

Supports a quiet_hosts.yaml config to suppress logging for chatty hosts.

Usage:
    mitmdump -s addons/request_logger.py --set safeyolo_log_path=/app/logs/safeyolo.jsonl
"""

import fnmatch
import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import yaml
from mitmproxy import ctx, http

try:
    from .utils import write_audit_event, BackgroundWorker
except ImportError:
    from utils import write_audit_event, BackgroundWorker

log = logging.getLogger("safeyolo.request-logger")


class QuietHostsConfig:
    """Manages quiet hosts configuration with hot reload."""

    def __init__(self, config_path: Path):
        self.config_path = config_path
        self._lock = threading.Lock()
        self._hosts: set[str] = set()  # Exact host matches
        self._host_patterns: list[str] = []  # Wildcard patterns like *.example.com
        self._paths: dict[str, list[str]] = {}  # host -> [path patterns]
        self._mtime: float = 0
        self._worker: Optional[BackgroundWorker] = None

    def load(self) -> bool:
        """Load config from file."""
        if not self.config_path.exists():
            log.debug(f"Quiet hosts config not found: {self.config_path}")
            return False

        try:
            content = self.config_path.read_text()
            config = yaml.safe_load(content) or {}

            hosts = set()
            host_patterns = []
            paths = {}

            # Parse hosts list
            for host in config.get("hosts", []):
                if "*" in host:
                    host_patterns.append(host.lower())
                else:
                    hosts.add(host.lower())

            # Parse paths dict (host -> [path patterns])
            for host, path_list in config.get("paths", {}).items():
                if isinstance(path_list, list):
                    paths[host.lower()] = path_list

            with self._lock:
                self._hosts = hosts
                self._host_patterns = host_patterns
                self._paths = paths
                self._mtime = self.config_path.stat().st_mtime

            total = len(hosts) + len(host_patterns) + sum(len(p) for p in paths.values())
            write_audit_event(
                "config_reload",
                addon="request-logger",
                config="quiet_hosts",
                rules=total,
                path=str(self.config_path),
            )
            return True

        except yaml.YAMLError as e:
            write_audit_event(
                "config_error",
                addon="request-logger",
                config="quiet_hosts",
                error=f"Invalid YAML: {e}",
                path=str(self.config_path),
            )
            return False
        except Exception as e:
            write_audit_event(
                "config_error",
                addon="request-logger",
                config="quiet_hosts",
                error=f"{type(e).__name__}: {e}",
                path=str(self.config_path),
            )
            return False

    def _check_reload(self):
        """Check if config file changed and reload if needed."""
        if not self.config_path.exists():
            return

        try:
            mtime = self.config_path.stat().st_mtime
            if mtime > self._mtime:
                self.load()  # load() writes its own audit event
        except Exception as e:
            log.debug(f"Config reload check failed: {type(e).__name__}: {e}")

    def start_watcher(self):
        """Start background file watcher."""
        if self._worker:
            return

        self._worker = BackgroundWorker(
            self._check_reload,
            interval_sec=5.0,
            name="quiet-hosts-watcher"
        )
        self._worker.start()
        log.debug("Started quiet hosts config watcher")

    def stop_watcher(self):
        """Stop the file watcher."""
        if self._worker:
            self._worker.stop()
            self._worker = None

    def should_quiet(self, host: str, path: str) -> bool:
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
            if host in self._hosts:
                return True

            # Check host wildcard patterns
            for pattern in self._host_patterns:
                if fnmatch.fnmatch(host, pattern):
                    return True

            # Check host:path patterns
            if host in self._paths:
                for path_pattern in self._paths[host]:
                    if fnmatch.fnmatch(path, path_pattern):
                        return True

        return False


class RequestLogger:
    """
    Native mitmproxy addon for JSONL structured logging.

    Logs:
    - All requests with method, host, path, size
    - All responses with status, size, duration
    - Blocks with plugin, reason, credential info

    Supports quiet_hosts.yaml to suppress logging for chatty hosts.
    """

    name = "request-logger"

    def __init__(self):
        self.log_path: Optional[Path] = None
        self.quiet_hosts: Optional[QuietHostsConfig] = None
        self.requests_total = 0
        self.requests_quieted = 0
        self.responses_total = 0
        self.blocks_total = 0

    def load(self, loader):
        """Register mitmproxy options."""
        loader.add_option(
            name="safeyolo_log_path",
            typespec=str,
            default="/app/logs/safeyolo.jsonl",
            help="Path for JSONL request log",
        )
        loader.add_option(
            name="safeyolo_quiet_hosts",
            typespec=str,
            default="/app/config/quiet_hosts.yaml",
            help="Path for quiet hosts config (suppress logging for chatty hosts)",
        )

    def configure(self, updates):
        """Handle option changes."""
        if "safeyolo_log_path" in updates:
            self.log_path = Path(ctx.options.safeyolo_log_path)
            # Ensure directory exists
            try:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                log.info(f"Request logger writing to {self.log_path}")
            except Exception as e:
                log.error(f"Failed to create log directory: {type(e).__name__}: {e}")

        if "safeyolo_quiet_hosts" in updates:
            config_path = Path(ctx.options.safeyolo_quiet_hosts)
            self.quiet_hosts = QuietHostsConfig(config_path)
            self.quiet_hosts.load()
            self.quiet_hosts.start_watcher()

    def _write_entry(self, entry: dict):
        """Write entry to JSONL log."""
        if not self.log_path:
            return

        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            log.error(f"Log write failed: {type(e).__name__}: {e}")

    def request(self, flow: http.HTTPFlow):
        """Log incoming request."""
        self.requests_total += 1

        # request_id set by request_id.py addon (runs first in chain)
        request_id = flow.metadata.get("request_id")

        parsed = urlparse(flow.request.pretty_url)
        host = parsed.netloc
        path = parsed.path

        # Check if this host/path should be quieted
        if self.quiet_hosts and self.quiet_hosts.should_quiet(host, path):
            self.requests_quieted += 1
            flow.metadata["quieted"] = True
            return

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": "traffic.request",
            "request_id": request_id,
            "method": flow.request.method,
            "host": host,
            "path": path,
            "size": len(flow.request.content or b""),
            "client": flow.client_conn.peername[0] if flow.client_conn.peername else None,
        }

        self._write_entry(entry)

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

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": "traffic.response",
            "request_id": request_id,
            "host": parsed.netloc,
            "path": parsed.path,
            "status": flow.response.status_code if flow.response else None,
            "size": len(flow.response.content or b"") if flow.response else 0,
            "ms": duration_ms,
        }

        # Add block details if applicable
        if blocked_by:
            entry["blocked_by"] = blocked_by
            # Include credential fingerprint from credguard if available
            fingerprint = flow.metadata.get("credential_fingerprint")
            if fingerprint:
                entry["credential_fingerprint"] = fingerprint

        self._write_entry(entry)

    def get_stats(self) -> dict:
        """Get logger statistics."""
        return {
            "requests_total": self.requests_total,
            "requests_quieted": self.requests_quieted,
            "responses_total": self.responses_total,
            "blocks_total": self.blocks_total,
            "log_path": str(self.log_path) if self.log_path else None,
        }


# mitmproxy addon instance
addons = [RequestLogger()]
