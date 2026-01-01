"""
request_logger.py - Native mitmproxy addon for structured logging

Logs all requests/responses to JSONL for monitoring and debugging.
Captures metadata from other addons (e.g., blocked_by, credential_prefix).

Usage:
    mitmdump -s addons/request_logger.py --set safeyolo_log_path=/app/logs/safeyolo.jsonl
"""

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from mitmproxy import ctx, http

log = logging.getLogger("safeyolo.logger")


class RequestLogger:
    """
    Native mitmproxy addon for JSONL structured logging.

    Logs:
    - All requests with method, host, path, size
    - All responses with status, size, duration
    - Blocks with plugin, reason, credential info
    """

    name = "request-logger"

    def __init__(self):
        self.log_path: Optional[Path] = None
        self.requests_total = 0
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

        # Generate request ID
        request_id = f"req-{int(time.time() * 1000) % 1000000}"
        flow.metadata["request_id"] = request_id
        flow.metadata["start_time"] = time.time()

        parsed = urlparse(flow.request.pretty_url)

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": "request",
            "id": request_id,
            "method": flow.request.method,
            "host": parsed.netloc,
            "path": parsed.path,
            "size": len(flow.request.content or b""),
            "client": flow.client_conn.peername[0] if flow.client_conn.peername else None,
        }

        self._write_entry(entry)

    def response(self, flow: http.HTTPFlow):
        """Log response (or block)."""
        request_id = flow.metadata.get("request_id")
        start_time = flow.metadata.get("start_time")
        blocked_by = flow.metadata.get("blocked_by")

        if blocked_by:
            self.blocks_total += 1
            event_type = "block"
        else:
            self.responses_total += 1
            event_type = "response"

        duration_ms = None
        if start_time:
            duration_ms = round((time.time() - start_time) * 1000, 1)

        parsed = urlparse(flow.request.pretty_url)

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            "id": request_id,
            "host": parsed.netloc,
            "status": flow.response.status_code if flow.response else None,
            "size": len(flow.response.content or b"") if flow.response else 0,
            "ms": duration_ms,
        }

        # Add block details if applicable
        if blocked_by:
            entry["blocked_by"] = blocked_by
            entry["credential_prefix"] = flow.metadata.get("credential_prefix")
            entry["path"] = parsed.path

        self._write_entry(entry)

    def get_stats(self) -> dict:
        """Get logger statistics."""
        return {
            "requests_total": self.requests_total,
            "responses_total": self.responses_total,
            "blocks_total": self.blocks_total,
            "log_path": str(self.log_path) if self.log_path else None,
        }


# mitmproxy addon instance
addons = [RequestLogger()]
