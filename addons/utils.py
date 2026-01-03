"""
utils.py - Shared utilities for SafeYolo addons

Functional helpers to reduce duplication across addons.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from mitmproxy import http

# Default audit log path - can be overridden via environment
AUDIT_LOG_PATH = Path(os.environ.get("SAFEYOLO_LOG_PATH", "/app/logs/safeyolo.jsonl"))


def write_jsonl(
    path: Optional[Path],
    event: str,
    logger: logging.Logger,
    **data,
) -> None:
    """
    Write a JSONL log entry.

    No-op if path is None. Handles directory creation and errors gracefully.

    Args:
        path: Path to JSONL file, or None to skip
        event: Event type (e.g., "credential_violation", "rate_limited")
        logger: Logger instance for error reporting
        **data: Additional fields to include in the log entry
    """
    if not path:
        return

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **data,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        logger.error(f"Log write failed: {type(e).__name__}: {e}")


def write_audit_event(event: str, **data) -> None:
    """
    Write an operational/audit event to the central JSONL log.

    Use this for events that should be in the audit trail:
    - Config reloads
    - State changes (circuit open/close)
    - Admin actions (approve/deny)
    - Startup/shutdown events

    Args:
        event: Event type (e.g., "config_reload", "circuit_open", "approval")
        **data: Additional fields (addon, config, error, etc.)

    Example:
        write_audit_event("config_reload", addon="request-logger", config="quiet_hosts", rules=2)
        write_audit_event("config_error", addon="rate-limiter", error="Invalid YAML")
    """
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **data,
    }
    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        # Fallback to stderr if log write fails
        print(f"[safeyolo] Audit log write failed: {type(e).__name__}: {e}", file=sys.stderr)
        print(f"[safeyolo] Event: {json.dumps(entry)}", file=sys.stderr)


def make_block_response(
    status: int,
    body: dict,
    addon_name: str,
    extra_headers: Optional[dict] = None,
) -> http.Response:
    """
    Create a standard JSON block response.

    All block responses include X-Blocked-By header for chain coordination.

    Args:
        status: HTTP status code (403, 429, 503, etc.)
        body: Response body as dict (will be JSON-encoded)
        addon_name: Name of blocking addon (for X-Blocked-By header)
        extra_headers: Additional headers to include

    Returns:
        mitmproxy http.Response
    """
    headers = {
        "Content-Type": "application/json",
        "X-Blocked-By": addon_name,
    }
    if extra_headers:
        headers.update(extra_headers)

    return http.Response.make(
        status,
        json.dumps(body).encode(),
        headers,
    )
