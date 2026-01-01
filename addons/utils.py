"""
utils.py - Shared utilities for SafeYolo addons

Functional helpers to reduce duplication across addons.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from mitmproxy import http


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
