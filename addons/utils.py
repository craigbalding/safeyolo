"""
utils.py - Shared utilities for SafeYolo addons

Functional helpers to reduce duplication across addons.

Event Taxonomy:
    traffic.request      - Incoming request
    traffic.response     - Response (normal or blocked)

    security.credential  - Credential detection decision
    security.injection   - Injection detection decision
    security.yara        - YARA match decision
    security.pattern     - Pattern match decision
    security.ratelimit   - Rate limit decision
    security.circuit     - Circuit breaker decision

    ops.startup          - Addon startup
    ops.config_reload    - Config file changed
    ops.config_error     - Config load failed

    admin.approve        - Credential approved
    admin.deny           - Credential denied
    admin.mode_change    - Mode toggled
    admin.auth_failure   - Failed auth attempt
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml
from mitmproxy import http

# Default audit log path - can be overridden via environment
AUDIT_LOG_PATH = Path(os.environ.get("SAFEYOLO_LOG_PATH", "/app/logs/safeyolo.jsonl"))

# Valid event prefixes for taxonomy validation
VALID_EVENT_PREFIXES = ("traffic.", "security.", "ops.", "admin.")

# Module-level logger for write_event errors
_log = logging.getLogger("safeyolo.utils")


def write_event(event: str, **data) -> None:
    """
    Write an event to the central JSONL audit log.

    Primary logging function for all SafeYolo events. Writes to AUDIT_LOG_PATH.

    Args:
        event: Event type using taxonomy (e.g., "security.credential", "admin.approve")
               Must start with: traffic., security., ops., or admin.
        **data: Event-specific fields. Common fields:
            - request_id: Correlation ID from flow.metadata
            - addon: Name of the addon emitting the event
            - decision: For security events - "allow", "block", or "warn"

    Example:
        write_event("security.credential",
            request_id="req-abc123",
            addon="credential-guard",
            decision="block",
            rule="openai",
            host="httpbin.org",
            reason="destination_mismatch"
        )
    """
    # Validate event taxonomy (warn but don't fail)
    if not event.startswith(VALID_EVENT_PREFIXES):
        _log.warning(f"Event '{event}' doesn't match taxonomy (expected: traffic.*, security.*, ops.*, admin.*)")

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
        print(f"[safeyolo] Event log write failed: {type(e).__name__}: {e}", file=sys.stderr)
        print(f"[safeyolo] Event: {json.dumps(entry)}", file=sys.stderr)


def write_audit_event(event: str, **data) -> None:
    """
    Write an operational/audit event to the central JSONL log.

    DEPRECATED: Use write_event() with taxonomy prefix instead.
    This function is kept for backward compatibility but auto-prefixes
    events with "ops." if they don't already have a taxonomy prefix.

    Args:
        event: Event type (e.g., "config_reload" -> "ops.config_reload")
        **data: Additional fields (addon, config, error, etc.)

    Example:
        write_audit_event("config_reload", addon="request-logger", config="quiet_hosts", rules=2)
        # Writes: {"event": "ops.config_reload", ...}
    """
    # Auto-prefix with ops. if no taxonomy prefix
    if not event.startswith(VALID_EVENT_PREFIXES):
        event = f"ops.{event}"

    write_event(event, **data)


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


# =============================================================================
# Config & File Utilities
# =============================================================================

def load_config_file(path: Path, default: Optional[dict] = None) -> dict:
    """Load YAML or JSON config file.

    Returns default (or {}) if file missing or invalid.
    Logs errors but doesn't raise.

    Args:
        path: Path to config file (.yaml, .yml, or .json)
        default: Default value if file missing/invalid

    Returns:
        Parsed config dict, or default
    """
    if not path.exists():
        return default if default is not None else {}
    try:
        content = path.read_text()
        if path.suffix in (".yaml", ".yml"):
            return yaml.safe_load(content) or {}
        return json.loads(content)
    except Exception as e:
        _log.error(f"Failed to load {path}: {type(e).__name__}: {e}")
        return default if default is not None else {}


def atomic_write_json(path: Path, data: Any) -> None:
    """Atomically write JSON via temp file rename.

    Args:
        path: Target file path
        data: JSON-serializable data
    """
    tmp = path.with_suffix('.tmp')
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2)
    tmp.rename(path)


# =============================================================================
# Flow & Context Utilities
# =============================================================================

def get_client_ip(flow: http.HTTPFlow) -> str:
    """Get client IP from flow, or 'unknown'.

    Args:
        flow: mitmproxy HTTP flow

    Returns:
        Client IP address string, or 'unknown' if unavailable
    """
    if flow.client_conn and flow.client_conn.peername:
        return flow.client_conn.peername[0]
    return "unknown"


def get_option_safe(name: str, default: Any = True) -> Any:
    """Get mitmproxy option, return default if unavailable.

    Safely handles cases where ctx.options is not available
    (e.g., in tests or before mitmproxy initialization).

    Args:
        name: Option name (e.g., 'ratelimit_enabled')
        default: Default value if option unavailable

    Returns:
        Option value, or default
    """
    try:
        from mitmproxy import ctx
        return getattr(ctx.options, name)
    except AttributeError:
        return default
