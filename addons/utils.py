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

import hashlib
import hmac
import json
import logging
import math
import os
import secrets
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

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


# =============================================================================
# Background Task Utilities
# =============================================================================

class BackgroundWorker:
    """Periodic background task runner.

    Runs a function at regular intervals in a daemon thread.
    Handles errors gracefully and supports clean shutdown.

    Example:
        def save_state():
            with open("state.json", "w") as f:
                json.dump(current_state, f)

        worker = BackgroundWorker(save_state, interval_sec=10.0, name="state-saver")
        worker.start()
        # ... later ...
        worker.stop()
    """

    def __init__(self, work_fn: Callable[[], None], interval_sec: float, name: str):
        """Initialize background worker.

        Args:
            work_fn: Function to call periodically (no arguments)
            interval_sec: Seconds between calls
            name: Thread name for debugging
        """
        self._work_fn = work_fn
        self._interval = interval_sec
        self._name = name
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> None:
        """Start the background worker thread."""
        if self._thread and self._thread.is_alive():
            return

        def loop():
            while not self._stop.wait(timeout=self._interval):
                try:
                    self._work_fn()
                except Exception as e:
                    _log.error(f"{self._name} error: {type(e).__name__}: {e}")

        self._stop.clear()
        self._thread = threading.Thread(target=loop, daemon=True, name=self._name)
        self._thread.start()
        _log.debug(f"Started background worker: {self._name}")

    def stop(self, timeout: float = 2.0) -> None:
        """Stop the background worker thread.

        Args:
            timeout: Seconds to wait for thread to finish
        """
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                _log.warning(f"{self._name} didn't stop within {timeout}s")
            self._thread = None
        _log.debug(f"Stopped background worker: {self._name}")


# =============================================================================
# Secret Detection Utilities
# =============================================================================

def calculate_shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string.

    Higher entropy suggests more randomness (potential secret).
    Typical thresholds: <3.0 low, 3.0-4.0 medium, >4.0 high.

    Args:
        s: Input string

    Returns:
        Shannon entropy in bits per character
    """
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def looks_like_secret(value: str, entropy_config: Optional[dict] = None) -> bool:
    """Check if value looks like a secret based on entropy heuristics.

    Uses length, character diversity, and Shannon entropy to detect
    potential secrets without pattern matching.

    Args:
        value: String to analyze
        entropy_config: Optional config dict with keys:
            - min_length: Minimum string length (default: 20)
            - min_charset_diversity: Unique chars / length ratio (default: 0.5)
            - min_shannon_entropy: Minimum entropy bits (default: 3.5)

    Returns:
        True if value appears to be a high-entropy secret
    """
    if entropy_config is None:
        entropy_config = {}

    min_length = entropy_config.get("min_length", 20)
    min_diversity = entropy_config.get("min_charset_diversity", 0.5)
    min_entropy = entropy_config.get("min_shannon_entropy", 3.5)

    if len(value) < min_length:
        return False

    unique_chars = len(set(value))
    diversity = unique_chars / len(value)
    if diversity < min_diversity:
        return False

    entropy = calculate_shannon_entropy(value)
    return entropy >= min_entropy


# =============================================================================
# HMAC Fingerprinting
# =============================================================================

def load_hmac_secret(secret_path: Path, env_var: str = "CREDGUARD_HMAC_SECRET") -> bytes:
    """Load or generate HMAC secret for sensitive data fingerprinting.

    Checks environment variable first, then file, then generates new secret.
    Generated secrets are saved with 0600 permissions.

    Args:
        secret_path: Path to secret file
        env_var: Environment variable name to check first

    Returns:
        HMAC secret as bytes
    """
    env_secret = os.environ.get(env_var)
    if env_secret:
        return env_secret.encode()

    if secret_path.exists():
        return secret_path.read_bytes().strip()

    # Generate new secret
    secret = secrets.token_hex(32).encode()
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    secret_path.write_bytes(secret)
    secret_path.chmod(0o600)
    _log.info(f"Generated new HMAC secret at {secret_path}")
    return secret


def hmac_fingerprint(value: str, secret: bytes, prefix_len: int = 16) -> str:
    """Generate HMAC fingerprint for sensitive data (never log raw values).

    Creates a truncated HMAC-SHA256 hash for logging and policy matching
    without exposing the actual sensitive value.

    Args:
        value: Sensitive string to fingerprint
        secret: HMAC secret key
        prefix_len: Length of hex digest to return (default: 16)

    Returns:
        Truncated hex digest (e.g., "a1b2c3d4e5f67890")
    """
    h = hmac.new(secret, value.encode(), hashlib.sha256)
    return h.hexdigest()[:prefix_len]
