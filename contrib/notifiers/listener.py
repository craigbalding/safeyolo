#!/usr/bin/env python3
"""
SafeYolo Approval Listener

Subscribes to ntfy callback topic and processes approve/deny responses
from mobile notification buttons, then calls the SafeYolo admin API.

Full flow:
  1. User taps [Approve] or [Deny] on notification
  2. Button POSTs to ntfy callback topic
  3. This listener receives the message
  4. Listener calls admin API to add/deny approval
  5. Subsequent requests with same credential pass through

Usage:
  # Use same callback topic as notify.py
  export NTFY_CALLBACK_TOPIC=safeyolo-cb-xxx  # or auto-read from file
  export SAFEYOLO_ADMIN_URL=http://localhost:9090
  export SAFEYOLO_ADMIN_TOKEN=your-admin-token

  python contrib/notifiers/listener.py

Configuration:
  NTFY_CALLBACK_TOPIC  - ntfy topic to subscribe to (auto-read from file if not set)
  NTFY_SERVER          - ntfy server (default: https://ntfy.sh)
  SAFEYOLO_ADMIN_URL   - Admin API URL (default: http://localhost:9090)
  SAFEYOLO_ADMIN_TOKEN - Admin API bearer token

Message format from buttons:
  approve:{fingerprint}|{host}|{project}
  deny:{fingerprint}|{host}|{project}
"""

import json
import logging
import os
import signal
import sys
from dataclasses import dataclass
from pathlib import Path

import httpx

# Buffer limit to prevent memory issues with streaming
MAX_BUFFER_SIZE = 1024 * 1024  # 1MB


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

@dataclass
class Config:
    """Listener configuration from environment."""
    callback_topic: str
    ntfy_server: str
    admin_url: str
    admin_token: str | None

    @classmethod
    def from_env(cls) -> "Config":
        callback_topic = os.getenv("NTFY_CALLBACK_TOPIC")
        if not callback_topic:
            callback_topic = cls._read_callback_topic()

        return cls(
            callback_topic=callback_topic,
            ntfy_server=os.getenv("NTFY_SERVER", "https://ntfy.sh"),
            admin_url=os.getenv("SAFEYOLO_ADMIN_URL", "http://localhost:9090"),
            admin_token=os.getenv("SAFEYOLO_ADMIN_TOKEN"),
        )

    @staticmethod
    def _read_callback_topic() -> str:
        """Read callback topic from persistent file."""
        topic_file = Path("./safeyolo/data/ntfy_callback_topic")
        if topic_file.exists():
            return topic_file.read_text().strip()
        raise ValueError(
            "No callback topic configured. Set NTFY_CALLBACK_TOPIC or run notify.py first "
            "to auto-generate one."
        )

    def validate(self) -> list[str]:
        """Return list of validation errors."""
        errors = []
        if not self.callback_topic:
            errors.append("No callback topic configured")
        if not self.admin_token:
            errors.append("SAFEYOLO_ADMIN_TOKEN not set")
        return errors

    @property
    def stream_url(self) -> str:
        """Full URL for ntfy JSON stream."""
        return f"{self.ntfy_server}/{self.callback_topic}/json"


# -----------------------------------------------------------------------------
# Message Parsing
# -----------------------------------------------------------------------------

@dataclass
class ApprovalMessage:
    """Parsed approval/deny message from button callback."""
    action: str  # "approve" or "deny"
    fingerprint: str
    host: str
    project: str


def parse_message(msg: str) -> ApprovalMessage | None:
    """
    Parse approval message from button callback.

    Expected format: {action}:{fingerprint}|{host}|{project}
    Example: approve:hmac:a1b2c3d4|api.example.com|default

    Returns ApprovalMessage or None if not a valid approval message.
    """
    msg = msg.strip()

    # Split action from payload
    if ":" not in msg:
        return None

    action, payload = msg.split(":", 1)
    action = action.lower()

    if action not in ("approve", "deny"):
        return None

    # Parse payload: fingerprint|host|project
    parts = payload.split("|")
    if len(parts) != 3:
        logging.warning(f"Invalid payload format: {payload}")
        return None

    fingerprint, host, project = parts

    if not fingerprint or not host:
        return None

    return ApprovalMessage(
        action=action,
        fingerprint=fingerprint,
        host=host,
        project=project or "default",
    )


# -----------------------------------------------------------------------------
# Admin API Client
# -----------------------------------------------------------------------------

class AdminAPIClient:
    """Client for SafeYolo admin API."""

    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.client = httpx.Client(timeout=10.0)

    def approve(self, fingerprint: str, host: str, project: str) -> bool:
        """Add approval rule via admin API."""
        url = f"{self.base_url}/admin/policy/{project}/approve"

        try:
            resp = self.client.post(
                url,
                headers={"Authorization": f"Bearer {self.token}"},
                json={
                    "token_hmac": fingerprint,
                    "hosts": [host],
                    "paths": ["/**"],
                },
            )

            if resp.status_code == 200:
                logging.info(f"Approved: {fingerprint[:16]}... -> {host} (project: {project})")
                return True
            else:
                logging.error(f"Approval failed: {resp.status_code} - {resp.text[:200]}")
                return False

        except httpx.HTTPError as e:
            logging.error(f"Admin API error: {type(e).__name__}: {e}")
            return False

    def deny(self, fingerprint: str, host: str, project: str) -> bool:
        """Log denial (no API action needed - credential stays blocked)."""
        logging.info(f"Denied: {fingerprint[:16]}... -> {host} (project: {project})")
        # No API call needed - leaving credential unapproved means it stays blocked
        return True


# -----------------------------------------------------------------------------
# Ntfy Stream Listener
# -----------------------------------------------------------------------------

def listen(config: Config, api: AdminAPIClient) -> None:
    """Subscribe to ntfy JSON stream and process approval messages."""
    logging.info(f"Connecting to: {config.stream_url}")

    # ntfy sends keepalives every ~30s. Timeout at 90s to detect dead connections.
    with httpx.Client(timeout=httpx.Timeout(90.0, connect=10.0)) as client:
        with client.stream("GET", config.stream_url) as resp:
            logging.info(f"Connected (status: {resp.status_code})")
            buffer = b""

            for chunk in resp.iter_raw():
                buffer += chunk

                # Prevent unbounded buffer growth
                if len(buffer) > MAX_BUFFER_SIZE:
                    logging.warning("Buffer overflow, resetting")
                    buffer = b""
                    continue

                # Process complete lines
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    line_str = line.decode("utf-8", errors="replace").strip()

                    if not line_str:
                        continue

                    try:
                        data = json.loads(line_str)
                    except json.JSONDecodeError:
                        continue

                    # Skip non-message events (open, keepalive)
                    if data.get("event") != "message":
                        continue

                    msg = data.get("message", "")
                    if not msg:
                        continue

                    logging.info(f"Received: {msg[:100]}")

                    # Parse and handle approval message
                    parsed = parse_message(msg)
                    if parsed:
                        if parsed.action == "approve":
                            api.approve(parsed.fingerprint, parsed.host, parsed.project)
                        else:
                            api.deny(parsed.fingerprint, parsed.host, parsed.project)
                    else:
                        logging.debug(f"Ignoring non-approval message: {msg[:50]}")


def listen_with_retry(config: Config, api: AdminAPIClient) -> None:
    """Listen with automatic reconnection on failure."""
    import time

    backoff = 5  # Start with 5 second backoff
    max_backoff = 300  # Max 5 minutes

    while True:
        try:
            listen(config, api)
        except (httpx.HTTPError, httpx.StreamError, ConnectionError, OSError) as e:
            logging.error(f"Connection error: {type(e).__name__}: {e}")
            logging.info(f"Reconnecting in {backoff}s...")
            time.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)
        except Exception as e:
            logging.error(f"Unexpected error: {type(e).__name__}: {e}")
            raise


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def setup_logging():
    """Configure logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main():
    setup_logging()

    try:
        config = Config.from_env()
    except ValueError as e:
        logging.error(str(e))
        sys.exit(1)

    errors = config.validate()
    if errors:
        for error in errors:
            logging.error(error)
        sys.exit(1)

    api = AdminAPIClient(config.admin_url, config.admin_token)

    logging.info(f"Listening for approvals on: {config.callback_topic}")
    logging.info(f"Admin API: {config.admin_url}")

    # Handle SIGTERM/SIGINT gracefully
    def shutdown(signum, frame):
        logging.info("Shutting down")
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    listen_with_retry(config, api)


if __name__ == "__main__":
    main()
