#!/usr/bin/env python3
"""
SafeYolo Notification Integration

Sends push notifications when credentials are blocked.
Example integration showing how to build on SafeYolo's JSONL event stream.

Supports:
  - ntfy.sh (self-hosted or public)
  - Pushcut (iOS)

Usage:
  # Set environment variables
  export SAFEYOLO_LOG=./safeyolo/logs/safeyolo.jsonl
  export NTFY_TOPIC=https://ntfy.sh/my-safeyolo-alerts

  # Run
  python contrib/notifiers/notify.py

  # Or with Pushcut
  export PUSHCUT_WEBHOOK=https://api.pushcut.io/xxx/notifications/SafeYolo
  python contrib/notifiers/notify.py

Configuration:
  SAFEYOLO_LOG      - Path to JSONL log file (default: ./safeyolo/logs/safeyolo.jsonl)
  NTFY_TOPIC        - ntfy topic URL (e.g., https://ntfy.sh/my-topic)
  NTFY_TOKEN        - ntfy access token (optional, for private topics)
  PUSHCUT_WEBHOOK   - Pushcut webhook URL

Integration Pattern:
  This script demonstrates the standard SafeYolo integration pattern:
  1. Tail the JSONL log file
  2. Parse each event as JSON
  3. Filter for events you care about
  4. Take action (send notification, update dashboard, etc.)

  See DEVELOPERS.md for event format documentation.
"""

import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import httpx

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

@dataclass
class Config:
    """Notification configuration from environment."""
    log_path: Path
    ntfy_topic: str | None
    ntfy_token: str | None
    pushcut_webhook: str | None

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            log_path=Path(os.getenv("SAFEYOLO_LOG", "./safeyolo/logs/safeyolo.jsonl")),
            ntfy_topic=os.getenv("NTFY_TOPIC"),
            ntfy_token=os.getenv("NTFY_TOKEN"),
            pushcut_webhook=os.getenv("PUSHCUT_WEBHOOK"),
        )

    def validate(self) -> list[str]:
        """Return list of validation errors."""
        errors = []
        if not self.log_path.exists():
            errors.append(f"Log file not found: {self.log_path}")
        if not self.ntfy_topic and not self.pushcut_webhook:
            errors.append("No notification backend configured (set NTFY_TOPIC or PUSHCUT_WEBHOOK)")
        return errors


# -----------------------------------------------------------------------------
# Notification Backends (pluggable pattern)
# -----------------------------------------------------------------------------

class NotificationBackend(Protocol):
    """Protocol for notification backends."""
    def send(self, title: str, message: str, priority: str = "default") -> bool:
        """Send notification. Returns True on success."""
        ...


class NtfyBackend:
    """ntfy.sh notification backend."""

    def __init__(self, topic: str, token: str | None = None):
        self.topic = topic
        self.token = token
        self.client = httpx.Client(timeout=10.0)

    def send(self, title: str, message: str, priority: str = "default") -> bool:
        headers = {"Title": title, "Priority": priority}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            resp = self.client.post(self.topic, content=message.encode(), headers=headers)
            resp.raise_for_status()
            return True
        except httpx.HTTPError as e:
            logging.error(f"ntfy send failed: {type(e).__name__}: {e}")
            return False


class PushcutBackend:
    """Pushcut notification backend (iOS)."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self.client = httpx.Client(timeout=10.0)

    def send(self, title: str, message: str, priority: str = "default") -> bool:
        payload = {
            "title": title,
            "text": message,
        }
        # Pushcut doesn't have priority, but we could map to different webhooks

        try:
            resp = self.client.post(self.webhook_url, json=payload)
            resp.raise_for_status()
            return True
        except httpx.HTTPError as e:
            logging.error(f"Pushcut send failed: {type(e).__name__}: {e}")
            return False


# -----------------------------------------------------------------------------
# Event Processing
# -----------------------------------------------------------------------------

def format_block_notification(event: dict) -> tuple[str, str, str]:
    """
    Format a credential block event into notification parts.

    Returns: (title, message, priority)
    """
    data = event.get("data", {})

    rule = data.get("rule", "unknown")
    host = data.get("host", "unknown")
    reason = data.get("reason", "blocked")
    fingerprint = data.get("fingerprint", "")[:12]

    title = f"Credential Blocked: {rule}"
    message = f"{rule} credential blocked from reaching {host}\nReason: {reason}\nFingerprint: {fingerprint}..."

    # High priority for destination mismatches (likely typo/attack)
    priority = "high" if reason == "destination_mismatch" else "default"

    return title, message, priority


def should_notify(event: dict) -> bool:
    """Determine if an event should trigger a notification."""
    # Only notify on credential blocks
    if event.get("event") != "security.credential":
        return False

    data = event.get("data", {})
    decision = data.get("decision")

    # Notify on blocks, not warnings or allows
    return decision == "block"


# -----------------------------------------------------------------------------
# Log Tailing
# -----------------------------------------------------------------------------

def tail_jsonl(path: Path):
    """
    Tail a JSONL file, yielding new events as they appear.

    This is the core integration pattern - tail the log and react to events.
    """
    with open(path) as f:
        # Start at end of file (only new events)
        f.seek(0, 2)

        while True:
            line = f.readline()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as e:
                    logging.warning(f"Failed to parse JSONL line: {e}")
            else:
                # No new data, wait briefly
                time.sleep(0.1)


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


def build_backends(config: Config) -> list[NotificationBackend]:
    """Build notification backends from config."""
    backends = []

    if config.ntfy_topic:
        backends.append(NtfyBackend(config.ntfy_topic, config.ntfy_token))
        logging.info(f"Configured ntfy backend: {config.ntfy_topic}")

    if config.pushcut_webhook:
        backends.append(PushcutBackend(config.pushcut_webhook))
        logging.info("Configured Pushcut backend")

    return backends


def main():
    setup_logging()

    config = Config.from_env()
    errors = config.validate()
    if errors:
        for error in errors:
            logging.error(error)
        sys.exit(1)

    backends = build_backends(config)

    logging.info(f"Watching: {config.log_path}")
    logging.info("Waiting for credential block events...")

    for event in tail_jsonl(config.log_path):
        if should_notify(event):
            title, message, priority = format_block_notification(event)

            logging.info(f"Sending notification: {title}")
            for backend in backends:
                backend.send(title, message, priority)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Shutting down")
        sys.exit(0)
