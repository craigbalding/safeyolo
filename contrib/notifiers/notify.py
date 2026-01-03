#!/usr/bin/env python3
"""
SafeYolo Notification Integration with Approval Buttons

Sends push notifications when credentials are blocked, with action buttons
to approve or deny directly from your phone.

Full flow:
  1. SafeYolo blocks credential -> JSONL event
  2. This script sends notification with [Approve] [Deny] buttons
  3. User taps button -> POST to ntfy callback topic
  4. listener.py receives callback -> calls admin API
  5. Credential approved, subsequent requests pass

Supports:
  - ntfy.sh (self-hosted or public) - Android, iOS, web
  - Pushcut (iOS) - with background URL actions

Usage:
  # Set environment variables
  export SAFEYOLO_LOG=./safeyolo/logs/safeyolo.jsonl
  export NTFY_TOPIC=https://ntfy.sh/my-safeyolo-alerts
  export NTFY_CALLBACK_TOPIC=safeyolo-callbacks-$(openssl rand -hex 8)

  # Run notifier (and listener in separate terminal)
  python contrib/notifiers/notify.py
  python contrib/notifiers/listener.py

Configuration:
  SAFEYOLO_LOG         - Path to JSONL log file (default: ./safeyolo/logs/safeyolo.jsonl)
  NTFY_TOPIC           - ntfy topic URL for notifications
  NTFY_TOKEN           - ntfy access token (optional, for private topics)
  NTFY_CALLBACK_TOPIC  - ntfy topic for button callbacks (auto-generated if not set)
  NTFY_SERVER          - ntfy server (default: https://ntfy.sh)
  PUSHCUT_WEBHOOK      - Pushcut webhook URL (uses ntfy for callbacks)

Integration Pattern:
  This script demonstrates the standard SafeYolo integration pattern:
  1. Tail the JSONL log file
  2. Parse each event as JSON
  3. Filter for events you care about
  4. Take action (send notification with approval buttons)

  See DEVELOPERS.md for event format documentation.
"""

import json
import logging
import os
import secrets
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
    ntfy_server: str
    ntfy_callback_topic: str
    pushcut_webhook: str | None

    @classmethod
    def from_env(cls) -> "Config":
        # Auto-generate callback topic if not set (persist to file)
        callback_topic = os.getenv("NTFY_CALLBACK_TOPIC")
        if not callback_topic:
            callback_topic = cls._get_or_create_callback_topic()

        return cls(
            log_path=Path(os.getenv("SAFEYOLO_LOG", "./safeyolo/logs/safeyolo.jsonl")),
            ntfy_topic=os.getenv("NTFY_TOPIC"),
            ntfy_token=os.getenv("NTFY_TOKEN"),
            ntfy_server=os.getenv("NTFY_SERVER", "https://ntfy.sh"),
            ntfy_callback_topic=callback_topic,
            pushcut_webhook=os.getenv("PUSHCUT_WEBHOOK"),
        )

    @staticmethod
    def _get_or_create_callback_topic() -> str:
        """Get or create persistent callback topic."""
        topic_file = Path("./safeyolo/data/ntfy_callback_topic")
        if topic_file.exists():
            return topic_file.read_text().strip()

        # Generate new topic
        topic = f"safeyolo-cb-{secrets.token_urlsafe(16)}"
        topic_file.parent.mkdir(parents=True, exist_ok=True)
        topic_file.write_text(topic)
        logging.info(f"Generated callback topic: {topic}")
        return topic

    def validate(self) -> list[str]:
        """Return list of validation errors."""
        errors = []
        if not self.log_path.exists():
            errors.append(f"Log file not found: {self.log_path}")
        if not self.ntfy_topic and not self.pushcut_webhook:
            errors.append("No notification backend configured (set NTFY_TOPIC or PUSHCUT_WEBHOOK)")
        return errors

    @property
    def callback_url(self) -> str:
        """Full URL for button callbacks."""
        return f"{self.ntfy_server}/{self.ntfy_callback_topic}"


# -----------------------------------------------------------------------------
# Notification Backends (pluggable pattern)
# -----------------------------------------------------------------------------

class NotificationBackend(Protocol):
    """Protocol for notification backends."""
    def send(
        self,
        title: str,
        message: str,
        priority: str,
        approval_payload: str | None,
        callback_url: str | None,
    ) -> bool:
        """Send notification. Returns True on success."""
        ...


class NtfyBackend:
    """ntfy.sh notification backend with action buttons."""

    def __init__(self, topic: str, token: str | None = None):
        self.topic = topic
        self.token = token
        self.client = httpx.Client(timeout=10.0)

    def send(
        self,
        title: str,
        message: str,
        priority: str = "default",
        approval_payload: str | None = None,
        callback_url: str | None = None,
    ) -> bool:
        headers = {"Title": title, "Priority": priority}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        # Build payload
        payload: dict = {
            "topic": self.topic.split("/")[-1],  # Extract topic from URL
            "title": title,
            "message": message,
            "priority": 4 if priority == "high" else 3,
            "tags": ["warning", "lock"],
        }

        # Add action buttons if we have approval payload
        if approval_payload and callback_url:
            payload["actions"] = [
                {
                    "action": "http",
                    "label": "Approve",
                    "url": callback_url,
                    "method": "POST",
                    "body": f"approve:{approval_payload}",
                },
                {
                    "action": "http",
                    "label": "Deny",
                    "url": callback_url,
                    "method": "POST",
                    "body": f"deny:{approval_payload}",
                    "clear": True,
                },
            ]

        try:
            resp = self.client.post(self.topic, json=payload)
            resp.raise_for_status()
            return True
        except httpx.HTTPError as e:
            logging.error(f"ntfy send failed: {type(e).__name__}: {e}")
            return False


class PushcutBackend:
    """Pushcut notification backend (iOS) with action buttons.

    Pushcut buttons use urlBackgroundOptions to POST to ntfy callback topic.
    """

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self.client = httpx.Client(timeout=10.0)

    def send(
        self,
        title: str,
        message: str,
        priority: str = "default",
        approval_payload: str | None = None,
        callback_url: str | None = None,
    ) -> bool:
        payload: dict = {
            "title": title,
            "text": message,
        }

        # Add action buttons if we have approval payload
        if approval_payload and callback_url:
            payload["actions"] = [
                {
                    "name": "Approve",
                    "url": callback_url,
                    "urlBackgroundOptions": {
                        "httpMethod": "POST",
                        "httpContentType": "text/plain",
                        "httpBody": f"approve:{approval_payload}",
                    },
                    "keepNotification": False,
                },
                {
                    "name": "Deny",
                    "url": callback_url,
                    "urlBackgroundOptions": {
                        "httpMethod": "POST",
                        "httpContentType": "text/plain",
                        "httpBody": f"deny:{approval_payload}",
                    },
                    "keepNotification": False,
                },
            ]

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

def format_block_notification(event: dict) -> tuple[str, str, str, str | None]:
    """
    Format a credential block event into notification parts.

    Returns: (title, message, priority, approval_payload)

    approval_payload format: {fingerprint}|{host}|{project}
    """
    data = event.get("data", {})

    rule = data.get("rule", "unknown")
    host = data.get("host", "unknown")
    reason = data.get("reason", "blocked")
    fingerprint = data.get("fingerprint", "")
    project = data.get("project_id", "default")

    # Format title based on reason
    if reason == "destination_mismatch":
        title = f"Wrong Destination: {rule}"
    elif reason == "unknown_credential":
        title = "Unknown Credential Detected"
    else:
        title = f"Credential Blocked: {rule}"

    # Format message
    message = f"{rule} -> {host}\nReason: {reason}"
    if fingerprint:
        message += f"\nFingerprint: {fingerprint[:16]}..."

    # High priority for destination mismatches (likely typo/attack)
    priority = "high" if reason == "destination_mismatch" else "default"

    # Build approval payload if we have fingerprint
    approval_payload = None
    if fingerprint:
        # Format: fingerprint|host|project
        # Listener will parse this to call admin API
        approval_payload = f"{fingerprint}|{host}|{project}"

    return title, message, priority, approval_payload


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
    logging.info(f"Callback topic: {config.ntfy_callback_topic}")
    logging.info("Waiting for credential block events...")
    logging.info("")
    logging.info("TIP: Run listener.py in another terminal to handle button callbacks")

    for event in tail_jsonl(config.log_path):
        if should_notify(event):
            title, message, priority, approval_payload = format_block_notification(event)

            logging.info(f"Sending notification: {title}")
            for backend in backends:
                backend.send(
                    title,
                    message,
                    priority,
                    approval_payload,
                    config.callback_url,
                )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Shutting down")
        sys.exit(0)
