#!/usr/bin/env python3
"""
Send push notifications when SafeYolo blocks credentials.

Usage:
    export NTFY_TOPIC=https://ntfy.sh/my-safeyolo-alerts
    python contrib/notifiers/notify.py

For approval buttons, also run listener.py in another terminal.
"""

import json
import os
import time
from pathlib import Path

import httpx

# Configuration from environment
LOG_PATH = Path(os.getenv("SAFEYOLO_LOG", "./safeyolo/logs/safeyolo.jsonl"))
NTFY_TOPIC = os.getenv("NTFY_TOPIC", "")
NTFY_SERVER = os.getenv("NTFY_SERVER", "https://ntfy.sh")
CALLBACK_TOPIC = os.getenv("NTFY_CALLBACK_TOPIC", "")


def tail_jsonl(path: Path):
    """Tail a JSONL file, yielding new lines as they appear."""
    with open(path) as f:
        f.seek(0, 2)  # Start at end
        while True:
            line = f.readline()
            if line:
                yield json.loads(line)
            else:
                time.sleep(0.1)


def send_notification(event: dict):
    """Send notification for a credential block event."""
    data = event.get("data", {})
    rule = data.get("rule", "unknown")
    host = data.get("host", "unknown")
    reason = data.get("reason", "blocked")
    fingerprint = data.get("fingerprint", "")
    project = data.get("project_id", "default")

    title = f"Credential Blocked: {rule}"
    message = f"{rule} -> {host}\nReason: {reason}"

    payload = {
        "topic": NTFY_TOPIC.split("/")[-1],
        "title": title,
        "message": message,
        "priority": 4 if reason == "destination_mismatch" else 3,
        "tags": ["warning"],
    }

    # Add approve/deny buttons if we have callback topic and fingerprint
    if CALLBACK_TOPIC and fingerprint:
        callback_url = f"{NTFY_SERVER}/{CALLBACK_TOPIC}"
        approval_data = f"{fingerprint}|{host}|{project}"
        payload["actions"] = [
            {"action": "http", "label": "Approve", "url": callback_url,
             "method": "POST", "body": f"approve:{approval_data}"},
            {"action": "http", "label": "Deny", "url": callback_url,
             "method": "POST", "body": f"deny:{approval_data}", "clear": True},
        ]

    resp = httpx.post(NTFY_TOPIC, json=payload, timeout=10.0)
    print(f"Sent: {title} ({resp.status_code})")


def main():
    if not NTFY_TOPIC:
        print("Set NTFY_TOPIC environment variable")
        return

    if not LOG_PATH.exists():
        print(f"Log file not found: {LOG_PATH}")
        return

    print(f"Watching: {LOG_PATH}")
    print(f"Sending to: {NTFY_TOPIC}")
    if CALLBACK_TOPIC:
        print(f"Callback topic: {CALLBACK_TOPIC}")
    print()

    for event in tail_jsonl(LOG_PATH):
        if event.get("event") == "security.credential":
            if event.get("data", {}).get("decision") == "block":
                send_notification(event)


if __name__ == "__main__":
    main()
