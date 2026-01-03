#!/usr/bin/env python3
"""
Handle approval button callbacks from ntfy notifications.

Subscribes to ntfy topic, parses approve/deny messages,
and calls SafeYolo admin API to add approvals.

Usage:
    export NTFY_CALLBACK_TOPIC=my-callback-topic
    export SAFEYOLO_ADMIN_TOKEN=your-token
    python contrib/notifiers/listener.py
"""

import json
import os
import time

import httpx

# Configuration from environment
CALLBACK_TOPIC = os.getenv("NTFY_CALLBACK_TOPIC", "")
NTFY_SERVER = os.getenv("NTFY_SERVER", "https://ntfy.sh")
ADMIN_URL = os.getenv("SAFEYOLO_ADMIN_URL", "http://localhost:9090")
ADMIN_TOKEN = os.getenv("SAFEYOLO_ADMIN_TOKEN", "")


def parse_message(msg: str):
    """Parse 'approve:fingerprint|host|project' format."""
    if ":" not in msg:
        return None

    action, payload = msg.split(":", 1)
    action = action.lower()

    if action not in ("approve", "deny"):
        return None

    parts = payload.split("|")
    if len(parts) != 3:
        return None

    return {"action": action, "fingerprint": parts[0], "host": parts[1], "project": parts[2]}


def call_admin_api(fingerprint: str, host: str, project: str):
    """Add approval via admin API."""
    url = f"{ADMIN_URL}/admin/policy/{project}/approve"
    resp = httpx.post(
        url,
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        json={"token_hmac": fingerprint, "hosts": [host], "paths": ["/**"]},
        timeout=10.0,
    )
    if resp.status_code == 200:
        print(f"Approved: {fingerprint[:16]}... -> {host}")
    else:
        print(f"Failed: {resp.status_code} - {resp.text[:100]}")


def listen():
    """Subscribe to ntfy and process messages."""
    url = f"{NTFY_SERVER}/{CALLBACK_TOPIC}/json"
    print(f"Listening: {url}")

    with httpx.Client(timeout=httpx.Timeout(90.0, connect=10.0)) as client:
        with client.stream("GET", url) as resp:
            buffer = b""
            for chunk in resp.iter_raw():
                buffer += chunk

                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    line = line.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue

                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    if data.get("event") != "message":
                        continue

                    msg = data.get("message", "")
                    parsed = parse_message(msg)

                    if parsed:
                        print(f"Received: {parsed['action']} {parsed['fingerprint'][:16]}...")
                        if parsed["action"] == "approve":
                            call_admin_api(parsed["fingerprint"], parsed["host"], parsed["project"])
                        else:
                            print(f"Denied: {parsed['fingerprint'][:16]}...")


def main():
    if not CALLBACK_TOPIC:
        print("Set NTFY_CALLBACK_TOPIC environment variable")
        return

    if not ADMIN_TOKEN:
        print("Set SAFEYOLO_ADMIN_TOKEN environment variable")
        return

    # Reconnect on failure
    while True:
        try:
            listen()
        except Exception as e:
            print(f"Connection error: {type(e).__name__}: {e}")
            print("Reconnecting in 5s...")
            time.sleep(5)


if __name__ == "__main__":
    main()
