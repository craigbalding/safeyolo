#!/usr/bin/env python3
"""
Handle approval button callbacks from ntfy notifications.

Subscribes to ntfy topic, parses approve/deny messages,
and calls SafeYolo admin API to add approvals.

Usage:
    export NTFY_CALLBACK_TOPIC=my-callback-topic
    export SAFEYOLO_ADMIN_TOKEN=your-token
    python contrib/notifiers/listener.py

Requires: pip install httpx tenacity
"""

import json
import os
import signal
import sys
import time

import httpx
from tenacity import retry, retry_if_exception_type, wait_exponential

# Configuration from environment
CALLBACK_TOPIC = os.getenv("NTFY_CALLBACK_TOPIC", "")
NTFY_SERVER = os.getenv("NTFY_SERVER", "https://ntfy.sh")
ADMIN_URL = os.getenv("SAFEYOLO_ADMIN_URL", "http://localhost:9090")
ADMIN_TOKEN = os.getenv("SAFEYOLO_ADMIN_TOKEN", "")

# Limits
MAX_BUFFER = 1024 * 1024  # 1MB - prevent memory issues from malformed stream


def log(msg: str):
    """Print with timestamp."""
    ts = time.strftime("%H:%M:%S")
    print(f"{ts} {msg}", flush=True)


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
    try:
        resp = httpx.post(
            url,
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
            json={"token_hmac": fingerprint, "hosts": [host], "paths": ["/**"]},
            timeout=10.0,
        )
        if resp.status_code == 200:
            log(f"Approved: {fingerprint[:16]}... -> {host}")
        else:
            log(f"API error: {resp.status_code} - {resp.text[:100]}")
    except Exception as e:
        log(f"API call failed: {type(e).__name__}: {e}")


def listen():
    """Subscribe to ntfy and process messages."""
    url = f"{NTFY_SERVER}/{CALLBACK_TOPIC}/json"
    log(f"Connecting: {url}")

    with httpx.Client(timeout=httpx.Timeout(90.0, connect=10.0)) as client:
        with client.stream("GET", url) as resp:
            log(f"Connected (status {resp.status_code})")
            buffer = b""

            for chunk in resp.iter_raw():
                buffer += chunk

                # Prevent unbounded memory growth
                if len(buffer) > MAX_BUFFER:
                    log("Buffer overflow, resetting")
                    buffer = b""
                    continue

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
                        log(f"Received: {parsed['action']} {parsed['fingerprint'][:16]}...")
                        if parsed["action"] == "approve":
                            call_admin_api(parsed["fingerprint"], parsed["host"], parsed["project"])
                        else:
                            log("Denied (no action taken)")


@retry(
    wait=wait_exponential(multiplier=1, min=5, max=300),
    retry=retry_if_exception_type((httpx.HTTPError, httpx.StreamError, ConnectionError, OSError)),
    before_sleep=lambda retry_state: log(f"Reconnecting in {retry_state.next_action.sleep}s..."),
)
def listen_forever():
    """Listen with automatic reconnection on failure."""
    try:
        listen()
    except Exception as e:
        log(f"Connection error: {type(e).__name__}: {e}")
        raise


def main():
    if not CALLBACK_TOPIC:
        print("Set NTFY_CALLBACK_TOPIC environment variable")
        sys.exit(1)

    if not ADMIN_TOKEN:
        print("Set SAFEYOLO_ADMIN_TOKEN environment variable")
        sys.exit(1)

    # Graceful shutdown
    def shutdown(signum, frame):
        log("Shutting down")
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    log(f"Starting listener for topic: {CALLBACK_TOPIC}")
    listen_forever()


if __name__ == "__main__":
    main()
