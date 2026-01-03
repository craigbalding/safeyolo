#!/usr/bin/env python3
"""
Ntfy approval listener for SafeYolo.

Subscribes to the ntfy topic and processes approval/deny responses
from mobile notifications, then calls the local admin API.

Usage:
    python3 ntfy_approval_listener.py [--admin-url URL] [--topic TOPIC]

Environment variables:
    SAFEYOLO_ADMIN_URL - Admin API URL (default: http://localhost:9090)
    NTFY_TOPIC - Ntfy topic (default: read from data/ntfy_topic)

The listener handles messages in format:
    approve:{token}  - Approve the pending request
    deny:{token}     - Deny the pending request
"""

import argparse
import json
import os
import signal
import sys
from datetime import datetime
from pathlib import Path

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

# Buffer limit to prevent memory issues
MAX_BUFFER_SIZE = 1024 * 1024  # 1MB

# Default paths - works both in container (/app) and local dev
# Check for container path first, fall back to relative
if Path("/app/data").exists():
    DATA_DIR = Path("/app/data")
    LOG_DIR = Path("/app/logs")
else:
    DATA_DIR = Path(__file__).parent.parent / "data"
    LOG_DIR = Path(__file__).parent.parent / "logs"


def log(log_file: Path, msg: str) -> None:
    """Append timestamped message to log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{timestamp} [approval-listener] {msg}"
    print(line, flush=True)
    try:
        with open(log_file, "a") as f:
            f.write(f"{line}\n")
    except Exception:
        pass


def get_topic(topic_arg: str | None) -> str:
    """Get ntfy topic from arg, env, or file."""
    if topic_arg:
        return topic_arg

    if env_topic := os.environ.get("NTFY_TOPIC"):
        return env_topic

    topic_file = DATA_DIR / "ntfy_topic"
    if topic_file.exists():
        return topic_file.read_text().strip()

    raise ValueError(
        "No ntfy topic configured. Set NTFY_TOPIC env var, "
        "pass --topic, or ensure data/ntfy_topic exists."
    )


def handle_approval(
    action: str, token: str, admin_url: str, log_file: Path
) -> bool:
    """Call admin API to approve or deny a request."""
    if action not in ("approve", "deny"):
        log(log_file, f"Unknown action: {action}")
        return False

    url = f"{admin_url}/admin/{action}/{token}"
    log(log_file, f"Calling: POST {url}")

    try:
        response = httpx.post(url, timeout=10.0)
        if response.status_code == 200:
            result = response.json()
            log(log_file, f"Success: {action} {token[:8]}... -> {result.get('message', 'OK')}")
            return True
        else:
            log(log_file, f"Failed: {response.status_code} - {response.text[:200]}")
            return False
    except Exception as e:
        log(log_file, f"Error calling admin API: {type(e).__name__}: {e}")
        return False


def parse_message(msg: str) -> tuple[str, str] | None:
    """Parse approval message format.

    Expected formats:
        approve:{token}
        deny:{token}

    Returns:
        (action, token) tuple or None if not an approval message
    """
    msg = msg.strip()

    # Handle format: action:token
    if ":" in msg:
        parts = msg.split(":", 1)
        if len(parts) == 2:
            action, token = parts[0].lower(), parts[1]
            if action in ("approve", "deny") and len(token) > 10:
                return action, token

    return None


def listen(
    topic: str, admin_url: str, log_file: Path, server: str = "https://ntfy.sh"
) -> None:
    """Listen to ntfy JSON stream and handle approval messages."""
    url = f"{server}/{topic}/json"
    log(log_file, f"Connecting to: {url}")

    # ntfy sends keepalives every ~30s. Timeout at 90s to detect dead connections.
    with httpx.Client(timeout=httpx.Timeout(90.0, connect=10.0)) as client:
        with client.stream("GET", url) as resp:
            log(log_file, f"Connected, status: {resp.status_code}")
            buffer = b""

            for chunk in resp.iter_raw():
                buffer += chunk

                # Prevent unbounded buffer growth
                if len(buffer) > MAX_BUFFER_SIZE:
                    log(log_file, "Buffer overflow, resetting")
                    buffer = b""
                    continue

                # Process complete lines
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
                    if not msg:
                        continue

                    log(log_file, f"Received: {msg[:100]}")

                    # Parse approval/deny message
                    parsed = parse_message(msg)
                    if parsed:
                        action, token = parsed
                        handle_approval(action, token, admin_url, log_file)
                    else:
                        log(log_file, f"Ignoring non-approval message")


@retry(
    stop=stop_after_attempt(None),  # Retry forever
    wait=wait_exponential(multiplier=1, min=5, max=300),  # 5s -> 5min max
    retry=retry_if_exception_type(
        (httpx.HTTPError, httpx.StreamError, httpx.ReadTimeout, ConnectionError, OSError)
    ),
)
def listen_with_backoff(
    topic: str, admin_url: str, log_file: Path, server: str = "https://ntfy.sh"
) -> None:
    """Wrapper that adds exponential backoff to listen()."""
    try:
        listen(topic, admin_url, log_file, server)
    except Exception as e:
        log(log_file, f"Connection error: {type(e).__name__}: {e}")
        raise


def main():
    parser = argparse.ArgumentParser(
        description="Listen for SafeYolo approval responses via ntfy"
    )
    parser.add_argument(
        "--admin-url",
        default=os.environ.get("SAFEYOLO_ADMIN_URL", "http://localhost:9090"),
        help="SafeYolo admin API URL (default: http://localhost:9090)",
    )
    parser.add_argument(
        "--topic",
        default=None,
        help="Ntfy topic (default: from NTFY_TOPIC env or data/ntfy_topic)",
    )
    parser.add_argument(
        "--server",
        default="https://ntfy.sh",
        help="Ntfy server URL (default: https://ntfy.sh)",
    )
    args = parser.parse_args()

    # Ensure log directory exists
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / "approval_listener.log"

    # Get topic
    try:
        topic = get_topic(args.topic)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    log(log_file, f"Starting approval listener")
    log(log_file, f"Topic: {topic}")
    log(log_file, f"Admin URL: {args.admin_url}")

    # Handle SIGTERM and SIGINT gracefully
    def shutdown(signum, frame):
        log(log_file, f"Received signal {signum}, shutting down")
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    try:
        listen_with_backoff(topic, args.admin_url, log_file, args.server)
    except Exception as e:
        log(log_file, f"Fatal error: {type(e).__name__}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
