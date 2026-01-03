#!/usr/bin/env python3
"""
Test approval notifications (Pushcut + ntfy).

Usage:
    python3 tests/test_ntfy_integration.py --generate-topic
    python3 tests/test_ntfy_integration.py
"""

import os
import secrets
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from addons.credential_guard import ApprovalNotifier


def generate_secure_topic():
    return f"safeyolo-{secrets.token_urlsafe(32)}"


def test_notifier_pushcut_only():
    """Pushcut-only config (most common use case)."""
    config = {
        "pushcut_url": "https://api.pushcut.io/xxx/notifications/Test",
        "callback_topic": "test-topic",
        "ntfy_enabled": False,
    }
    notifier = ApprovalNotifier(config)

    assert notifier.is_enabled()
    assert notifier.pushcut_url
    assert not notifier.ntfy_enabled
    print("Pushcut-only config")


def test_notifier_ntfy_only():
    """ntfy-only config (Android users)."""
    # Patch _get_pushcut_url to prevent reading from persistent file
    with patch.object(ApprovalNotifier, "_get_pushcut_url", return_value=None):
        config = {
            "ntfy_enabled": True,
            "callback_topic": "test-topic",
        }
        notifier = ApprovalNotifier(config)

        assert notifier.is_enabled()
        assert notifier.ntfy_enabled
        assert not notifier.pushcut_url
        print("ntfy-only config")


def test_notifier_both():
    """Both channels enabled."""
    config = {
        "pushcut_url": "https://api.pushcut.io/xxx/notifications/Test",
        "ntfy_enabled": True,
        "callback_topic": "test-topic",
    }
    notifier = ApprovalNotifier(config)

    assert notifier.is_enabled()
    assert notifier.pushcut_url
    assert notifier.ntfy_enabled
    print("Both channels enabled")


def test_notifier_disabled():
    """No channels enabled."""
    # Patch _get_pushcut_url to prevent reading from persistent file
    with patch.object(ApprovalNotifier, "_get_pushcut_url", return_value=None):
        config = {
            "callback_topic": "test-topic",
        }
        notifier = ApprovalNotifier(config)

        assert not notifier.is_enabled()
        print("No channels enabled")


def test_topic_from_env():
    """Topic from environment variable."""
    with patch.dict(os.environ, {"NTFY_TOPIC": "env-topic"}):
        config = {}
        notifier = ApprovalNotifier(config)
        assert notifier.callback_topic == "env-topic"
    print("Topic from env")


@pytest.mark.skipif(
    not os.environ.get("NTFY_INTEGRATION_TEST"),
    reason="Set NTFY_INTEGRATION_TEST=1 to run real ntfy integration tests"
)
def test_send_ntfy(topic=None):
    """Integration test - send to real ntfy.

    This test requires network access and valid SSL certificates.
    Set NTFY_INTEGRATION_TEST=1 to enable.
    """
    topic = topic or os.environ.get("NTFY_TOPIC") or generate_secure_topic()
    print(f"\nSending to ntfy topic: {topic}")

    config = {
        "ntfy_enabled": True,
        "callback_topic": topic,
    }
    notifier = ApprovalNotifier(config)

    success = notifier.send_approval_request(
        token="test-abc123",
        credential_type="openai",
        host="suspicious.example.com",
        path="/api/v1/chat",
        reason="not_in_policy",
        confidence="high",
        tier=1,
    )

    assert success, "Failed to send"
    print(f"Sent! Subscribe: https://ntfy.sh/{topic}")


if __name__ == "__main__":
    if "--generate-topic" in sys.argv:
        topic = generate_secure_topic()
        print(f'export NTFY_TOPIC="{topic}"')
        print(f"Subscribe: https://ntfy.sh/{topic}")
        sys.exit(0)

    print("--- Unit Tests ---")
    test_notifier_pushcut_only()
    test_notifier_ntfy_only()
    test_notifier_both()
    test_notifier_disabled()
    test_topic_from_env()
    print("\nUnit tests passed!")

    print("\n--- Integration Test ---")
    try:
        test_send_ntfy()
    except Exception as e:
        print(f"Integration test failed: {e}")
        sys.exit(1)

    print("\nAll tests passed!")
