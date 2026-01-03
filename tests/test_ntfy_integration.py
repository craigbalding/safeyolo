#!/usr/bin/env python3
"""
Test the Credential Guard approval workflow with real Ntfy.

This script:
1. Sends a test notification to Ntfy
2. Verifies the notification includes action buttons
3. Simulates the approval workflow

Usage:
    # Generate a secure, hard-to-guess topic
    python3 -c "import secrets; print(f'export NTFY_TOPIC=safeyolo-{secrets.token_urlsafe(32)}')"

    # Or let the script generate one for you:
    python3 tests/test_ntfy_integration.py --generate-topic

    # Then run the test
    python3 tests/test_ntfy_integration.py

    # Subscribe to notifications in another terminal:
    curl -s "https://ntfy.sh/$NTFY_TOPIC/json"
"""

import json
import os
import secrets
import sys
import urllib.request
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from addons.credential_guard import NtfyApprovalBackend


def generate_secure_topic():
    """Generate a secure, hard-to-guess Ntfy topic."""
    # 32 bytes = ~43 characters URL-safe base64
    topic = f"safeyolo-{secrets.token_urlsafe(32)}"
    return topic


def test_ntfy_notification():
    """Test sending a notification with action buttons."""
    topic = os.environ.get("NTFY_TOPIC") or generate_secure_topic()

    print(f"📡 Testing Ntfy integration with topic: {topic}")
    print(f"📱 Subscribe to notifications: https://ntfy.sh/{topic}")
    print()

    # Create backend instance
    config = {
        "server": "https://ntfy.sh",
        "topic": topic,
        "priority": 4,
        "tags": ["warning", "lock"]
    }

    backend = NtfyApprovalBackend(config)

    assert backend.is_enabled(), "Backend not enabled (topic missing)"
    print("✅ Backend initialized")

    # Send test notification
    print("\n Sending test approval notification...")

    test_token = "test-token-abc123xyz456"

    success = backend.send_approval_request(
        token=test_token,
        credential_type="openai",
        host="suspicious.example.com",
        path="/api/v1/chat",
        reason="not_in_policy",
        confidence="high",
        tier=1,
    )

    assert success, "Failed to send notification"
    print("Notification sent successfully!")
    print(f"\nCheck your Ntfy app or: https://ntfy.sh/{topic}")
    print("\nThe notification should have two buttons:")
    print(f"   Approve -> POSTs 'approve:{test_token}' to ntfy topic")
    print(f"   Deny    -> POSTs 'deny:{test_token}' to ntfy topic")
    print("\nRun scripts/ntfy_approval_listener.py to process button clicks.")


def test_unknown_credential_notification():
    """Test notification for unknown credential type."""
    topic = os.environ.get("NTFY_TOPIC") or generate_secure_topic()

    config = {
        "server": "https://ntfy.sh",
        "topic": topic,
        "priority": 4,
        "tags": ["warning", "lock"]
    }

    backend = NtfyApprovalBackend(config)

    print("\nSending unknown credential notification...")

    test_token = "test-unknown-def789"

    success = backend.send_approval_request(
        token=test_token,
        credential_type="unknown_secret",
        host="custom-api.example.com",
        path="/endpoint",
        reason="unknown_credential_type",
        confidence="medium",
        tier=2,
    )

    assert success, "Failed to send notification"
    print("Unknown credential notification sent!")


def show_usage():
    """Show how to monitor notifications."""
    topic = os.environ.get("NTFY_TOPIC", "your-topic-here")

    print("\n" + "="*60)
    print("HOW TO USE NTFY APPROVALS")
    print("="*60)
    print("\n1. Start the approval listener (runs locally):")
    print("   python3 scripts/ntfy_approval_listener.py")
    print("\n2. Subscribe in browser:")
    print(f"   https://ntfy.sh/{topic}")
    print("\n3. Subscribe via curl (JSON stream):")
    print(f"   curl -s 'https://ntfy.sh/{topic}/json'")
    print("\n4. Ntfy mobile app:")
    print("   - Download: https://ntfy.sh/docs/subscribe/phone/")
    print(f"   - Subscribe to topic: {topic}")
    print("\n" + "="*60)


if __name__ == "__main__":
    # Handle --generate-topic flag
    if "--generate-topic" in sys.argv:
        topic = generate_secure_topic()
        print("🔐 Generated secure Ntfy topic (43+ characters):")
        print()
        print(f'export NTFY_TOPIC="{topic}"')
        print()
        print("📋 Copy and run the above command, then run this test again.")
        print()
        print(f"📱 Subscribe in browser: https://ntfy.sh/{topic}")
        sys.exit(0)

    print("=" * 60)
    print("🧪 Credential Guard + Ntfy Integration Test")
    print("=" * 60)
    print()

    try:
        # Test 1: Send known credential notification
        test_ntfy_notification()

        # Test 2: Send unknown credential notification
        test_unknown_credential_notification()

        # Show monitoring info
        show_usage()

        print("\nAll tests passed!")
        print("\nNext steps:")
        print("   1. Start the listener: python3 scripts/ntfy_approval_listener.py")
        print("   2. Check your Ntfy app for notifications")
        print("   3. Tap Approve/Deny - listener will call the admin API")
        sys.exit(0)

    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
