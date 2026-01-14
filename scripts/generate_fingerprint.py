#!/usr/bin/env python3
"""
Generate HMAC fingerprint for a credential.

Use this to pre-approve credentials in baseline.yaml without going through the
interactive approval flow. The fingerprint format matches what SafeYolo uses
internally and what appears in `safeyolo watch` when credentials are blocked.

Security:
- Credential is read via getpass (not echoed, not in shell history)
- Credential is never logged or written to disk
- Uses the same HMAC secret as your SafeYolo installation

Usage:
    python scripts/generate_fingerprint.py

    # Or pipe from a secure source (e.g., password manager CLI)
    pass show mykey | python scripts/generate_fingerprint.py --stdin
"""

import argparse
import getpass
import hashlib
import hmac
import sys
from pathlib import Path


def get_hmac_secret() -> bytes:
    """Load HMAC secret from SafeYolo data directory."""
    locations = [
        Path.cwd() / "safeyolo" / "data" / "hmac_secret",
        Path.home() / ".safeyolo" / "data" / "hmac_secret",
    ]

    for path in locations:
        if path.exists():
            return path.read_bytes().strip()

    print("Error: No HMAC secret found.", file=sys.stderr)
    print("", file=sys.stderr)
    print("Run 'safeyolo start' first to generate the HMAC secret, or check that", file=sys.stderr)
    print("your SafeYolo config directory exists at one of:", file=sys.stderr)
    for path in locations:
        print(f"  {path.parent.parent}", file=sys.stderr)
    sys.exit(1)


def generate_fingerprint(value: str, secret: bytes) -> str:
    """Generate HMAC-SHA256 fingerprint matching SafeYolo's format."""
    h = hmac.new(secret, value.encode(), hashlib.sha256)
    return h.hexdigest()[:16]


def main():
    parser = argparse.ArgumentParser(
        description="Generate HMAC fingerprint for a credential",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read credential from stdin (for piping from password managers)",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Output fingerprint without 'hmac:' prefix",
    )
    args = parser.parse_args()

    secret = get_hmac_secret()

    if args.stdin:
        credential = sys.stdin.read().strip()
        if not credential:
            print("Error: No input received on stdin", file=sys.stderr)
            sys.exit(1)
    else:
        print("Enter credential (input hidden):", file=sys.stderr)
        try:
            credential = getpass.getpass(prompt="")
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.", file=sys.stderr)
            sys.exit(1)

        if not credential:
            print("Error: No credential entered", file=sys.stderr)
            sys.exit(1)

    fingerprint = generate_fingerprint(credential, secret)
    print(fingerprint if args.raw else f"hmac:{fingerprint}")


if __name__ == "__main__":
    main()
