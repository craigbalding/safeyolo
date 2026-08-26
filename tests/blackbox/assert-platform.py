#!/usr/bin/env python3
"""Assert the SafeYolo isolation platform reported by ``doctor --json``.

Blackbox lanes must fail if they silently run on a different isolation
mechanism.  In particular, a KVM acceptance run that falls back to systrap is
not KVM evidence, and a systrap CI run that unexpectedly acquires /dev/kvm is
not the lane it claims to be.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

PLATFORM_PREFIXES = {
    "systrap": "systrap ",
    "kvm": "KVM ",
    "vz": "Apple Virtualization.framework ",
}


def reported_platform(payload: dict) -> tuple[str, str]:
    """Return normalized platform name and the original doctor message."""
    for check in payload.get("checks", []):
        if check.get("name") != "Isolation platform":
            continue
        message = str(check.get("message", ""))
        for platform, prefix in PLATFORM_PREFIXES.items():
            if message.startswith(prefix):
                return platform, message
        raise ValueError(f"unrecognized Isolation platform message: {message!r}")
    raise ValueError("doctor JSON has no 'Isolation platform' check")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("expected", choices=sorted(PLATFORM_PREFIXES))
    parser.add_argument("doctor_json", type=Path)
    args = parser.parse_args()

    try:
        payload = json.loads(args.doctor_json.read_text())
        actual, message = reported_platform(payload)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))

    print(f"Isolation platform: {actual} ({message})")
    if actual != args.expected:
        parser.error(
            f"blackbox lane expected {args.expected!r}, but SafeYolo selected {actual!r}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
