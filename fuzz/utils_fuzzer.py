#!/usr/bin/env python3
"""Atheris fuzzer for utils module.

Fuzzes entropy calculation, host matching, path matching, and HMAC fingerprinting.
"""

import sys

import atheris

# Instrument before importing target modules
with atheris.instrument_imports():
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "addons"))
    from utils import (
        calculate_shannon_entropy,
        hmac_fingerprint,
        looks_like_secret,
        matches_host_pattern,
        matches_resource_pattern,
    )


ENTROPY_CONFIG = {
    "min_length": 20,
    "min_charset_diversity": 0.5,
    "min_shannon_entropy": 3.5
}


@atheris.instrument_func
def test_shannon_entropy(data: bytes):
    """Fuzz entropy calculation."""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return

    try:
        calculate_shannon_entropy(text)
    except Exception:
        # Intentional: fuzzer continues on exceptions to find crashes
        pass


@atheris.instrument_func
def test_looks_like_secret(data: bytes):
    """Fuzz secret detection."""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return

    try:
        looks_like_secret(text, ENTROPY_CONFIG)
    except Exception:
        # Intentional: fuzzer continues on exceptions to find crashes
        pass


@atheris.instrument_func
def test_host_matching(data: bytes):
    """Fuzz host pattern matching."""
    if len(data) < 2:
        return

    # Split data into host and pattern
    split_point = data[0] % (len(data) - 1) + 1
    host_bytes = data[1:split_point]
    pattern_bytes = data[split_point:]

    try:
        host = host_bytes.decode("utf-8", errors="replace")
        pattern = pattern_bytes.decode("utf-8", errors="replace")
    except Exception:
        return

    try:
        matches_host_pattern(host, pattern)
    except Exception:
        # Intentional: fuzzer continues on exceptions to find crashes
        pass


@atheris.instrument_func
def test_path_matching(data: bytes):
    """Fuzz resource/path pattern matching."""
    if len(data) < 2:
        return

    # Split data into path and pattern
    split_point = data[0] % (len(data) - 1) + 1
    path_bytes = data[1:split_point]
    pattern_bytes = data[split_point:]

    try:
        path = path_bytes.decode("utf-8", errors="replace")
        pattern = pattern_bytes.decode("utf-8", errors="replace")
    except Exception:
        return

    try:
        matches_resource_pattern(path, pattern)
    except Exception:
        # Intentional: fuzzer continues on exceptions to find crashes
        pass


@atheris.instrument_func
def test_hmac_fingerprint(data: bytes):
    """Fuzz HMAC fingerprinting."""
    if len(data) < 2:
        return

    # Use first half as credential, second as secret
    split_point = len(data) // 2
    credential_bytes = data[:split_point]
    secret = data[split_point:]

    if not secret:
        secret = b"default"

    try:
        credential = credential_bytes.decode("utf-8", errors="replace")
    except Exception:
        return

    try:
        hmac_fingerprint(credential, secret)
    except Exception:
        # Intentional: fuzzer continues on exceptions to find crashes
        pass


def main():
    # Primary target: entropy-based secret detection
    atheris.Setup(sys.argv, test_looks_like_secret)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
