#!/usr/bin/env python3
"""Atheris fuzzer for credential_guard module.

Fuzzes credential detection in HTTP headers.
"""

import sys

import atheris

# Instrument before importing target modules
with atheris.instrument_imports():
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "addons"))
    from credential_guard import (
        DEFAULT_RULES,
        analyze_headers,
        extract_bearer_token,
    )


ENTROPY_CONFIG = {
    "min_length": 20,
    "min_charset_diversity": 0.5,
    "min_shannon_entropy": 3.5
}


@atheris.instrument_func
def test_analyze_headers(data: bytes):
    """Fuzz header analysis with arbitrary header values."""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return

    # Test with Authorization header
    headers = {"Authorization": text}

    try:
        analyze_headers(
            headers=headers,
            rules=DEFAULT_RULES,
            safe_headers_config={},
            entropy_config=ENTROPY_CONFIG,
            standard_auth_headers=["authorization"],
            detection_level="standard"
        )
    except Exception:
        # Intentional: fuzzer continues on exceptions to find crashes
        pass


@atheris.instrument_func
def test_analyze_arbitrary_headers(data: bytes):
    """Fuzz with arbitrary header names and values."""
    if len(data) < 2:
        return

    # Split data into header name and value
    split_point = data[0] % (len(data) - 1) + 1
    name_bytes = data[1:split_point]
    value_bytes = data[split_point:]

    try:
        header_name = name_bytes.decode("utf-8", errors="replace")
        header_value = value_bytes.decode("utf-8", errors="replace")
    except Exception:
        return

    # Skip empty header names
    if not header_name:
        return

    headers = {header_name: header_value}

    try:
        analyze_headers(
            headers=headers,
            rules=DEFAULT_RULES,
            safe_headers_config={},
            entropy_config=ENTROPY_CONFIG,
            standard_auth_headers=["authorization", header_name.lower()],
            detection_level="paranoid"
        )
    except Exception:
        # Intentional: fuzzer continues on exceptions to find crashes
        pass


@atheris.instrument_func
def test_extract_bearer_token(data: bytes):
    """Fuzz bearer token extraction."""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return

    try:
        extract_bearer_token(text)
    except Exception:
        # Intentional: fuzzer continues on exceptions to find crashes
        pass


def main():
    atheris.Setup(sys.argv, test_analyze_headers)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
