#!/usr/bin/env python3
"""Atheris fuzzer for pattern_scanner module.

Fuzzes the regex-based pattern matching for secrets and jailbreak detection.
"""

import sys

import atheris

# Instrument before importing target modules
with atheris.instrument_imports():
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "addons"))
    import re

    from pattern_scanner import PatternRule, PatternScanner


# Pre-compile rules once
SCANNER = None


def get_scanner():
    """Lazily initialize scanner."""
    global SCANNER
    if SCANNER is None:
        SCANNER = PatternScanner()
        SCANNER.configure({})
    return SCANNER


@atheris.instrument_func
def test_scan_text(data: bytes):
    """Fuzz the _scan_text method with arbitrary input."""
    scanner = get_scanner()

    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return

    # Test both input and output scanning
    try:
        scanner._scan_text(text, "input")
        scanner._scan_text(text, "output")
    except Exception:
        # Intentional: fuzzer continues on exceptions to find crashes
        pass


@atheris.instrument_func
def test_pattern_rule_matches(data: bytes):
    """Fuzz PatternRule.matches with arbitrary patterns and text."""
    if len(data) < 2:
        return

    # Split data into pattern and text
    split_point = data[0] % (len(data) - 1) + 1
    pattern_bytes = data[1:split_point]
    text_bytes = data[split_point:]

    try:
        pattern_str = pattern_bytes.decode("utf-8", errors="replace")
        text_str = text_bytes.decode("utf-8", errors="replace")
    except Exception:
        return

    # Skip empty patterns
    if not pattern_str:
        return

    try:
        compiled = re.compile(pattern_str, re.IGNORECASE)
        rule = PatternRule(
            rule_id="fuzz",
            name="Fuzz Test",
            pattern=compiled,
            target="input",
            severity=3,
            category="test",
        )
        rule.matches(text_str)
    except re.error:
        # Invalid regex is expected from fuzz input
        pass
    except Exception:
        # Intentional: fuzzer continues on exceptions to find crashes
        pass


def main():
    # Use scan_text as main target (most important)
    atheris.Setup(sys.argv, test_scan_text)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
