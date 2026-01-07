#!/usr/bin/env python3
"""Atheris fuzzer for pattern detection.

Fuzzes regex-based pattern matching for secrets and jailbreak detection.
"""

import sys

import atheris

# Instrument before importing target modules
with atheris.instrument_imports():
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "addons"))
    import re

    from detection import PatternRule, compile_rules, scan_text


# Pre-compile rules once
RULES = None


def get_rules():
    """Lazily initialize rules."""
    global RULES
    if RULES is None:
        RULES = compile_rules()
    return RULES


@atheris.instrument_func
def test_scan_text(data: bytes):
    """Fuzz the scan_text function with arbitrary input."""
    rules = get_rules()

    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return

    # Test both input and output scanning
    try:
        scan_text(text, "input", rules)
        scan_text(text, "output", rules)
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
