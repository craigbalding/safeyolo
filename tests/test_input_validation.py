"""Input validation tests for security-sensitive CLI parameters.

Agent names flow into:
  - Filesystem paths (agent config dir, rootfs overlay)
  - sudo shell arguments (iptables, runsc, ip netns)
  - Kernel object names (netns, veth)

The validator must reject anything that could escape these contexts.
"""

import re

import pytest

# Import the validator and pattern directly — no subprocess needed.
from safeyolo.commands.agent import HOSTNAME_PATTERN, _validate_instance_name

# typer.Exit → click.exceptions.Exit → RuntimeError (not SystemExit).
try:
    from click.exceptions import Exit as ClickExit
except ImportError:
    ClickExit = SystemExit


class TestAgentNameValidation:
    """Verify agent name validator rejects injection payloads."""

    # --- Positive cases: must be accepted ---

    @pytest.mark.parametrize("name", [
        "myproject",
        "a",
        "claude-code",
        "agent-0",
        "a1b2c3",
        "x" * 63,  # max length
    ])
    def test_valid_names_accepted(self, name):
        # _validate_instance_name raises typer.Exit on rejection;
        # absence of exception = accepted.
        _validate_instance_name(name)

    # --- Negative cases: must be rejected ---

    @pytest.mark.parametrize("name,label", [
        # Shell metacharacters — command injection
        ("foo;whoami", "semicolon"),
        ("foo$(whoami)", "dollar-paren"),
        ("foo`whoami`", "backtick"),
        ("foo|whoami", "pipe"),
        ("foo&whoami", "ampersand"),
        ("foo>whoami", "redirect"),
        ("foo\nwhoami", "newline"),
        # Path traversal
        ("../etc/shadow", "dot-dot-slash"),
        ("foo/bar", "slash"),
        # Spaces / whitespace
        ("foo bar", "space"),
        ("foo\tbar", "tab"),
        # Uppercase (netns/veth names are case-sensitive on Linux)
        ("MyProject", "uppercase"),
        # Starts/ends with hyphen
        ("-leadinghyphen", "leading-hyphen"),
        ("trailinghyphen-", "trailing-hyphen"),
        # Empty / too long
        ("", "empty"),
        ("a" * 64, "too-long"),
        # Null byte
        ("foo\x00bar", "null-byte"),
        # Unicode
        ("foo\u0301bar", "unicode-combining"),
    ])
    def test_injection_payloads_rejected(self, name, label):
        with pytest.raises((SystemExit, ClickExit)):
            _validate_instance_name(name)

    def test_hostname_pattern_anchored(self):
        """Regex must be anchored (^ and $) so partial matches don't
        slip through.
        """
        assert HOSTNAME_PATTERN.pattern.startswith("^")
        assert HOSTNAME_PATTERN.pattern.endswith("$")
