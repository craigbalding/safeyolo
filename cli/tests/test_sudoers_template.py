"""Tests for the macOS sudoers template — privilege tightening invariants.

These tests encode the security contract of safeyolo.sudoers:

  - Runtime cannot append to /etc/pf.conf (no `tee -a /etc/pf.conf`).
  - Runtime cannot read /etc/pf.conf via sudo (no `cat /etc/pf.conf`).
  - No wildcard pattern grants arbitrary anchor names like com.safeyolo*
    (only the two fixed names com.safeyolo and com.safeyolo-test).
  - No wildcard pattern grants arbitrary anchor file writes under
    /etc/pf.anchors (only the two fixed files).
  - The feth and sysctl grants that runtime does need are preserved.
"""

from pathlib import Path

import pytest


SUDOERS_PATH = (
    Path(__file__).parent.parent
    / "src"
    / "safeyolo"
    / "templates"
    / "safeyolo.sudoers"
)


@pytest.fixture(scope="module")
def sudoers_text() -> str:
    return SUDOERS_PATH.read_text()


@pytest.fixture(scope="module")
def sudoers_rules(sudoers_text: str) -> str:
    """Return only the non-comment lines (the actual sudoers rules)."""
    lines = [
        line
        for line in sudoers_text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return "\n".join(lines)


class TestDoesNotGrantPfConfWrites:
    """The whole point of this change: runtime cannot touch /etc/pf.conf."""

    def test_no_tee_append_to_pf_conf(self, sudoers_rules):
        assert "tee -a /etc/pf.conf" not in sudoers_rules
        # Also guard against paths with whitespace variants.
        assert "tee  -a /etc/pf.conf" not in sudoers_rules

    def test_no_tee_write_to_pf_conf(self, sudoers_rules):
        # Neither `tee -a` nor plain `tee` should target pf.conf at runtime.
        assert "tee /etc/pf.conf" not in sudoers_rules
        assert "/etc/pf.conf" not in sudoers_rules, (
            "Runtime sudoers must not reference /etc/pf.conf at all."
        )

    def test_no_cat_pf_conf(self, sudoers_rules):
        assert "cat /etc/pf.conf" not in sudoers_rules


class TestFixedAnchorNames:
    """Anchor grants must enumerate fixed names, not use wildcards."""

    def test_no_wildcard_anchor_pattern_in_pfctl(self, sudoers_rules):
        # com.safeyolo* would allow com.safeyolo-anything — disallowed.
        assert "com.safeyolo*" not in sudoers_rules

    def test_no_wildcard_anchor_file_pattern(self, sudoers_rules):
        # /etc/pf.anchors/com.safeyolo* would allow arbitrary file writes.
        assert "/etc/pf.anchors/com.safeyolo*" not in sudoers_rules

    def test_grants_pfctl_for_fixed_prod_anchor(self, sudoers_rules):
        assert "/sbin/pfctl -a com.safeyolo -f *" in sudoers_rules
        assert "/sbin/pfctl -a com.safeyolo -F all" in sudoers_rules
        assert "/sbin/pfctl -a com.safeyolo -s *" in sudoers_rules

    def test_grants_pfctl_for_fixed_test_anchor(self, sudoers_rules):
        # Blackbox test harness uses com.safeyolo-test; also a fixed name.
        assert "/sbin/pfctl -a com.safeyolo-test -f *" in sudoers_rules
        assert "/sbin/pfctl -a com.safeyolo-test -F all" in sudoers_rules

    def test_grants_tee_for_fixed_anchor_files_only(self, sudoers_rules):
        assert "/usr/bin/tee /etc/pf.anchors/com.safeyolo" in sudoers_rules
        assert "/usr/bin/tee /etc/pf.anchors/com.safeyolo-test" in sudoers_rules

    def test_no_unexpected_anchor_paths(self, sudoers_rules):
        """Only com.safeyolo and com.safeyolo-test should appear under /etc/pf.anchors."""
        for line in sudoers_rules.splitlines():
            if "/etc/pf.anchors/" not in line:
                continue
            # Strip quoting artifacts; look at the path segment.
            # Allowed tokens: com.safeyolo, com.safeyolo-test (no other variants).
            assert "/etc/pf.anchors/com.safeyolo " in (line + " ") or \
                   "/etc/pf.anchors/com.safeyolo," in line or \
                   "/etc/pf.anchors/com.safeyolo-test" in line, (
                       f"Unexpected pf.anchors reference: {line}"
                   )


class TestRuntimeEssentialsPreserved:
    """The grants the runtime *does* still need must remain."""

    def test_pfctl_enable(self, sudoers_rules):
        assert "/sbin/pfctl -e" in sudoers_rules

    def test_pfctl_status(self, sudoers_rules):
        assert "/sbin/pfctl -s info" in sudoers_rules

    def test_ifconfig_feth(self, sudoers_rules):
        assert "/sbin/ifconfig feth*" in sudoers_rules

    def test_ip_forwarding(self, sudoers_rules):
        assert "/usr/sbin/sysctl -w net.inet.ip.forwarding=1" in sudoers_rules


class TestTemplateDocumentation:
    """Comments in the template must not advertise removed behaviors."""

    def test_no_mention_of_runtime_pf_conf_mutation(self, sudoers_text):
        # Phrases that described the old, removed behavior.
        forbidden = [
            "tee -a /etc/pf.conf",
            "Read pf config",
            "Append anchor to pf config",
            "com.safeyolo* -f",
            "com.safeyolo* -F",
            "com.safeyolo* -s",
            "tee /etc/pf.anchors/*",
        ]
        for phrase in forbidden:
            assert phrase not in sudoers_text, (
                f"Stale documentation references removed behavior: {phrase!r}"
            )
