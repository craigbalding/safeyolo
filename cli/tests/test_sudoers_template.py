"""Tests for the macOS sudoers template — privilege tightening invariants.

The macOS template now only needs to grant one thing: aliasing synthetic
127.0.0.X addresses onto lo0 so the host-side proxy_bridge can bind the
upstream TCP source for agent attribution. No pf, no feth, no sysctl —
those went away with the vsock arch.
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


class TestLoopbackAliasGrants:
    """The only grant: lo0 alias/-alias for 127.0.0.* attribution IPs."""

    def test_grants_lo0_alias(self, sudoers_rules):
        assert "/sbin/ifconfig lo0 alias 127.0.0.*" in sudoers_rules

    def test_grants_lo0_unalias(self, sudoers_rules):
        assert "/sbin/ifconfig lo0 -alias 127.0.0.*" in sudoers_rules

    def test_scoped_to_loopback(self, sudoers_rules):
        """Every ifconfig rule must target lo0 — never a real interface."""
        for line in sudoers_rules.splitlines():
            if "ifconfig" in line:
                assert "lo0" in line, f"ifconfig rule not scoped to lo0: {line}"

    def test_scoped_to_127_addresses(self, sudoers_rules):
        """Every ifconfig rule must pin the 127.0.0.* prefix — no wildcards
        that would allow aliasing arbitrary IPs onto lo0."""
        for line in sudoers_rules.splitlines():
            if "ifconfig" in line:
                assert "127.0.0.*" in line, (
                    f"ifconfig rule not scoped to 127.0.0.*: {line}"
                )


class TestLegacyGrantsRemoved:
    """Everything from the feth+pf era must be gone."""

    def test_no_pfctl(self, sudoers_text):
        assert "pfctl" not in sudoers_text

    def test_no_feth_interface(self, sudoers_text):
        assert "feth" not in sudoers_text

    def test_no_pf_conf_reference(self, sudoers_text):
        assert "pf.conf" not in sudoers_text

    def test_no_pf_anchors_reference(self, sudoers_text):
        assert "pf.anchors" not in sudoers_text

    def test_no_sysctl_ip_forwarding(self, sudoers_text):
        assert "net.inet.ip.forwarding" not in sudoers_text

    def test_no_tee(self, sudoers_text):
        assert "tee " not in sudoers_text


class TestTemplatePlaceholders:
    """The template still uses %safeyolo_user as the placeholder."""

    def test_placeholder_present(self, sudoers_text):
        assert "%safeyolo_user" in sudoers_text
