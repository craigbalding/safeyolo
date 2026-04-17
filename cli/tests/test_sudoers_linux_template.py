"""Tests for the Linux sudoers template and `safeyolo setup sudoers` on Linux.

The invariants here pin the contract between the template and the
`_resolve_sudoers_body` substitution logic:

  - The template uses `%safeyolo` as a group placeholder so
    `setup sudoers` can substitute the invoking user's username.
  - The cp rule is locked to the fixed scratch mount point, not
    bare `cp -a *` (which would be a generic root-escalation primitive).
  - The runtime privileged commands we actually need at agent
    lifecycle time (runsc, iptables, mount/umount, ip) are granted.
"""

from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from safeyolo.cli import app

SUDOERS_PATH = (
    Path(__file__).parent.parent
    / "src"
    / "safeyolo"
    / "templates"
    / "safeyolo-linux.sudoers"
)


@pytest.fixture(scope="module")
def sudoers_text() -> str:
    return SUDOERS_PATH.read_text()


@pytest.fixture(scope="module")
def sudoers_rules(sudoers_text: str) -> str:
    """Non-comment, non-blank lines only — the actual sudoers rules."""
    lines = [
        line
        for line in sudoers_text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return "\n".join(lines)


class TestLinuxTemplateInvariants:

    def test_template_exists(self):
        assert SUDOERS_PATH.exists(), f"Missing: {SUDOERS_PATH}"

    def test_uses_safeyolo_group_placeholder(self, sudoers_rules):
        """setup sudoers' substitution logic looks for the literal
        string `%safeyolo`. If someone renames the group, substitution
        silently leaves the template unchanged and the rules don't
        match any user."""
        assert "%safeyolo" in sudoers_rules

    def test_cp_source_is_locked_to_scratch_mount(self, sudoers_rules):
        """Source arg of the cp rule is the fixed scratch mount point."""
        assert "/usr/bin/cp -a *" not in sudoers_rules, (
            "Unlocked `cp -a *` rule is a root-escalation primitive"
        )
        assert "/usr/bin/cp -a /tmp/safeyolo-rootfs-mnt/." in sudoers_rules

    def test_cp_destination_uses_placeholder_not_wildcard(self, sudoers_rules):
        """`cp -a /tmp/safeyolo-rootfs-mnt/. *` with a trailing `*` dest
        was still a `sudo cp <anywhere>` escalation primitive. The
        template must use a substitution placeholder that setup renders
        into the literal resolved share-dir path at install time."""
        assert "/tmp/safeyolo-rootfs-mnt/. *" not in sudoers_rules, (
            "Destination wildcard re-introduced — would allow `sudo cp` to any path"
        )
        assert "%SAFEYOLO_BASE_ROOTFS_DEST%" in sudoers_rules, (
            "Placeholder removed — _resolve_sudoers_body has nothing to substitute"
        )

    def test_mkdir_has_no_wildcard(self, sudoers_rules):
        """/run/safeyolo is a fixed path — no `mkdir -p /run/safeyolo*`."""
        assert "mkdir -p /run/safeyolo*" not in sudoers_rules
        assert "mkdir -p /run/safeyolo" in sudoers_rules

    def test_no_rm_rf_rule(self, sudoers_rules):
        """fuse-overlayfs + squash_to_uid makes all files user-owned.
        No sudo rm needed — shutil.rmtree handles cleanup."""
        assert "rm -rf" not in sudoers_rules

    def test_no_wildcard_mount(self, sudoers_rules):
        """mount * is root-equivalent. Only pinned loop mount allowed."""
        # No `mount *` (bare wildcard)
        for line in sudoers_rules.splitlines():
            if "mount" in line and "umount" not in line and "loop" not in line:
                assert "mount *" not in line, f"Unpinned mount rule: {line}"

    def test_no_wildcard_umount(self, sudoers_rules):
        """umount * can unmount critical system filesystems."""
        for line in sudoers_rules.splitlines():
            if "umount" in line:
                assert "/tmp/safeyolo-rootfs-mnt" in line, (
                    f"umount not pinned to extraction mount point: {line}"
                )

    def test_mount_pinned_to_extraction_paths(self, sudoers_rules):
        r"""Loop mount rule uses pinned ext4 path and fixed mount point.
        Note: sudoers requires \, to escape commas in arguments."""
        assert r"mount -o loop\,ro %SAFEYOLO_BASE_EXT4% /tmp/safeyolo-rootfs-mnt" in sudoers_rules
        assert "umount /tmp/safeyolo-rootfs-mnt" in sudoers_rules

    def test_chown_rule_for_base_rootfs(self, sudoers_rules):
        """chown rule pinned to base rootfs dest for fuse-overlayfs lowerdir."""
        assert "chown -R %SAFEYOLO_CHOWN_TARGET% %SAFEYOLO_BASE_ROOTFS_DEST%" in sudoers_rules

    def test_no_ip_netns_exec(self, sudoers_rules):
        """ip netns exec allows running arbitrary binaries as root.
        The template must use ip -n instead."""
        assert "ip netns exec" not in sudoers_rules
        # No blanket `ip netns *` — must be scoped to add/del
        assert "ip netns *" not in sudoers_rules

    def test_ip_netns_scoped_to_safeyolo_prefix(self, sudoers_rules):
        """Namespace operations must be limited to safeyolo-* names."""
        assert "ip netns add safeyolo-*" in sudoers_rules
        assert "ip netns del safeyolo-*" in sudoers_rules

    def test_ip_link_scoped_to_veth_prefix(self, sudoers_rules):
        """Host-side veth operations scoped to veth-sy* interface names."""
        # No blanket `ip link *`
        assert "/ip link *\\" not in sudoers_rules and \
               "/ip link *\n" not in sudoers_rules
        assert "ip link add veth-sy*" in sudoers_rules
        assert "ip link del veth-sy*" in sudoers_rules
        assert "ip link set veth-sy* up" in sudoers_rules

    def test_ip_addr_scoped_to_veth_prefix(self, sudoers_rules):
        """Host-side addr operations scoped to veth-sy* interfaces."""
        assert "ip addr add * dev veth-sy*" in sudoers_rules

    def test_ip_n_grants_for_guest_side_config(self, sudoers_rules):
        """Guest-side config uses ip -n safeyolo-* (not ip netns exec)."""
        assert "ip -n safeyolo-* addr *" in sudoers_rules
        assert "ip -n safeyolo-* link *" in sudoers_rules
        assert "ip -n safeyolo-* route *" in sudoers_rules

    def test_runsc_pinned_to_safeyolo_state_dir(self, sudoers_rules):
        """runsc rules must pin --root /run/safeyolo so they can't operate
        on containers outside SafeYolo's state directory."""
        assert "runsc --root /run/safeyolo" in sudoers_rules
        # No blanket `runsc *` — must be subcommand-specific.
        for line in sudoers_rules.splitlines():
            if "runsc" in line:
                assert "--root /run/safeyolo" in line, (
                    f"runsc rule without --root pinning: {line}"
                )

    def test_runsc_enumerates_subcommands(self, sudoers_rules):
        """Each runsc subcommand must be explicitly listed."""
        for subcmd in ("create", "start", "state", "kill", "delete", "exec"):
            assert f"runsc --root /run/safeyolo {subcmd} *" in sudoers_rules or \
                   f"runsc --root /run/safeyolo --platform=kvm {subcmd} *" in sudoers_rules or \
                   f"runsc --root /run/safeyolo --platform=systrap {subcmd} *" in sudoers_rules, \
                   f"Missing runsc subcommand grant: {subcmd}"

    def test_grants_iptables(self, sudoers_rules):
        """Per-agent egress rules."""
        assert "iptables *" in sudoers_rules

    def test_grants_pinned_mount_and_umount(self, sudoers_rules):
        """Only the one-time base extraction mount is granted, pinned
        to exact paths. No wildcard mount/umount."""
        assert "mount -o loop" in sudoers_rules
        assert "umount /tmp/safeyolo-rootfs-mnt" in sudoers_rules


class TestSetupSudoersOnLinux:

    def test_substitutes_safeyolo_placeholder_with_username(self, tmp_path):
        """setup sudoers renders `%safeyolo` → invoking user's name before
        writing. Pin that via the helper — the full command mocks out the
        tee/chmod/visudo calls so we don't need root."""
        from safeyolo.commands.setup import _resolve_sudoers_body

        with (
            patch("safeyolo.commands.setup._platform.system", return_value="Linux"),
            patch.dict("os.environ", {"USER": "alice"}, clear=False),
        ):
            body = _resolve_sudoers_body(SUDOERS_PATH)

        assert "%safeyolo" not in body, "Placeholder left unresolved"
        assert "alice ALL=(root) NOPASSWD" in body

    def test_prefers_sudo_user_over_user(self, tmp_path):
        """When invoked via `sudo ...`, $USER is `root` but $SUDO_USER
        is the real invoker — substitute the real user, not root."""
        from safeyolo.commands.setup import _resolve_sudoers_body

        with (
            patch("safeyolo.commands.setup._platform.system", return_value="Linux"),
            patch.dict("os.environ", {"USER": "root", "SUDO_USER": "alice"}, clear=False),
        ):
            body = _resolve_sudoers_body(SUDOERS_PATH)

        assert "root ALL=(root) NOPASSWD" not in body
        assert "alice ALL=(root) NOPASSWD" in body

    def test_substitutes_base_rootfs_dest_placeholder(self, tmp_path):
        """The cp rule's destination placeholder must be rendered into
        the literal resolved share-dir path, leaving no wildcard."""
        from safeyolo.commands.setup import _resolve_sudoers_body

        fake_share = tmp_path / "fake-safeyolo" / "share"
        with (
            patch("safeyolo.commands.setup._platform.system", return_value="Linux"),
            patch.dict("os.environ", {"USER": "alice"}, clear=False),
            patch("safeyolo.config.get_share_dir", return_value=fake_share),
        ):
            body = _resolve_sudoers_body(SUDOERS_PATH)

        assert "%SAFEYOLO_BASE_ROOTFS_DEST%" not in body, "Placeholder unresolved"
        expected_dest = str(fake_share / "rootfs-base")
        assert f"/usr/bin/cp -a /tmp/safeyolo-rootfs-mnt/. {expected_dest}" in body
        # Belt-and-suspenders: no wildcard remains in the cp rule.
        assert "/tmp/safeyolo-rootfs-mnt/. *" not in body

    def test_substitutes_ext4_and_chown_placeholders(self, tmp_path):
        """The mount and chown rules must have all placeholders resolved."""
        from safeyolo.commands.setup import _resolve_sudoers_body

        fake_share = tmp_path / "fake-safeyolo" / "share"
        with (
            patch("safeyolo.commands.setup._platform.system", return_value="Linux"),
            patch.dict("os.environ", {"USER": "alice"}, clear=False),
            patch("safeyolo.config.get_share_dir", return_value=fake_share),
        ):
            body = _resolve_sudoers_body(SUDOERS_PATH)

        assert "%SAFEYOLO_BASE_EXT4%" not in body, "ext4 placeholder unresolved"
        expected_ext4 = str(fake_share / "rootfs-base.ext4")
        assert f"mount -o loop\\,ro {expected_ext4} /tmp/safeyolo-rootfs-mnt" in body

        assert "%SAFEYOLO_CHOWN_TARGET%" not in body, "chown placeholder unresolved"
        # chown target should be uid:gid of the alice user (or alice:alice fallback)
        assert "chown -R" in body


class TestSetupSudoersOnDarwin:

    def test_substitutes_safeyolo_user_placeholder_with_username(self, tmp_path):
        """Darwin template uses %safeyolo_user, substituted at install time."""
        from safeyolo.commands.setup import _resolve_sudoers_body

        macos_template = (
            Path(__file__).parent.parent
            / "src" / "safeyolo" / "templates" / "safeyolo.sudoers"
        )
        with (
            patch("safeyolo.commands.setup._platform.system", return_value="Darwin"),
            patch.dict("os.environ", {"USER": "craigb"}, clear=False),
        ):
            body = _resolve_sudoers_body(macos_template)

        assert "%safeyolo_user" not in body, "Placeholder left unresolved"
        assert "craigb ALL=(root) NOPASSWD" in body


class TestUsernameValidation:

    def test_rejects_username_with_newline(self):
        import pytest

        from safeyolo.commands.setup import _resolve_sudoers_body

        with (
            patch("safeyolo.commands.setup._platform.system", return_value="Linux"),
            patch.dict("os.environ", {"USER": "alice\nALL=(ALL) NOPASSWD: ALL"}, clear=False),
        ):
            with pytest.raises(RuntimeError, match="unsafe for sudoers"):
                _resolve_sudoers_body(SUDOERS_PATH)

    def test_rejects_username_with_spaces(self):
        import pytest

        from safeyolo.commands.setup import _resolve_sudoers_body

        with (
            patch("safeyolo.commands.setup._platform.system", return_value="Linux"),
            patch.dict("os.environ", {"USER": "alice bob"}, clear=False),
        ):
            with pytest.raises(RuntimeError, match="unsafe for sudoers"):
                _resolve_sudoers_body(SUDOERS_PATH)

    def test_accepts_valid_username(self):
        from safeyolo.commands.setup import _resolve_sudoers_body

        with (
            patch("safeyolo.commands.setup._platform.system", return_value="Linux"),
            patch.dict("os.environ", {"USER": "alice_bob-2"}, clear=False),
        ):
            body = _resolve_sudoers_body(SUDOERS_PATH)
            assert "alice_bob-2 ALL=(root) NOPASSWD" in body


class TestSetupTopLevelCheck:

    def test_reports_warn_when_sudoers_not_installed_on_linux(self, tmp_path):
        """`safeyolo setup` on Linux should warn when sudoers is absent
        and point at `safeyolo setup sudoers` as the fix."""
        runner = CliRunner()
        # Point sudoers_path at a non-existent file to guarantee WARN.
        missing = tmp_path / "does-not-exist"
        with (
            patch("safeyolo.commands.setup._platform.system", return_value="Linux"),
            patch("safeyolo.commands.setup.check_guest_images", return_value=True),
            patch("safeyolo.commands.setup.check_runsc", return_value=(True, "found")),
            patch("safeyolo.commands.setup.Path", side_effect=lambda p: missing if p == "/etc/sudoers.d/safeyolo" else Path(p)),
        ):
            result = runner.invoke(app, ["setup"])

        assert result.exit_code == 0
        assert "sudoers" in result.output.lower()
        assert "safeyolo setup sudoers" in result.output
