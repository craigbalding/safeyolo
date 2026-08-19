"""Tests for the shared custom-rootfs guest installer."""

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GUEST_DIR = REPO_ROOT / "guest"


def test_installer_precreates_runtime_bind_mount_targets(tmp_path: Path) -> None:
    """Custom rootfs trees must be complete before Linux uid remapping."""
    rootfs = tmp_path / "rootfs"
    (rootfs / "usr/sbin").mkdir(parents=True)
    (rootfs / "usr/local/bin").mkdir(parents=True)
    (rootfs / "etc").mkdir(parents=True)
    (rootfs / "usr/sbin/useradd").touch()
    (rootfs / "usr/sbin/useradd").chmod(0o755)

    command = (
        "chroot() { return 0; }; "
        'source "$SAFEYOLO_GUEST_SRC_DIR/install-guest-common.sh"; '
        'install_safeyolo_guest_common "$TEST_ROOTFS"'
    )
    result = subprocess.run(
        ["bash", "-c", command],
        env={
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "SAFEYOLO_GUEST_SRC_DIR": str(GUEST_DIR),
            "TEST_ROOTFS": str(rootfs),
        },
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    for relative in ("workspace", "safeyolo", "safeyolo-status", "home/agent"):
        target = rootfs / relative
        assert target.is_dir()
        assert target.stat().st_mode & 0o777 == 0o755

    ca_target = rootfs / "usr/local/share/ca-certificates/safeyolo.crt"
    assert ca_target.is_file()
    assert ca_target.stat().st_mode & 0o777 == 0o644


def test_default_rootfs_hook_uses_shared_mount_target_installer() -> None:
    """The default and custom builders must not drift again."""
    source = (GUEST_DIR / "rootfs-customize-hook.sh").read_text()

    assert 'source "$GUEST_SRC_DIR/install-guest-common.sh"' in source
    assert 'install_safeyolo_runtime_mount_targets "$ROOTFS"' in source
