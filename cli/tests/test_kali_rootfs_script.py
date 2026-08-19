"""Regression tests for the bundled Kali custom-rootfs builder."""

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
KALI_BUILDER = REPO_ROOT / "contrib" / "kali-pentest" / "build-kali-rootfs.sh"


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(0o755)


def test_linux_builder_keeps_pull_unprivileged_and_elevates_unpack(
    tmp_path: Path,
) -> None:
    """The host password authorizes operations, not the whole build script."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    call_log = tmp_path / "calls"

    _write_executable(
        fake_bin / "id",
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        "  -u|-g) echo 12345 ;;\n"
        "  *) exit 2 ;;\n"
        "esac\n",
    )
    _write_executable(
        fake_bin / "sudo",
        "#!/bin/sh\n"
        "printf 'sudo' >> \"$TEST_CALL_LOG\"\n"
        "for arg in \"$@\"; do printf '|%s' \"$arg\" >> \"$TEST_CALL_LOG\"; done\n"
        "printf '\\n' >> \"$TEST_CALL_LOG\"\n"
        "[ \"${1-}\" = -v ] && exit 0\n"
        "exit 73\n",
    )
    _write_executable(
        fake_bin / "skopeo",
        "#!/bin/sh\n"
        "printf 'skopeo' >> \"$TEST_CALL_LOG\"\n"
        "for arg in \"$@\"; do printf '|%s' \"$arg\" >> \"$TEST_CALL_LOG\"; done\n"
        "printf '\\n' >> \"$TEST_CALL_LOG\"\n",
    )
    # The dependency check requires umoci on PATH. The sudo double exits before
    # invoking it, which also catches an accidental unprivileged call.
    _write_executable(fake_bin / "umoci", "#!/bin/sh\nexit 91\n")

    work_dir = tmp_path / "work"
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}:{env['PATH']}",
            "TEST_CALL_LOG": str(call_log),
            "SAFEYOLO_AGENT_NAME": "kali-test",
            "SAFEYOLO_ROOTFS_OUT_TREE": str(tmp_path / "rootfs"),
            "SAFEYOLO_ROOTFS_OUT_CACHE_PATHS": str(tmp_path / "cache-paths"),
            "SAFEYOLO_ROOTFS_WORK_DIR": str(work_dir),
            "SAFEYOLO_GUEST_SRC_DIR": str(REPO_ROOT / "guest"),
            "SAFEYOLO_TARGET_ARCH": "amd64",
        }
    )

    result = subprocess.run(
        [str(KALI_BUILDER)], env=env, capture_output=True, text=True
    )

    assert result.returncode == 73
    calls = call_log.read_text().splitlines()
    assert calls[0] == "sudo|-v"
    pull_index = next(i for i, call in enumerate(calls) if call.startswith("skopeo|"))
    unpack_index = next(
        i for i, call in enumerate(calls) if call.startswith("sudo|umoci|unpack|")
    )
    assert pull_index < unpack_index
    assert not any(call.startswith("sudo|skopeo|") for call in calls)


def test_kali_apt_phase_restores_container_runtime_environment() -> None:
    """Protect the shared fix for systemd/dbus package configuration."""
    source = KALI_BUILDER.read_text()
    apt_phase = source[
        source.index('echo "=== Installing Kali apt packages ==="') :
        source.index('echo "=== Installing pinned Go-based pentest binaries ==="')
    ]

    assert "_mount_chroot_runtime" in apt_phase
    assert "apt-get update" in apt_phase
    assert "apt-get install" in apt_phase
    assert "apt-get install -y -qq" not in apt_phase
    assert "dpkg --audit" in apt_phase
    assert "_unmount_chroot_runtime" in apt_phase
    assert "command -v systemctl dbus-daemon sudo tmux sshd chromium" in apt_phase
    assert apt_phase.index("_mount_chroot_runtime") < apt_phase.index("apt-get update")
    assert apt_phase.index("apt-get install") < apt_phase.index("dpkg --audit")
    assert apt_phase.index("dpkg --audit") < apt_phase.index(
        "_unmount_chroot_runtime"
    )

    mount_helper = source[
        source.index("_mount_chroot_runtime()") :
        source.index('echo "=== Installing Kali apt packages ==="')
    ]
    assert "for source in /proc /sys /dev" in mount_helper
    assert 'mount --bind "$source" "$target"' in mount_helper
    assert 'umount "${CHROOT_MOUNTS[$i]}"' in mount_helper

    # The official Kali container rootfs uses the same policy to prevent
    # package maintainer scripts from starting daemons during image builds.
    assert 'tee "$TREE/usr/sbin/policy-rc.d"' in source
    assert "exit 101" in source


def test_kali_chroots_use_deterministic_utf8_locale() -> None:
    """Do not leak an unsupported operator locale into the minimal rootfs."""
    source = KALI_BUILDER.read_text()

    assert '"LANG=C.UTF-8"' in source
    assert '"LC_ALL=C.UTF-8"' in source
    assert source.count('/usr/bin/env -i "${CHROOT_ENV[@]}"') == 2


def test_kali_rootfs_seeds_hushlogin_for_persistent_agent_home() -> None:
    """Suppress Kali's login banner after SafeYolo mounts the agent home."""
    source = KALI_BUILDER.read_text()

    assert 'install -m 0644 /dev/null "$TREE/etc/skel/.hushlogin"' in source


def test_unprivileged_tool_installs_get_only_minimal_build_devices() -> None:
    """Git needs /dev/null, without exposing the host's complete /dev."""
    source = KALI_BUILDER.read_text()
    unprivileged_phase = source[
        source.index('echo "=== Python pentest venv (unprivileged) ==="') :
        source.index("# The Python pentest tools live in one isolated venv.")
    ]
    helper = source[
        source.index("_mount_chroot_build_devices()") :
        source.index('echo "=== Installing Kali apt packages ==="')
    ]

    assert "for device in null zero random urandom" in helper
    assert 'mount --bind "/dev/$device" "$target"' in helper
    assert "/dev/tty" not in helper
    assert "_mount_chroot_build_devices" in unprivileged_phase
    assert "_remove_chroot_build_devices" in unprivileged_phase
    assert unprivileged_phase.index("_mount_chroot_build_devices") < (
        unprivileged_phase.index("git clone")
    )
    assert unprivileged_phase.index("git clone") < unprivileged_phase.index(
        "_remove_chroot_build_devices"
    )
