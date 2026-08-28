"""Regression tests for the bundled Kali custom-rootfs builder."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
KALI_BUILDER = REPO_ROOT / "contrib" / "kali-pentest" / "build-kali-rootfs.sh"
KALI_BUILDER_TEST_HOST_TOOLS = (
    "curl",
    "unzip",
    "tar",
    "sha256sum",
    "mount",
    "umount",
)


def _missing_kali_builder_test_tools(which=shutil.which) -> tuple[str, ...]:
    """Return builder preflight tools not supplied by the test doubles."""
    return tuple(tool for tool in KALI_BUILDER_TEST_HOST_TOOLS if which(tool) is None)


# Establish the host precondition once at collection. If a present tool later
# disappears or fails, the builder regression stays red rather than re-skipping.
MISSING_KALI_BUILDER_TEST_TOOLS = _missing_kali_builder_test_tools()


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(0o755)


@pytest.mark.skipif(
    bool(MISSING_KALI_BUILDER_TEST_TOOLS),
    reason=(
        "Kali rootfs builder regression requires host tools: "
        + ", ".join(MISSING_KALI_BUILDER_TEST_TOOLS)
    ),
)
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
        "[ \"${1-}\" = rm ] && exec \"$@\"\n"
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
        i for i, call in enumerate(calls)
        if call.startswith("sudo|umoci|unpack|")
    )
    assert pull_index < unpack_index
    assert not any(call.startswith("sudo|skopeo|") for call in calls)


def test_kali_builder_precondition_reports_absent_unzip() -> None:
    available = set(KALI_BUILDER_TEST_HOST_TOOLS) - {"unzip"}

    assert _missing_kali_builder_test_tools(
        lambda tool: f"/test/bin/{tool}" if tool in available else None
    ) == ("unzip",)


def test_kali_builder_precondition_accepts_complete_toolset() -> None:
    assert not _missing_kali_builder_test_tools(
        lambda tool: f"/test/bin/{tool}"
    )


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
    assert "Kali apt request" in apt_phase
    assert "APT_DPKG_BEFORE" in apt_phase
    assert "APT_DPKG_AFTER" in apt_phase
    assert "Kali apt packages ready" in apt_phase
    assert "chromium fluxbox novnc websockify xterm python3 ffuf sqlmap" in apt_phase

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


def test_kali_root_directory_mode_does_not_inherit_operator_umask() -> None:
    """A caller's umask 077 must not make the remapped rootfs opaque."""
    source = KALI_BUILDER.read_text()
    unpack_phase = source[
        source.index('echo "=== Unpacking ==="') :
        source.index("# Plumbing for chroot-installs.")
    ]

    assert '_as_root mv "$SAFEYOLO_ROOTFS_WORK_DIR/unpack/rootfs" "$TREE"' in unpack_phase
    assert '_as_root chmod 0755 "$TREE"' in unpack_phase
    assert unpack_phase.index("_as_root mv") < unpack_phase.index("_as_root chmod 0755")


def test_kali_staged_tree_is_verified_before_success() -> None:
    """The builder must not claim success for an unbootable copied tree."""
    source = KALI_BUILDER.read_text()
    staging = source[
        source.index('echo "=== Staging tree') :
        source.index("# Per-distro package caches")
    ]

    assert '_as_root chmod 0755 "$SAFEYOLO_ROOTFS_OUT_TREE"' in staging
    assert '_as_root chown -R 100000:100000 "$SAFEYOLO_ROOTFS_OUT_TREE"' in staging
    assert "etc workspace safeyolo safeyolo-status home/agent" in staging
    assert "usr/local/share/ca-certificates/safeyolo.crt" in staging
    assert '_as_root stat -c %u "$SAFEYOLO_ROOTFS_OUT_TREE"' in staging
    assert '_as_root stat -c %a "$SAFEYOLO_ROOTFS_OUT_TREE"' in staging
    assert source.index("Invalid staged rootfs ownership/mode") < source.index(
        'echo "=== Kali rootfs built successfully ==="'
    )


def test_kali_guest_installer_runs_with_strict_shell_errors() -> None:
    """A failed shared-helper command must stop the expensive build."""
    source = KALI_BUILDER.read_text()

    assert (
        "bash -c 'set -euo pipefail; source \"$1\"; "
        "install_safeyolo_guest_common \"$2\"'"
    ) in source


def test_kali_chroots_use_deterministic_utf8_locale() -> None:
    """Do not leak an unsupported operator locale into the minimal rootfs."""
    source = KALI_BUILDER.read_text()

    assert '"LANG=C.UTF-8"' in source
    assert '"LC_ALL=C.UTF-8"' in source
    assert source.count('/usr/bin/env -i "${CHROOT_ENV[@]}"') == 2


def test_kali_postinstall_reads_subordinate_tree_as_root() -> None:
    """Host-user probes must not assume private rootfs paths are readable."""
    source = KALI_BUILDER.read_text()

    assert "if _as_root grep -q '^PATH=' \"$TREE/etc/environment\"; then" in source
    assert "if grep -q '^PATH=' \"$TREE/etc/environment\"; then" not in source


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
