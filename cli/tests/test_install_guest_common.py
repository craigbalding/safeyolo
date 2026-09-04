"""Tests for the shared custom-rootfs guest installer."""

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GUEST_DIR = REPO_ROOT / "guest"
GLOBAL_ONLY_CONFIG = "/etc/safeyolo/mise-project-config-disabled.toml"


def test_installer_rejects_rootfs_without_prlimit(tmp_path: Path) -> None:
    """The PID 1 boot dependency must fail at image build time."""
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    command = (
        "chroot() { return 1; }; "
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

    assert result.returncode != 0
    assert "missing prlimit in rootfs" in result.stderr


def test_installer_precreates_runtime_bind_mount_targets(tmp_path: Path) -> None:
    """Custom rootfs trees must be complete before Linux uid remapping."""
    rootfs = tmp_path / "rootfs"
    (rootfs / "usr/sbin").mkdir(parents=True)
    (rootfs / "usr/bin").mkdir(parents=True)
    (rootfs / "usr/local/bin").mkdir(parents=True)
    (rootfs / "etc").mkdir(parents=True)
    (rootfs / "etc/passwd").write_text(
        "agent:x:1000:1000::/home/agent:/bin/bash\n"
    )
    (rootfs / "etc/group").write_text("sudo:x:27:\n")
    (rootfs / "usr/sbin/useradd").touch()
    (rootfs / "usr/sbin/useradd").chmod(0o755)
    (rootfs / "usr/sbin/visudo").touch()
    (rootfs / "usr/sbin/visudo").chmod(0o755)
    (rootfs / "usr/bin/sudo").touch()
    (rootfs / "usr/bin/sudo").chmod(0o755)

    command = (
        "chroot() { "
        "  case \"$*\" in *' id -nG agent') echo 'agent sudo';; esac; "
        "  return 0; "
        "}; "
        "chown() { return 0; }; "
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

    sudo_shim = rootfs / "usr/local/bin/sudo"
    assert sudo_shim.is_file()
    assert sudo_shim.stat().st_mode & 0o777 == 0o755
    assert 'REAL_SUDO=/usr/bin/sudo' in sudo_shim.read_text()
    assert 'SETPRIV=/usr/bin/setpriv' in sudo_shim.read_text()

    sudoers = rootfs / "etc/sudoers.d/safeyolo-agent"
    assert sudoers.is_file()
    assert sudoers.stat().st_mode & 0o777 == 0o440
    assert "agent ALL=(ALL) NOPASSWD:ALL" in sudoers.read_text()
    assert "Defaults env_keep +=" in sudoers.read_text()


def test_privilege_helper_requires_group_and_policy_validation_tools(
    tmp_path: Path,
) -> None:
    """A sudo-capable image must not silently ship an unvalidated policy."""
    rootfs = tmp_path / "rootfs"
    (rootfs / "usr/bin").mkdir(parents=True)
    (rootfs / "usr/local/bin").mkdir(parents=True)
    (rootfs / "etc/sudoers.d").mkdir(parents=True)
    (rootfs / "etc").mkdir(exist_ok=True)
    (rootfs / "etc/passwd").write_text(
        "agent:x:1000:1000::/home/agent:/bin/bash\n"
    )
    (rootfs / "etc/group").write_text("sudo:x:27:agent\n")
    (rootfs / "usr/bin/sudo").touch()
    (rootfs / "usr/bin/sudo").chmod(0o755)
    (rootfs / "usr/sbin").mkdir()
    (rootfs / "usr/sbin/visudo").touch()
    (rootfs / "usr/sbin/visudo").chmod(0o755)
    log = tmp_path / "chroot.log"

    command = (
        "chroot() { "
        f"  printf '%s\\n' \"$*\" >> '{log}'; "
        "  case \"$*\" in *' id -nG agent') echo 'agent sudo';; esac; "
        "  return 0; "
        "}; "
        "chown() { printf '%s\\n' \"$*\" >> \"$TEST_CHOWN_LOG\"; return 0; }; "
        'source "$SAFEYOLO_GUEST_SRC_DIR/install-guest-common.sh"; '
        'install_safeyolo_privilege_helper "$TEST_ROOTFS"'
    )
    chown_log = tmp_path / "chown.log"
    result = subprocess.run(
        ["bash", "-c", command],
        env={
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "SAFEYOLO_GUEST_SRC_DIR": str(GUEST_DIR),
            "TEST_ROOTFS": str(rootfs),
            "TEST_CHOWN_LOG": str(chown_log),
        },
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    calls = log.read_text().splitlines()
    assert any("usermod -a -G sudo agent" in call for call in calls)
    assert any("visudo -cf /etc/sudoers.d/safeyolo-agent.tmp." in call for call in calls)
    assert any(call.startswith("0:0 ") for call in chown_log.read_text().splitlines())


def test_sudoers_policy_is_valid_with_system_visudo(tmp_path: Path) -> None:
    """The exact generated user rule and environment preservation parse."""
    visudo = Path("/usr/sbin/visudo")
    if not visudo.exists():
        return
    policy = tmp_path / "safeyolo-agent"
    policy.write_text(
        "agent ALL=(ALL) NOPASSWD:ALL\n"
        "Defaults env_keep += \"HTTP_PROXY HTTPS_PROXY http_proxy https_proxy "
        "NO_PROXY no_proxy SSL_CERT_FILE REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS\"\n"
    )
    policy.chmod(0o440)
    result = subprocess.run(
        [str(visudo), "-cf", str(policy)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_default_rootfs_hook_uses_shared_mount_target_installer() -> None:
    """The default and custom builders must not drift again."""
    source = (GUEST_DIR / "rootfs-customize-hook.sh").read_text()

    assert 'source "$SAFEYOLO_GUEST_SRC_DIR/install-guest-common.sh"' in source
    assert 'install_safeyolo_mise_integration "$ROOTFS"' in source
    assert 'install_safeyolo_runtime_mount_targets "$ROOTFS"' in source
    assert 'install_safeyolo_privilege_helper "$ROOTFS"' in source


def test_default_and_custom_builders_share_current_mise_pin() -> None:
    """The default base and custom rootfs helper must use one verified pin."""
    default_builder = (GUEST_DIR / "build-rootfs.sh").read_text()
    custom_helper = (GUEST_DIR / "install-guest-common.sh").read_text()

    for value in (
        "2026.8.8",
        "6e6e96d319fe274996db5aed691f5398552865e641dc4b6fb6b01d73f4853a17",
        "58edfbdba6d4255b6536a61daeaf3b21f7a059430c789e948c8494ba32d59e1f",
    ):
        assert value in default_builder
        assert value in custom_helper


def test_default_builder_supports_a_host_without_resolv_conf() -> None:
    """Nested SafeYolo relies on its outer proxy and has no host resolver."""
    source = (GUEST_DIR / "build-rootfs.sh").read_text()

    assert "if [ -r /etc/resolv.conf ]; then" in source
    assert 'sudo cp /etc/resolv.conf "$ROOTFS/etc/resolv.conf"' not in source
    assert source.index("if [ -r /etc/resolv.conf ]; then") < source.index(
        'sudo chroot "$ROOTFS" /usr/bin/apt-get update'
    )


def test_default_builder_stages_then_removes_inherited_tls_ca() -> None:
    """The outer proxy CA is build-only state, not part of the artifact."""
    source = (GUEST_DIR / "build-rootfs.sh").read_text()

    stage = 'sudo install -D -m 0644 -- "$SSL_CERT_FILE" "$BUILD_SSL_CERT_DEST"'
    first_chroot = 'sudo chroot "$ROOTFS" /usr/bin/apt-get update'
    cleanup = 'sudo rm -f -- "$BUILD_SSL_CERT_DEST"'
    empty_runtime_target = (
        'sudo install -D -m 0644 /dev/null "$BUILD_SSL_CERT_DEST"'
    )
    emit = 'echo "=== Emitting directory tree ==="'
    assert source.index(stage) < source.index(first_chroot)
    assert source.index(first_chroot) < source.index(cleanup) < source.index(emit)
    assert source.index(cleanup) < source.index(empty_runtime_target) < source.index(emit)


def test_mise_integration_keeps_ordinary_tools_global_and_has_explicit_opt_in(
    tmp_path: Path,
) -> None:
    """An untrusted workspace config cannot intercept a global tool command."""
    rootfs = tmp_path / "rootfs"
    (rootfs / "usr/sbin").mkdir(parents=True)
    (rootfs / "usr/bin").mkdir(parents=True)
    (rootfs / "usr/local/bin").mkdir(parents=True)
    (rootfs / "etc").mkdir(parents=True)
    (rootfs / "etc/passwd").write_text(
        "agent:x:1000:1000::/home/agent:/bin/bash\n"
    )
    for executable in ("usr/sbin/useradd", "usr/bin/sudo"):
        target = rootfs / executable
        target.touch()
        target.chmod(0o755)

    fake_mise = rootfs / "usr/local/bin/mise"
    fake_mise.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = project-probe ]; then\n"
        "  [ -z \"${MISE_OVERRIDE_CONFIG_FILENAMES+x}\" ] || exit 93\n"
        "  [ -z \"${MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES+x}\" ] || exit 94\n"
        "  [ -f ./mise.toml ] || exit 95\n"
        "  printf 'project|%s|%s\\n' \"$HTTP_PROXY\" \"$SSL_CERT_FILE\"\n"
        "fi\n"
    )
    fake_mise.chmod(0o755)

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

    profile = rootfs / "etc/profile.d/mise.sh"
    runtime_environment = rootfs / "etc/safeyolo-mise-environment"
    environment = (rootfs / "etc/environment").read_text()
    wrapper = rootfs / "usr/local/bin/mise-project"
    profile_text = profile.read_text()
    assert f'MISE_OVERRIDE_CONFIG_FILENAMES="{GLOBAL_ONLY_CONFIG}"' in profile_text
    assert 'MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES="none"' in profile_text
    assert "mise activate" not in profile_text
    assert f"MISE_OVERRIDE_CONFIG_FILENAMES={GLOBAL_ONLY_CONFIG}" in environment
    assert "MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES=none" in environment
    assert "BASH_ENV=/etc/mise-activate.sh" in environment
    assert runtime_environment.read_text() in environment
    assert wrapper.stat().st_mode & 0o777 == 0o755

    agent_home = tmp_path / "agent-home"
    global_tool = agent_home / ".mise/shims/uv"
    global_tool.parent.mkdir(parents=True)
    global_tool.write_text(
        "#!/bin/sh\n"
        f"[ \"$MISE_OVERRIDE_CONFIG_FILENAMES\" = \"{GLOBAL_ONLY_CONFIG}\" ] || exit 91\n"
        "[ \"$MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES\" = none ] || exit 92\n"
        "printf 'global-tool\\n'\n"
    )
    global_tool.chmod(0o755)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "mise.toml").write_text(
        '[tools]\nuv = "untrusted"\n[env]\nINTERCEPTED = "yes"\n'
    )

    ordinary = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", '. "$TEST_PROFILE"; uv'],
        cwd=workspace,
        env={
            "HOME": str(agent_home),
            "PATH": f"{rootfs / 'usr/local/bin'}:/usr/bin:/bin",
            "TEST_PROFILE": str(profile),
        },
        capture_output=True,
        text=True,
    )
    assert ordinary.returncode == 0, ordinary.stderr
    assert ordinary.stdout == "global-tool\n"

    opted_in = subprocess.run(
        [str(wrapper), "project-probe"],
        cwd=workspace,
        env={
            "HOME": str(agent_home),
            "PATH": f"{rootfs / 'usr/local/bin'}:/usr/bin:/bin",
            "HTTP_PROXY": "http://proxy.invalid:8080",
            "SSL_CERT_FILE": "/safeyolo/ca.crt",
            "MISE_OVERRIDE_CONFIG_FILENAMES": GLOBAL_ONLY_CONFIG,
            "MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES": "none",
        },
        capture_output=True,
        text=True,
    )
    assert opted_in.returncode == 0, opted_in.stderr
    assert opted_in.stdout == (
        "project|http://proxy.invalid:8080|/safeyolo/ca.crt\n"
    )


def test_standard_setup_paths_only_write_global_mise_configuration() -> None:
    """SafeYolo startup/install scripts never create repository mise config."""
    paths = (
        GUEST_DIR / "install-guest-common.sh",
        GUEST_DIR / "rootfs-customize-hook.sh",
        REPO_ROOT / "contrib/codex-host-setup.sh",
        REPO_ROOT / "contrib/claude-host-setup.sh",
        REPO_ROOT / "contrib/mise-shell-host-setup.sh",
    )
    for path in paths:
        commands = [
            line.strip()
            for line in path.read_text().splitlines()
            if line.strip().startswith("mise use ")
        ]
        assert all(command.startswith("mise use -g ") for command in commands), path

    tracked_project_configs = subprocess.run(
        [
            "git", "ls-files", "mise.toml", ".mise.toml",
            "**/mise.toml", "**/.mise.toml",
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    assert tracked_project_configs == []


def test_vsock_harness_starts_with_project_mise_discovery_disabled() -> None:
    """Direct microVM harness exec does not depend on shell profile loading."""
    source = (GUEST_DIR / "vsock-term.c").read_text()

    assert 'setenv("MISE_OVERRIDE_CONFIG_FILENAMES",' in source
    assert '"/etc/safeyolo/mise-project-config-disabled.toml", 1);' in source
    assert 'setenv("MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES", "none", 1);' in source
    assert 'setenv("BASH_ENV", "/etc/mise-activate.sh", 1);' in source


def test_guest_init_reapplies_mise_after_rebuilding_environment() -> None:
    """Cold boot and restore cannot discard the rootfs-owned mise baseline."""
    for script_name in ("guest-init-static.sh", "guest-init-per-run.sh"):
        source = (REPO_ROOT / "cli/src/safeyolo" / script_name).read_text()
        rebuild = source.index("cp /safeyolo/proxy.env /etc/environment")
        restore = source.index(
            "cat /etc/safeyolo-mise-environment >> /etc/environment"
        )
        assert rebuild < restore, script_name


def test_guest_installer_does_not_hide_agent_creation_failure() -> None:
    """Idempotency must distinguish an existing account from failed useradd."""
    source = (GUEST_DIR / "install-guest-common.sh").read_text()

    assert "if ! grep -q '^agent:[^:]*:1000:'" in source
    assert 'chroot "$rootfs" useradd -m -s /bin/bash -u 1000 agent' in source
    assert "useradd -m -s /bin/bash -u 1000 agent 2>/dev/null || true" not in source
    assert 'for required_dir in workspace safeyolo safeyolo-status home/agent' in source


def test_guest_installer_unlocks_root_for_pubkey_auth() -> None:
    """`safeyolo agent shell --root` SSHes to root@sandbox on the
    macOS microVM. Debian bases ship root with pw="!" (locked), and
    OpenSSH on Alpine (9.7+) refuses pubkey auth against locked
    accounts. Unlocking root at rootfs build time mirrors the
    existing `usermod -p '*' agent` pattern. Regression guard for #296.
    """
    source = (GUEST_DIR / "install-guest-common.sh").read_text()

    assert 'chroot "$rootfs" usermod -p \'*\' root' in source
    # PasswordAuthentication is off in the sshd_config the same
    # installer writes -- clearing the lock does NOT enable password
    # login. Verify that guard still holds for anyone reading this
    # test in isolation.
    assert 'PasswordAuthentication no' in source
