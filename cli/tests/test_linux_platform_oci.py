"""Unit tests for the Linux gVisor OCI spec builder.

Exercises behavior on the `_generate_oci_config` path. These tests instantiate
`LinuxPlatform` directly, hermetically scope the config dir + HOME via
tmp_path, and assert the spec shape and filesystem side-effects.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason=(
        "safeyolo.platform.linux imports Linux-only glue (runsc userns, "
        "/proc/self/ns/net wiring). Running it on macOS/darwin isn't "
        "meaningful and will fail at import. Linux-only by design."
    ),
)


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    """Scope SAFEYOLO_CONFIG_DIR and HOME to tmp_path.

    This keeps `get_agent_home_dir(name)` and `Path.home()` inside the
    test's tmp_path so we can materialize fake host paths under HOME
    without polluting the operator's real home directory.
    """
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    # Path.home() reads $HOME on POSIX; Linux-only test, so this holds.
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def test_extra_shares_under_home_precreate_destinations(isolated_env):
    """Nested bind-mount destinations under /home/agent must pre-exist
    on the host before runsc consumes the OCI spec.

    Why: with /home/agent now an OCI bind-mount backed by the host-side
    per-agent home dir (possibly empty on first boot), gVisor will try
    to resolve nested bind destinations against that directory. If the
    destination doesn't exist, runsc fails at container-create time
    rather than gracefully creating it. The `extra_shares` loop in
    `_generate_oci_config` therefore mkdirs each nested destination
    under the host-side `agent_home` before appending the mount entry.
    """
    from safeyolo.platform.linux import LinuxPlatform
    from safeyolo.vm import ensure_agent_persistent_dirs, get_agent_home_dir

    name = "probe-agent"

    # Materialize the per-agent host dirs and a fake host-side ~/.claude.
    ensure_agent_persistent_dirs(name)
    fake_claude = isolated_env / ".claude"
    fake_claude.mkdir()
    (fake_claude / "config.json").write_text("{}\n")

    plat = LinuxPlatform()
    spec = plat._generate_oci_config(  # noqa: SLF001 — private-but-tested by design
        name=name,
        rootfs_path=isolated_env / "agents" / name / "rootfs",
        workspace_path=str(isolated_env),
        config_share=isolated_env / "agents" / name / "config-share",
        fw_alloc={"host_ip": "127.0.0.1", "attribution_ip": "10.200.0.1"},
        cpus=1,
        memory_mb=1024,
        extra_shares=[(str(fake_claude), "/home/agent/.claude", True)],
    )

    # Side effect: the destination dir now exists under host-side agent_home.
    agent_home = get_agent_home_dir(name)
    assert (agent_home / ".claude").is_dir(), (
        f"_generate_oci_config did not pre-create {agent_home / '.claude'}. "
        f"Without this mkdir, runsc would fail at container-create time "
        f"because the OCI bind destination /home/agent/.claude has no "
        f"live target on the host side."
    )

    # Spec-level: the extra_share mount is wired through at the expected
    # guest path with rw semantics preserved (read_only=True → ro in opts).
    matches = [
        m for m in spec["mounts"]
        if m.get("destination") == "/home/agent/.claude"
    ]
    assert len(matches) == 1, (
        f"Expected exactly one /home/agent/.claude mount entry in OCI "
        f"spec; got {len(matches)}. Mount list: "
        f"{[m['destination'] for m in spec['mounts']]}"
    )
    m = matches[0]
    assert m["source"] == str(fake_claude.resolve()), m
    assert "ro" in m["options"], m


def test_package_cache_mount_root_ignores_restrictive_umask(isolated_env):
    """The `_apt` user must be able to traverse persistent cache roots."""
    from safeyolo.platform.linux import LinuxPlatform
    from safeyolo.vm import ensure_agent_persistent_dirs, get_agent_cache_dir

    name = "cache-agent"
    ensure_agent_persistent_dirs(name)
    agent_dir = isolated_env / "agents" / name
    (agent_dir / "cache-paths.txt").write_text("/var/lib/apt/lists\n")

    previous_umask = os.umask(0o077)
    try:
        spec = LinuxPlatform()._generate_oci_config(  # noqa: SLF001
            name=name,
            rootfs_path=agent_dir / "rootfs",
            workspace_path=str(isolated_env),
            config_share=agent_dir / "config-share",
            fw_alloc={"host_ip": "127.0.0.1", "attribution_ip": "10.200.0.8"},
            cpus=1,
            memory_mb=1024,
            extra_shares=None,
        )
    finally:
        os.umask(previous_umask)

    cache_dir = get_agent_cache_dir(name, "/var/lib/apt/lists")
    assert cache_dir.stat().st_mode & 0o777 == 0o755
    assert any(
        mount.get("destination") == "/var/lib/apt/lists"
        and mount.get("source") == str(cache_dir)
        for mount in spec["mounts"]
    )


def test_home_agent_is_bind_mounted(isolated_env):
    """The OCI spec must contain a /home/agent bind-mount sourced from
    the per-agent host dir.

    Why: without this mount, Linux gVisor writes to /home/agent land
    in the memory-backed rootfs overlay and vanish on sandbox stop.
    The blackbox `test_home_persistence` covers behavior end-to-end;
    this unit test guards the OCI spec shape directly so a refactor
    of the mount-list construction can't drop /home/agent silently.
    """
    from safeyolo.platform.linux import LinuxPlatform
    from safeyolo.vm import ensure_agent_persistent_dirs, get_agent_home_dir

    name = "probe-agent-home"
    ensure_agent_persistent_dirs(name)

    plat = LinuxPlatform()
    spec = plat._generate_oci_config(  # noqa: SLF001
        name=name,
        rootfs_path=isolated_env / "agents" / name / "rootfs",
        workspace_path=str(isolated_env),
        config_share=isolated_env / "agents" / name / "config-share",
        fw_alloc={"host_ip": "127.0.0.1", "attribution_ip": "10.200.0.2"},
        cpus=1,
        memory_mb=1024,
        extra_shares=None,
    )

    matches = [
        m for m in spec["mounts"]
        if m.get("destination") == "/home/agent"
    ]
    assert len(matches) == 1, (
        f"OCI spec missing /home/agent bind-mount. "
        f"Destinations: {[m['destination'] for m in spec['mounts']]}"
    )
    m = matches[0]
    assert m["type"] == "bind"
    assert m["source"] == str(get_agent_home_dir(name))
    # rw + nosuid + nodev — matches /workspace hardening.
    assert "rw" in m["options"]
    assert "nosuid" in m["options"]
    assert "nodev" in m["options"]


def test_workspace_dcache_zero_is_mount_local(isolated_env, monkeypatch):
    """Normal startup disables idle dentry retention only for /workspace."""
    from safeyolo.platform import linux
    from safeyolo.vm import ensure_agent_persistent_dirs

    name = "etxtbsy-workspace-dcache"
    ensure_agent_persistent_dirs(name)
    monkeypatch.delenv(linux.EXPERIMENT_WORKSPACE_DCACHE_ENV, raising=False)

    spec = linux.LinuxPlatform()._generate_oci_config(  # noqa: SLF001
        name=name,
        rootfs_path=isolated_env / "rootfs",
        workspace_path=str(isolated_env),
        config_share=isolated_env / "config-share",
        fw_alloc={"host_ip": "127.0.0.1", "attribution_ip": "10.200.0.9"},
        cpus=1,
        memory_mb=1024,
        extra_shares=None,
    )

    workspace = next(
        mount for mount in spec["mounts"]
        if mount["destination"] == "/workspace"
    )
    assert "dcache=0" in workspace["options"]
    assert all(
        not any(option.startswith("dcache=") for option in mount.get("options", []))
        for mount in spec["mounts"]
        if mount["destination"] != "/workspace"
    )


def test_etxtbsy_experiment_can_restore_cached_workspace_baseline(
    isolated_env, monkeypatch,
):
    """The archived experiment can still reproduce the pre-fix default."""
    from safeyolo.platform import linux
    from safeyolo.vm import ensure_agent_persistent_dirs

    name = "etxtbsy-workspace-baseline"
    ensure_agent_persistent_dirs(name)
    monkeypatch.setenv(linux.EXPERIMENT_WORKSPACE_DCACHE_ENV, "default")

    spec = linux.LinuxPlatform()._generate_oci_config(  # noqa: SLF001
        name=name,
        rootfs_path=isolated_env / "rootfs",
        workspace_path=str(isolated_env),
        config_share=isolated_env / "config-share",
        fw_alloc={"host_ip": "127.0.0.1", "attribution_ip": "10.200.0.11"},
        cpus=1,
        memory_mb=1024,
        extra_shares=None,
    )

    workspace = next(
        mount for mount in spec["mounts"]
        if mount["destination"] == "/workspace"
    )
    assert not any(option.startswith("dcache=") for option in workspace["options"])


def test_writable_extra_shares_get_dcache_zero_but_readonly_shares_do_not(
    isolated_env, monkeypatch,
):
    """Writable operator shares get host-exec semantics without global scope."""
    from safeyolo.platform import linux
    from safeyolo.vm import ensure_agent_persistent_dirs

    name = "etxtbsy-extra-share-scope"
    ensure_agent_persistent_dirs(name)
    monkeypatch.delenv(linux.EXPERIMENT_WORKSPACE_DCACHE_ENV, raising=False)
    writable = isolated_env / "writable-share"
    readonly = isolated_env / "readonly-share"
    writable.mkdir()
    readonly.mkdir()

    spec = linux.LinuxPlatform()._generate_oci_config(  # noqa: SLF001
        name=name,
        rootfs_path=isolated_env / "rootfs",
        workspace_path=str(isolated_env),
        config_share=isolated_env / "config-share",
        fw_alloc={"host_ip": "127.0.0.1", "attribution_ip": "10.200.0.12"},
        cpus=1,
        memory_mb=1024,
        extra_shares=[
            (str(writable), "/mnt/writable", False),
            (str(readonly), "/mnt/readonly", True),
        ],
    )

    workspace = next(m for m in spec["mounts"] if m["destination"] == "/workspace")
    extras = [
        m for m in spec["mounts"]
        if m["source"] in {str(writable), str(readonly)}
    ]
    assert "dcache=0" in workspace["options"]
    assert len(extras) == 2
    writable_mount = next(m for m in extras if m["source"] == str(writable))
    readonly_mount = next(m for m in extras if m["source"] == str(readonly))
    assert "rw" in writable_mount["options"]
    assert "dcache=0" in writable_mount["options"]
    assert "ro" in readonly_mount["options"]
    assert not any(option.startswith("dcache=") for option in readonly_mount["options"])
    assert all(
        {"nosuid", "nodev"}.issubset(mount["options"])
        for mount in (writable_mount, readonly_mount)
    )


def test_etxtbsy_experiment_runsc_flags_are_validated(monkeypatch):
    """Diagnostic values cannot inject text into the runsc shell command."""
    from safeyolo.platform import linux

    monkeypatch.setenv(linux.EXPERIMENT_RUNSC_DCACHE_ENV, "0")
    monkeypatch.setenv(linux.EXPERIMENT_RUNSC_DIRECTFS_ENV, "false")
    assert linux._experiment_runsc_flags() == [  # noqa: SLF001
        "--dcache=0",
        "--directfs=false",
    ]

    monkeypatch.setenv(linux.EXPERIMENT_RUNSC_DCACHE_ENV, "0; touch /tmp/oops")
    with pytest.raises(RuntimeError, match="non-negative integer"):
        linux._experiment_runsc_flags()  # noqa: SLF001


def test_etxtbsy_normal_startup_leaves_global_dcache_unset(monkeypatch):
    """Normal startup must preserve gVisor's per-mount dcache selection."""
    from safeyolo.platform import linux

    monkeypatch.delenv(linux.EXPERIMENT_RUNSC_DCACHE_ENV, raising=False)
    monkeypatch.delenv(linux.EXPERIMENT_RUNSC_DIRECTFS_ENV, raising=False)

    assert linux._experiment_runsc_flags() == []  # noqa: SLF001


def test_etxtbsy_experiment_workspace_dcache_rejects_invalid_value(
    isolated_env, monkeypatch,
):
    """An invalid mount option is rejected before an OCI spec is written."""
    from safeyolo.platform import linux
    from safeyolo.vm import ensure_agent_persistent_dirs

    name = "etxtbsy-invalid-dcache"
    ensure_agent_persistent_dirs(name)
    monkeypatch.setenv(linux.EXPERIMENT_WORKSPACE_DCACHE_ENV, "-1")

    with pytest.raises(RuntimeError, match="non-negative integer"):
        linux.LinuxPlatform()._generate_oci_config(  # noqa: SLF001
            name=name,
            rootfs_path=isolated_env / "rootfs",
            workspace_path=str(isolated_env),
            config_share=isolated_env / "config-share",
            fw_alloc={"host_ip": "127.0.0.1", "attribution_ip": "10.200.0.10"},
            cpus=1,
            memory_mb=1024,
            extra_shares=None,
        )


def test_oci_environment_pins_persistent_mise_paths(isolated_env):
    """The base sandbox environment points mise and PATH at agent home."""
    from safeyolo.platform.linux import LinuxPlatform
    from safeyolo.vm import ensure_agent_persistent_dirs

    name = "probe-agent-mise"
    ensure_agent_persistent_dirs(name)
    plat = LinuxPlatform()
    spec = plat._generate_oci_config(  # noqa: SLF001
        name=name,
        rootfs_path=isolated_env / "agents" / name / "rootfs",
        workspace_path=str(isolated_env),
        config_share=isolated_env / "agents" / name / "config-share",
        fw_alloc={"host_ip": "127.0.0.1", "attribution_ip": "10.200.0.3"},
        cpus=1,
        memory_mb=1024,
        extra_shares=None,
    )

    env = dict(item.split("=", 1) for item in spec["process"]["env"])
    assert env["MISE_DATA_DIR"] == "/home/agent/.mise"
    assert env["MISE_CONFIG_DIR"] == "/home/agent/.mise"
    assert env["MISE_CACHE_DIR"] == "/home/agent/.mise/cache"
    assert env["PATH"].startswith("/home/agent/.mise/shims:")


def test_proxy_mount_uses_stable_private_directory(isolated_env):
    """Socket replacement must remain visible to a running sandbox."""
    from safeyolo.platform.linux import LinuxPlatform
    from safeyolo.sockets import directory_for

    name = "proxy-mount"
    proxy_dir = directory_for(name, "10.200.0.4")
    proxy_dir.mkdir(parents=True)

    spec = LinuxPlatform()._generate_oci_config(  # noqa: SLF001
        name=name,
        rootfs_path=isolated_env / "rootfs",
        workspace_path=str(isolated_env),
        config_share=isolated_env / "config-share",
        fw_alloc={"host_ip": "127.0.0.1", "attribution_ip": "10.200.0.4"},
        cpus=1,
        memory_mb=1024,
        extra_shares=None,
    )

    mount = next(
        item for item in spec["mounts"]
        if item["destination"] == "/safeyolo/proxy"
    )
    assert mount["source"] == str(proxy_dir)
    assert {"rbind", "ro", "nosuid", "nodev"} <= set(mount["options"])
    assert mount["source"] != str(proxy_dir / "proxy.sock")


def test_prepare_rootfs_rejects_missing_bind_targets(isolated_env, monkeypatch):
    """A uid-remapped tree cannot be repaired by the host launcher."""
    from pathlib import Path

    from safeyolo.platform.linux import LinuxPlatform

    rootfs = isolated_env / "agents" / "incomplete" / "rootfs"
    (rootfs / "etc").mkdir(parents=True)

    platform = LinuxPlatform()
    monkeypatch.setattr(platform, "agent_rootfs_path", lambda _name: rootfs)
    original_stat = Path.stat

    def subordinate_root_stat(path, *args, **kwargs):
        if path == rootfs:
            return SimpleNamespace(st_uid=100000)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", subordinate_root_stat)

    with pytest.raises(RuntimeError, match=r"missing required.*?/workspace"):
        platform.prepare_rootfs("incomplete")


def test_runsc_command_restores_mise_after_environment_path():
    """runsc commands source mise activation after /etc/environment."""
    from safeyolo.platform.linux import _wrap_runsc_command

    wrapped = _wrap_runsc_command("codex --version")

    assert wrapped.index("/etc/environment") < wrapped.index("/etc/mise-activate.sh")
    assert wrapped.endswith("codex --version")


def test_native_port_forward_donates_connected_uds(isolated_env, monkeypatch):
    """Linux preview uses runsc stream mode without a host TCP listener."""
    from safeyolo.platform import linux

    created = []

    class FakePortForwardProcess:
        def __init__(self, command, **kwargs):
            self.command = command
            self.kwargs = kwargs
            self.returncode = 0
            stream_path = command[command.index("--stream") + 1]
            self.peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.peer.connect(stream_path)
            created.append(self)

        def communicate(self, timeout=None):
            assert timeout == linux.PORT_FORWARD_TIMEOUT_SECONDS
            return b"", b""

    monkeypatch.setattr(linux, "_get_userns_pid", lambda name: 4242)
    monkeypatch.setattr(linux, "_find_runsc", lambda: "/test/runsc")
    monkeypatch.setattr(linux, "_runsc_root", lambda: "/test/run")
    monkeypatch.setattr(linux.subprocess, "Popen", FakePortForwardProcess)

    relay = linux.LinuxPlatform().popen_port_forward("desktop-agent", 6080)
    process = created[0]
    stream_path = process.command[process.command.index("--stream") + 1]
    assert process.command[:6] == [
        "nsenter", "--user", "--net", "--target", "4242", "--",
    ]
    assert process.command[6:11] == [
        "/test/runsc", "--root", "/test/run", "port-forward", "--stream",
    ]
    assert process.command[-2:] == ["safeyolo-desktop-agent", "6080"]
    assert not os.path.exists(stream_path)
    assert "6080:6080" not in process.command

    relay.stdin.write(b"request")
    assert process.peer.recv(7) == b"request"
    process.peer.sendall(b"response")
    assert relay.stdout.read(8) == b"response"

    assert relay.wait(timeout=1) == 0
    assert relay.poll() == 0
    process.peer.close()


def test_remove_agent_dir_retries_subuid_tree_in_temporary_userns(
    isolated_env, monkeypatch,
):
    """Subordinate-owned rootfs trees are removed without host sudo."""
    from safeyolo.platform import linux

    name = "custom-rootfs"
    agent_dir = isolated_env / "agents" / name
    (agent_dir / "rootfs" / "etc").mkdir(parents=True)
    original_rmtree = shutil.rmtree
    attempts = 0

    def permission_then_delete(path):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise PermissionError(13, "Permission denied", str(path / "rootfs"))
        original_rmtree(path)

    def run_cleanup(cmd, *, check):
        assert check is False
        assert cmd == [
            "nsenter", "--user", "--net", "--target", "4242", "--",
            "setpriv", "--reuid=0", "--regid=0", "--clear-groups",
            "rm", "-rf", "--", str(agent_dir),
        ]
        permission_then_delete(agent_dir)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(linux.shutil, "rmtree", permission_then_delete)
    start_userns = lambda requested_name, *, persist_pid: (  # noqa: E731
        4242
        if requested_name == name and persist_pid is False
        else pytest.fail("unexpected userns arguments")
    )
    monkeypatch.setattr(linux, "_start_userns", start_userns)
    monkeypatch.setattr(linux, "_run", run_cleanup)
    killed = []
    monkeypatch.setattr(linux.os, "kill", lambda pid, sig: killed.append((pid, sig)))

    linux.LinuxPlatform().remove_agent_dir(name)

    assert not agent_dir.exists()
    assert attempts == 2
    assert killed == [(4242, 9)]
