"""Unit tests for the Linux gVisor OCI spec builder.

Exercises behavior on the `_generate_oci_config` path that isn't
reachable via the blackbox suite because the CLI doesn't currently
wire `extra_shares` to any public flag. These tests instantiate
`LinuxPlatform` directly, hermetically scope the config dir + HOME
via tmp_path, and assert the spec shape and filesystem side-effects.
"""
from __future__ import annotations

import shutil
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
        extra_shares=[(str(fake_claude), "claude", True)],
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
