"""Unit tests for the Linux gVisor OCI spec builder.

Exercises behavior on the `_generate_oci_config` path that isn't
reachable via the blackbox suite because the CLI doesn't currently
wire `extra_shares` to any public flag. These tests instantiate
`LinuxPlatform` directly, hermetically scope the config dir + HOME
via tmp_path, and assert the spec shape and filesystem side-effects.
"""
from __future__ import annotations

import sys

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
