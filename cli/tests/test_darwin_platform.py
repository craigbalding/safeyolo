"""Unit tests for macOS SSH session creation."""

import inspect
import subprocess

import pytest

from safeyolo.platform import darwin


def test_darwin_commands_restore_global_only_mise_after_runtime_environment() -> None:
    """Every non-interactive SSH path loads proxy state, then mise."""
    wrapped = darwin._wrap_ssh_command(  # noqa: SLF001
        "uv --version", user="agent"
    )

    assert wrapped.index("/etc/environment") < wrapped.index(
        "/etc/mise-activate.sh"
    )
    assert wrapped.endswith("uv --version")

    platform_source = inspect.getsource(darwin.DarwinPlatform)
    assert platform_source.count(
        "_wrap_ssh_command(command, user=ssh_user)"
    ) == 3


def test_darwin_normal_ssh_session_repairs_its_own_limit() -> None:
    """The normal session repairs its visible PID 1 and session shell."""
    wrapped = darwin._wrap_ssh_command("probe", user="agent")  # noqa: SLF001

    pid1 = (
        "/usr/local/bin/sudo -n /usr/bin/prlimit --pid 1 "
        "--nofile=65536:65536"
    )
    session = (
        '/usr/local/bin/sudo -n /usr/bin/prlimit --pid "$$" '
        "--nofile=65536:65536"
    )
    assert wrapped.index(pid1) < wrapped.index(session)
    assert wrapped.index(session) < wrapped.index("ulimit -Sn")
    assert wrapped.index("/proc/1/limits") < wrapped.index("probe")


def test_darwin_root_ssh_session_uses_direct_limit_operation() -> None:
    """The true root entry path does not use the agent sudo fallback."""
    wrapped = darwin._wrap_ssh_command("probe", user="root")  # noqa: SLF001

    assert "/usr/bin/prlimit --pid 1 --nofile=65536:65536" in wrapped
    assert '/usr/bin/prlimit --pid "$$" --nofile=65536:65536' in wrapped
    assert "/usr/local/bin/sudo" not in wrapped
    assert wrapped.index("/proc/1/limits") < wrapped.index("probe")


@pytest.mark.parametrize(
    ("user", "target", "uses_sudo"),
    [
        ("agent", "agent@sandbox", True),
        ("root", "root@sandbox", False),
    ],
)
def test_darwin_interactive_shell_repairs_limit_before_login_shell(
    monkeypatch, tmp_path, user, target, uses_sudo
) -> None:
    """Both interactive SSH identities repair before their login shell."""
    shell_socket = tmp_path / "shell.sock"
    shell_socket.touch()
    key = tmp_path / "id_ed25519"
    key.touch()
    captured = {}

    monkeypatch.setattr(darwin, "_shell_socket_path", lambda _name: shell_socket)
    monkeypatch.setattr(darwin, "get_ssh_key_path", lambda: key)

    def fake_run(command, *, stdin):
        captured["command"] = command
        captured["stdin"] = stdin
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(darwin.subprocess, "run", fake_run)

    result = darwin.DarwinPlatform().exec_in_sandbox(
        "agent1", None, user=user, interactive=True
    )

    command = captured["command"]
    assert result == 0
    assert "-t" in command
    assert target in command
    remote = command[-1]
    assert remote.index('/usr/bin/prlimit --pid "$$"') < remote.index(
        "exec /bin/bash -l"
    )
    assert ("/usr/local/bin/sudo" in remote) is uses_sudo
    assert captured["stdin"] is None
