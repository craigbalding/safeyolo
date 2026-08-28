"""Unit tests for macOS SSH command environment wrapping."""

import inspect

from safeyolo.platform import darwin


def test_darwin_commands_restore_global_only_mise_after_runtime_environment() -> None:
    """Every non-interactive SSH path loads proxy state, then mise."""
    wrapped = darwin._wrap_ssh_command("uv --version")  # noqa: SLF001

    assert wrapped.index("/etc/environment") < wrapped.index(
        "/etc/mise-activate.sh"
    )
    assert wrapped.endswith("uv --version")

    platform_source = inspect.getsource(darwin.DarwinPlatform)
    assert platform_source.count("_wrap_ssh_command(command)") == 3
