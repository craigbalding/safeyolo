"""Executable regression tests for first-party agent host setup scripts."""

import os
import subprocess
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    ("script_name", "tool_name", "expected_args"),
    [
        (
            "codex-host-setup.sh",
            "codex",
            ["-s", "danger-full-access", "-a", "never", "--probe"],
        ),
        (
            "claude-host-setup.sh",
            "claude",
            ["--dangerously-skip-permissions", "--probe"],
        ),
    ],
)
def test_mise_installed_agent_is_immediately_executable(
    tmp_path: Path,
    script_name: str,
    tool_name: str,
    expected_args: list[str],
) -> None:
    """A first-boot mise install is visible to the following ``exec``.

    Linux invokes the generated command non-interactively. This test starts
    without mise environment variables or a shim path, matching the failing
    runsc-exec environment, then uses a fake mise to materialize the requested
    agent executable in ``MISE_DATA_DIR/shims``.
    """
    repo_root = Path(__file__).resolve().parents[2]
    setup_script = repo_root / "contrib" / script_name
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    fake_bin = tmp_path / "bin"
    operator_home.mkdir()
    fake_bin.mkdir()

    setup_env = os.environ.copy()
    setup_env.update(
        {
            "HOME": str(operator_home),
            "SAFEYOLO_AGENT_NAME": "test-agent",
            "SAFEYOLO_AGENT_HOME": str(agent_home),
            "SAFEYOLO_AGENT_FOLDER": str(tmp_path),
        }
    )
    subprocess.run([str(setup_script)], check=True, env=setup_env, capture_output=True, text=True)

    fake_mise = fake_bin / "mise"
    fake_mise.write_text(
        "#!/usr/bin/env python3\n"
        "import os\n"
        "from pathlib import Path\n"
        "if any(arg.startswith('npm:') for arg in __import__('sys').argv[1:]):\n"
        "    tool = Path(os.environ['MISE_DATA_DIR']) / 'shims' / os.environ['TEST_TOOL_NAME']\n"
        "    tool.parent.mkdir(parents=True, exist_ok=True)\n"
        "    tool.write_text(\"#!/bin/sh\\nprintf '%s\\\\n' \\\"$@\\\" > \\\"$TEST_EXEC_LOG\\\"\\n\")\n"
        "    tool.chmod(0o755)\n"
    )
    fake_mise.chmod(0o755)

    exec_log = tmp_path / "exec-args.txt"
    command_env = os.environ.copy()
    for key in list(command_env):
        if key.startswith(("MISE_", "__MISE_")) or key == "BASH_ENV":
            command_env.pop(key)
    command_env.update(
        {
            "HOME": str(agent_home),
            "PATH": f"{fake_bin}:/usr/bin:/bin",
            "TEST_EXEC_LOG": str(exec_log),
            "TEST_TOOL_NAME": tool_name,
        }
    )

    generated_command = agent_home / ".safeyolo-command"
    result = subprocess.run(
        [str(generated_command), "--probe"],
        env=command_env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    actual_args = exec_log.read_text().splitlines()
    for expected in expected_args:
        assert expected in actual_args
