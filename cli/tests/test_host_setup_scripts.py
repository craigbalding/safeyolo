"""Executable regression tests for first-party agent host setup scripts."""

import json
import os
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE_SOURCE = REPO_ROOT / "docs" / "AGENTS.md"
SKILL_SOURCE = REPO_ROOT / "cli/src/safeyolo/agent_context/skills/safeyolo"
COORD_BOOTSTRAP_SOURCE = REPO_ROOT / "contrib/coord-mcp-bootstrap.sh"
COORD_LAUNCHER_SOURCE = REPO_ROOT / "contrib/safeyolo-coord-mcp-launcher.sh"
COORD_SHIM_SOURCE = REPO_ROOT / "contrib/safeyolo-coord-mcp.py"
CODEX_COORD_SUPERVISOR_SOURCE = REPO_ROOT / "contrib/codex-coord-supervisor.py"
SKILL_LINK_TARGET = "/safeyolo/skills/safeyolo"
LEGACY_SKILL_LINK_TARGET = "../../.safeyolo/skills/safeyolo"


def _setup_env(operator_home: Path, agent_home: Path, folder: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(operator_home),
            "SAFEYOLO_AGENT_NAME": "test-agent",
            "SAFEYOLO_AGENT_HOME": str(agent_home),
            "SAFEYOLO_AGENT_FOLDER": str(folder),
        }
    )
    return env


def _run_setup(
    script_name: str,
    operator_home: Path,
    agent_home: Path,
    folder: Path,
    *,
    check: bool = True,
    stage_coord_runtime: bool = True,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = _setup_env(operator_home, agent_home, folder)
    env.update(extra_env or {})
    result = subprocess.run(
        [str(REPO_ROOT / "contrib" / script_name)],
        check=check,
        env=env,
        capture_output=True,
        text=True,
    )
    # Executing the generated harness command is outside host setup itself.
    # Most tests provide fake harnesses and need a matching already-installed
    # coord runtime so they do not install packages over the network. Dedicated
    # bootstrap-failure coverage opts out below.
    if (
        result.returncode == 0
        and stage_coord_runtime
        and script_name
        in {"claude-host-setup.sh", "codex-host-setup.sh", "codex-coord-host-setup.sh"}
    ):
        coord_python = agent_home / ".safeyolo/venv/bin/python"
        coord_python.parent.mkdir(parents=True, exist_ok=True)
        coord_python.write_text("#!/bin/sh\nexit 0\n")
        coord_python.chmod(0o755)
    return result


def _assert_managed_context(agent_home: Path, consumer_dir: str | None) -> None:
    assert (agent_home / ".safeyolo/AGENTS.md").read_bytes() == BASELINE_SOURCE.read_bytes()

    if consumer_dir is not None:
        link = agent_home / consumer_dir / "skills" / "safeyolo"
        assert link.is_symlink()
        assert os.readlink(link) == SKILL_LINK_TARGET


@pytest.mark.parametrize(
    ("script_name", "tool_name", "expected_args", "consumer_dir"),
    [
        (
            "codex-host-setup.sh",
            "codex",
            ["-s", "danger-full-access", "-a", "never", "--probe"],
            ".agents",
        ),
        (
            "claude-host-setup.sh",
            "claude",
            ["--dangerously-skip-permissions", "--probe"],
            ".claude",
        ),
    ],
)
def test_mise_installed_agent_is_immediately_executable_with_context(
    tmp_path: Path,
    script_name: str,
    tool_name: str,
    expected_args: list[str],
    consumer_dir: str,
) -> None:
    """First-boot installs resolve and receive the exact SafeYolo baseline."""
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    fake_bin = tmp_path / "bin"
    operator_home.mkdir()
    fake_bin.mkdir()

    _run_setup(script_name, operator_home, agent_home, tmp_path)
    _assert_managed_context(agent_home, consumer_dir)

    fake_mise = fake_bin / "mise"
    fake_mise.write_text(
        "#!/usr/bin/env python3\n"
        "import os\n"
        "from pathlib import Path\n"
        "assert os.environ['MISE_OVERRIDE_CONFIG_FILENAMES'] == "
        "'/etc/safeyolo/mise-project-config-disabled.toml'\n"
        "assert os.environ['MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES'] == 'none'\n"
        "if any(arg.startswith('npm:') for arg in __import__('sys').argv[1:]):\n"
        "    tool = Path(os.environ['MISE_DATA_DIR']) / 'shims' / os.environ['TEST_TOOL_NAME']\n"
        "    tool.parent.mkdir(parents=True, exist_ok=True)\n"
        "    tool.write_text(\"#!/bin/sh\\nprintf '%s\\\\0' \\\"$@\\\" > \\\"$TEST_EXEC_LOG\\\"\\n\")\n"
        "    tool.chmod(0o755)\n"
    )
    fake_mise.chmod(0o755)

    exec_log = tmp_path / "exec-args.bin"
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
    actual_args = [
        arg.decode()
        for arg in exec_log.read_bytes().split(b"\0")
        if arg
    ]
    for expected in expected_args:
        assert expected in actual_args

    baseline = BASELINE_SOURCE.read_text().rstrip("\n")
    if tool_name == "codex":
        config_index = actual_args.index("-c")
        config_override = actual_args[config_index + 1]
        parsed = tomllib.loads(config_override)
        assert parsed == {"developer_instructions": baseline}
    else:
        prompt_index = actual_args.index("--append-system-prompt")
        assert actual_args[prompt_index + 1] == baseline


@pytest.mark.parametrize(
    "package_root",
    (
        "node_modules/@anthropic-ai/claude-code",
        "lib/node_modules/@anthropic-ai/claude-code",
    ),
)
def test_claude_bootstrap_repairs_mise_install_with_skipped_postinstall(
    tmp_path: Path,
    package_root: str,
) -> None:
    """Modern and legacy mise Claude placeholders are repaired before launch."""
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    fake_bin = tmp_path / "bin"
    operator_home.mkdir()
    fake_bin.mkdir()

    _run_setup("claude-host-setup.sh", operator_home, agent_home, tmp_path)

    shim = agent_home / ".mise/shims/claude"
    shim.parent.mkdir(parents=True)
    shim.write_text("#!/bin/sh\nexit 1\n")
    shim.chmod(0o755)

    install_dir = agent_home / ".mise/installs/npm-anthropic-ai-claude-code/2.1.235"
    postinstall = install_dir / package_root / "install.cjs"
    postinstall.parent.mkdir(parents=True)
    postinstall.write_text("// test fixture\n")

    fake_mise = fake_bin / "mise"
    fake_mise.write_text(
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        "from pathlib import Path\n"
        "with Path(os.environ['TEST_MISE_LOG']).open('a') as f:\n"
        "    f.write(' '.join(sys.argv[1:]) + '\\n')\n"
        "if sys.argv[1] == 'where':\n"
        "    print(os.environ['TEST_CLAUDE_INSTALL_DIR'])\n"
        "elif sys.argv[1] == 'exec':\n"
        "    shim = Path(os.environ['TEST_CLAUDE_SHIM'])\n"
        "    shim.write_text(\"#!/bin/sh\\n\"\n"
        "                    \"if [ \\\"$1\\\" = --version ]; then exit 0; fi\\n\"\n"
        "                    \"printf '%s\\\\0' \\\"$@\\\" > \\\"$TEST_EXEC_LOG\\\"\\n\")\n"
        "    shim.chmod(0o755)\n"
    )
    fake_mise.chmod(0o755)

    exec_log = tmp_path / "exec-args.bin"
    mise_log = tmp_path / "mise.log"
    command_env = os.environ.copy()
    for key in list(command_env):
        if key.startswith(("MISE_", "__MISE_")) or key == "BASH_ENV":
            command_env.pop(key)
    command_env.update(
        {
            "HOME": str(agent_home),
            "PATH": f"{fake_bin}:/usr/bin:/bin",
            "TEST_CLAUDE_INSTALL_DIR": str(install_dir),
            "TEST_CLAUDE_SHIM": str(shim),
            "TEST_EXEC_LOG": str(exec_log),
            "TEST_MISE_LOG": str(mise_log),
        }
    )

    result = subprocess.run(
        [str(agent_home / ".safeyolo-command"), "--probe"],
        env=command_env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    mise_calls = mise_log.read_text().splitlines()
    assert "where npm:@anthropic-ai/claude-code@latest" in mise_calls
    assert any(call.startswith("exec node@22 -- node ") for call in mise_calls)
    assert "--probe" in exec_log.read_bytes().decode().split("\0")


@pytest.mark.parametrize(
    ("script_name", "consumer_dir", "user_instruction"),
    [
        ("codex-host-setup.sh", ".agents", ".codex/AGENTS.md"),
        ("claude-host-setup.sh", ".claude", ".claude/CLAUDE.md"),
    ],
)
def test_context_staging_is_idempotent_and_preserves_user_files(
    tmp_path: Path,
    script_name: str,
    consumer_dir: str,
    user_instruction: str,
) -> None:
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    operator_home.mkdir()
    instruction = agent_home / user_instruction
    instruction.parent.mkdir(parents=True)
    instruction.write_text("user-owned instructions\n")
    personal_skill = agent_home / consumer_dir / "skills" / "personal" / "SKILL.md"
    personal_skill.parent.mkdir(parents=True)
    personal_skill.write_text("user-owned skill\n")

    _run_setup(script_name, operator_home, agent_home, tmp_path)
    _run_setup(script_name, operator_home, agent_home, tmp_path)

    _assert_managed_context(agent_home, consumer_dir)
    assert instruction.read_text() == "user-owned instructions\n"
    assert personal_skill.read_text() == "user-owned skill\n"


@pytest.mark.parametrize(
    "script_name",
    ("codex-host-setup.sh", "claude-host-setup.sh"),
)
def test_bundled_setup_registers_coord_mcp_idempotently_and_preserves_config(
    tmp_path: Path,
    script_name: str,
) -> None:
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    operator_home.mkdir()

    if script_name == "claude-host-setup.sh":
        config_path = agent_home / ".claude.json"
        config_path.parent.mkdir(parents=True)
        config_path.write_text(
            '{"custom": {"preserved": true}, "mcpServers": '
            '{"unrelated": {"command": "other"}}}\n'
        )
    else:
        config_path = agent_home / ".codex/config.toml"
        config_path.parent.mkdir(parents=True)
        config_path.write_text(
            'model = "preserved"\n\n'
            '[mcp_servers.unrelated]\ncommand = "other"\n'
        )

    _run_setup(script_name, operator_home, agent_home, tmp_path)
    _run_setup(script_name, operator_home, agent_home, tmp_path)

    staged_shim = agent_home / ".safeyolo/safeyolo-coord-mcp.py"
    staged_launcher = agent_home / ".safeyolo/safeyolo-coord-mcp-launcher"
    assert staged_shim.read_bytes() == COORD_SHIM_SOURCE.read_bytes()
    assert staged_shim.stat().st_mode & 0o111
    assert staged_launcher.read_bytes() == COORD_LAUNCHER_SOURCE.read_bytes()
    assert staged_launcher.stat().st_mode & 0o111
    command = (agent_home / ".safeyolo-command").read_text()
    assert command.count(
        "# ---- coord-mcp-bootstrap: mcp+httpx install (guarded, idempotent) ----"
    ) == 1

    if script_name == "claude-host-setup.sh":
        data = json.loads(config_path.read_text())
        assert data["custom"] == {"preserved": True}
        assert data["mcpServers"]["unrelated"] == {"command": "other"}
        managed = data["mcpServers"]["safeyolo-coord"]
    else:
        data = tomllib.loads(config_path.read_text())
        assert data["model"] == "preserved"
        assert data["mcp_servers"]["unrelated"] == {"command": "other"}
        managed = data["mcp_servers"]["safeyolo-coord"]

    expected = {
        "command": "/home/agent/.safeyolo/safeyolo-coord-mcp-launcher",
        "args": [],
    }
    if script_name == "codex-host-setup.sh":
        expected["tool_timeout_sec"] = 330
        assert expected["tool_timeout_sec"] > 300
    assert managed == expected


def test_codex_coord_registration_repairs_timeout_idempotently(
    tmp_path: Path,
) -> None:
    """Reapplying @codex repairs the old table and preserves its neighbours."""
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    operator_home.mkdir()
    config_path = agent_home / ".codex/config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        'model = "preserved"\n\n'
        "[mcp_servers.before]\n"
        'command = "before"\n\n'
        "[mcp_servers.safeyolo-coord]\n"
        'command = "old-launcher"\n'
        'args = ["--old"]\n\n'
        "[mcp_servers.after]\n"
        'command = "after"\n'
    )

    _run_setup("codex-host-setup.sh", operator_home, agent_home, tmp_path)
    first = config_path.read_text()
    _run_setup("codex-host-setup.sh", operator_home, agent_home, tmp_path)

    assert config_path.read_text() == first
    assert first.count("[mcp_servers.safeyolo-coord]") == 1
    data = tomllib.loads(first)
    assert data["model"] == "preserved"
    assert data["mcp_servers"]["before"] == {"command": "before"}
    assert data["mcp_servers"]["after"] == {"command": "after"}
    assert data["mcp_servers"]["safeyolo-coord"] == {
        "command": "/home/agent/.safeyolo/safeyolo-coord-mcp-launcher",
        "args": [],
        "tool_timeout_sec": 330,
    }


@pytest.mark.parametrize(
    ("script_name", "config_relative"),
    [
        ("codex-host-setup.sh", ".codex/config.toml"),
        ("claude-host-setup.sh", ".claude.json"),
    ],
)
def test_registered_coord_launcher_restores_safeyolo_environment(
    tmp_path: Path,
    script_name: str,
    config_relative: str,
) -> None:
    """The registered command must work when its parent drops proxy/CA vars."""
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    operator_home.mkdir()
    _run_setup(script_name, operator_home, agent_home, tmp_path)

    config_path = agent_home / config_relative
    if script_name == "codex-host-setup.sh":
        managed = tomllib.loads(config_path.read_text())["mcp_servers"][
            "safeyolo-coord"
        ]
    else:
        managed = json.loads(config_path.read_text())["mcpServers"][
            "safeyolo-coord"
        ]

    assert managed["command"] == (
        "/home/agent/.safeyolo/safeyolo-coord-mcp-launcher"
    )
    assert managed["args"] == []
    registered = Path(managed["command"])
    launcher = agent_home / registered.relative_to("/home/agent")

    proxy_values = {
        "HTTP_PROXY": "http://proxy-upper.example:8080",
        "HTTPS_PROXY": "http://proxy-upper.example:8080",
        "http_proxy": "http://proxy-lower.example:8080",
        "https_proxy": "http://proxy-lower.example:8080",
        "NO_PROXY": "localhost,upper.example",
        "no_proxy": "localhost,lower.example",
        "SSL_CERT_FILE": "/safe yolo/ca.pem",
        "REQUESTS_CA_BUNDLE": "/safe yolo/ca.pem",
        "NODE_EXTRA_CA_CERTS": "/safe yolo/ca.pem",
    }
    proxy_env = tmp_path / "proxy.env"
    proxy_env.write_text(
        "".join(f"export {key}={value!r}\n" for key, value in proxy_values.items())
        + "export HOME='/home/agent'\n"
    )

    fake_python = agent_home / ".safeyolo/venv/bin/python"
    fake_python.write_text(
        "#!/bin/sh\n"
        "printf 'adapter=%s\\n' \"$1\"\n"
        "env\n"
    )
    fake_python.chmod(0o755)

    sanitized_env = {
        "PATH": "/usr/bin:/bin",
        "SAFEYOLO_PROXY_ENV_FILE": str(proxy_env),
    }
    assert not set(proxy_values) & set(sanitized_env)
    result = subprocess.run(
        [str(launcher)],
        check=True,
        env=sanitized_env,
        capture_output=True,
        text=True,
    )

    output_env = dict(
        line.split("=", 1)
        for line in result.stdout.splitlines()
        if "=" in line
    )
    assert {key: output_env[key] for key in proxy_values} == proxy_values
    assert output_env["adapter"] == str(
        agent_home / ".safeyolo/safeyolo-coord-mcp.py"
    )


def test_coord_launcher_reports_missing_authoritative_environment(
    tmp_path: Path,
) -> None:
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    operator_home.mkdir()
    _run_setup("codex-host-setup.sh", operator_home, agent_home, tmp_path)

    launcher = agent_home / ".safeyolo/safeyolo-coord-mcp-launcher"
    result = subprocess.run(
        [str(launcher)],
        env={
            "PATH": "/usr/bin:/bin",
            "SAFEYOLO_PROXY_ENV_FILE": str(tmp_path / "missing-proxy.env"),
        },
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "cannot read" in result.stderr
    assert "missing-proxy.env" in result.stderr


def test_coord_dependency_failure_stops_harness_with_diagnostic(tmp_path: Path) -> None:
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    fake_bin = tmp_path / "bin"
    operator_home.mkdir()
    fake_bin.mkdir()
    _run_setup(
        "codex-host-setup.sh",
        operator_home,
        agent_home,
        tmp_path,
        stage_coord_runtime=False,
    )

    (fake_bin / "mise").write_text("#!/bin/sh\nexit 1\n")
    (fake_bin / "python3").write_text("#!/bin/sh\nexit 1\n")
    (fake_bin / "codex").write_text(
        "#!/bin/sh\n"
        'if [ "$1" = --version ]; then exit 0; fi\n'
        'touch "$TEST_HARNESS_STARTED"\n'
    )
    for executable in fake_bin.iterdir():
        executable.chmod(0o755)

    started = tmp_path / "harness-started"
    result = subprocess.run(
        [str(agent_home / ".safeyolo-command")],
        env={
            **os.environ,
            "HOME": str(agent_home),
            "PATH": f"{fake_bin}:/usr/bin:/bin",
            "TEST_HARNESS_STARTED": str(started),
        },
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "refusing to start the harness without safeyolo-coord" in result.stderr
    assert not started.exists()


@pytest.mark.parametrize(
    ("script_name", "config_relative", "invalid"),
    [
        ("claude-host-setup.sh", ".claude.json", "{invalid json\n"),
        ("codex-host-setup.sh", ".codex/config.toml", "[invalid\n"),
    ],
)
def test_bundled_setup_reports_invalid_harness_config(
    tmp_path: Path,
    script_name: str,
    config_relative: str,
    invalid: str,
) -> None:
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    operator_home.mkdir()
    config_path = agent_home / config_relative
    config_path.parent.mkdir(parents=True)
    config_path.write_text(invalid)

    result = _run_setup(
        script_name,
        operator_home,
        agent_home,
        tmp_path,
        check=False,
        stage_coord_runtime=False,
    )

    assert result.returncode != 0
    assert "cannot update invalid" in result.stderr


def test_wheel_manifest_includes_coord_runtime_files() -> None:
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    force_include = project["tool"]["hatch"]["build"]["targets"]["wheel"][
        "force-include"
    ]

    assert force_include["contrib/coord-mcp-bootstrap.sh"] == (
        "safeyolo/contrib/coord-mcp-bootstrap.sh"
    )
    assert force_include["contrib/safeyolo-coord-mcp-launcher.sh"] == (
        "safeyolo/contrib/safeyolo-coord-mcp-launcher.sh"
    )
    assert force_include["contrib/safeyolo-coord-mcp.py"] == (
        "safeyolo/contrib/safeyolo-coord-mcp.py"
    )
    assert force_include["contrib/codex-coord-host-setup.sh"] == (
        "safeyolo/contrib/codex-coord-host-setup.sh"
    )
    assert force_include["contrib/codex-coord-supervisor.py"] == (
        "safeyolo/contrib/codex-coord-supervisor.py"
    )
    assert force_include["docs/AGENTS.md"] == "safeyolo/docs/AGENTS.md"
    assert COORD_BOOTSTRAP_SOURCE.stat().st_mode & 0o111
    assert COORD_LAUNCHER_SOURCE.stat().st_mode & 0o111
    assert COORD_SHIM_SOURCE.stat().st_mode & 0o111
    assert CODEX_COORD_SUPERVISOR_SOURCE.stat().st_mode & 0o111


def test_codex_coord_setup_is_explicit_private_and_idempotent(tmp_path: Path) -> None:
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    operator_home.mkdir()
    requested = {
        "SAFEYOLO_CODEX_COORD_ROOMS": "backlog, releases",
        "SAFEYOLO_CODEX_COORDINATORS": "relay",
    }

    _run_setup(
        "codex-coord-host-setup.sh",
        operator_home,
        agent_home,
        tmp_path,
        extra_env=requested,
    )
    first_command = (agent_home / ".safeyolo-command").read_bytes()
    first_config = (agent_home / ".safeyolo/codex-coord-supervisor.json").read_bytes()
    _run_setup(
        "codex-coord-host-setup.sh",
        operator_home,
        agent_home,
        tmp_path,
        extra_env=requested,
    )

    command = (agent_home / ".safeyolo-command").read_text()
    config_path = agent_home / ".safeyolo/codex-coord-supervisor.json"
    config = json.loads(config_path.read_text())
    assert first_command == (agent_home / ".safeyolo-command").read_bytes()
    assert first_config == config_path.read_bytes()
    assert config == {
        "agent_name": "test-agent",
        "coordinators": ["relay"],
        "rooms": ["backlog", "releases"],
        "workspace": "/workspace",
    }
    assert config_path.stat().st_mode & 0o777 == 0o600
    assert (agent_home / ".safeyolo/codex-coord-supervisor.py").stat().st_mode & 0o111
    assert 'exec python3 "$HOME/.safeyolo/codex-coord-supervisor.py"' in command
    assert "--dangerously-bypass-approvals-and-sandbox" in command
    assert command.count("coord-mcp-bootstrap: mcp+httpx install") == 1


def test_normal_codex_setup_keeps_interactive_entrypoint(tmp_path: Path) -> None:
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    operator_home.mkdir()

    _run_setup("codex-host-setup.sh", operator_home, agent_home, tmp_path)

    command = (agent_home / ".safeyolo-command").read_text()
    assert 'exec codex "${args[@]}" "$@"' in command
    assert 'exec python3 "$HOME/.safeyolo/codex-coord-supervisor.py"' not in command
    assert not (agent_home / ".safeyolo/codex-coord-supervisor.json").exists()


@pytest.mark.parametrize(
    ("script_name", "consumer_dir"),
    [
        ("codex-host-setup.sh", ".agents"),
        ("claude-host-setup.sh", ".claude"),
    ],
)
def test_context_staging_migrates_legacy_managed_skill_link(
    tmp_path: Path,
    script_name: str,
    consumer_dir: str,
) -> None:
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    operator_home.mkdir()
    link = agent_home / consumer_dir / "skills" / "safeyolo"
    link.parent.mkdir(parents=True)
    link.symlink_to(LEGACY_SKILL_LINK_TARGET)

    _run_setup(script_name, operator_home, agent_home, tmp_path)

    assert link.is_symlink()
    assert os.readlink(link) == SKILL_LINK_TARGET


@pytest.mark.parametrize(
    ("script_name", "consumer_dir"),
    [
        ("codex-host-setup.sh", ".agents"),
        ("claude-host-setup.sh", ".claude"),
    ],
)
def test_context_staging_refuses_user_owned_safeyolo_skill(
    tmp_path: Path,
    script_name: str,
    consumer_dir: str,
) -> None:
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    operator_home.mkdir()
    collision = agent_home / consumer_dir / "skills" / "safeyolo"
    collision.mkdir(parents=True)
    marker = collision / "SKILL.md"
    marker.write_text("user-owned safeyolo skill\n")

    result = _run_setup(
        script_name,
        operator_home,
        agent_home,
        tmp_path,
        check=False,
    )

    assert result.returncode != 0
    assert "Refusing to replace existing user skill" in result.stderr
    assert marker.read_text() == "user-owned safeyolo skill\n"


def test_claude_setup_stages_personal_skills_but_reserves_safeyolo_name(
    tmp_path: Path,
) -> None:
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    personal = operator_home / ".claude/skills/personal/SKILL.md"
    colliding = operator_home / ".claude/skills/safeyolo/SKILL.md"
    personal.parent.mkdir(parents=True)
    colliding.parent.mkdir(parents=True)
    personal.write_text("operator personal skill\n")
    colliding.write_text("operator collision\n")

    result = _run_setup(
        "claude-host-setup.sh",
        operator_home,
        agent_home,
        tmp_path,
    )

    _assert_managed_context(agent_home, ".claude")
    assert (agent_home / ".claude/skills/personal/SKILL.md").read_text() == (
        "operator personal skill\n"
    )
    assert "reserved by SafeYolo" in result.stderr
    assert os.readlink(agent_home / ".claude/skills/safeyolo") == SKILL_LINK_TARGET


def test_mise_shell_stages_vendor_neutral_context_without_agent_links(tmp_path: Path) -> None:
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    operator_home.mkdir()

    _run_setup("mise-shell-host-setup.sh", operator_home, agent_home, tmp_path)

    _assert_managed_context(agent_home, None)
    assert not (agent_home / ".agents").exists()
    assert not (agent_home / ".claude").exists()


def test_mise_shell_command_forwards_runtime_args(tmp_path: Path) -> None:
    """The vendor-neutral shell adapter preserves SafeYolo run arguments."""
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    operator_home.mkdir()

    _run_setup("mise-shell-host-setup.sh", operator_home, agent_home, tmp_path)

    exec_log = tmp_path / "exec-arg.txt"
    command_env = os.environ.copy()
    command_env.update(
        {
            "HOME": str(agent_home),
            "TEST_EXEC_LOG": str(exec_log),
        }
    )
    result = subprocess.run(
        [
            str(agent_home / ".safeyolo-command"),
            "-c",
            'printf "%s" "$1" > "$TEST_EXEC_LOG"',
            "safeyolo-probe",
            "runtime argument",
        ],
        env=command_env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert exec_log.read_text() == "runtime argument"


def test_shared_skill_has_cross_agent_frontmatter_and_direct_references() -> None:
    content = (SKILL_SOURCE / "SKILL.md").read_text()
    _, frontmatter, body = content.split("---", 2)
    metadata = yaml.safe_load(frontmatter)

    assert set(metadata) == {"name", "description"}
    assert metadata["name"] == "safeyolo"
    assert "SafeYolo" in metadata["description"]
    for reference in (
        "agent-api.md",
        "troubleshooting.md",
        "guest-tools.md",
        "desktop.md",
    ):
        assert f"references/{reference}" in body
        assert (SKILL_SOURCE / "references" / reference).is_file()

    desktop = (SKILL_SOURCE / "references/desktop.md").read_text()
    for expected in (
        "safeyolo agent desktop AGENT --open",
        "/safeyolo/guest-desktop status",
        "cannot create the host preview",
        "Do not expose guest ports 5900 or 6080 directly",
    ):
        assert expected in desktop


def test_baseline_explains_guest_privilege_without_implying_host_root() -> None:
    """The always-on launch prompt must teach the supported package path."""
    content = BASELINE_SOURCE.read_text()

    for expected in (
        "sudo -n apt-get install -y PACKAGE",
        "sudo -n apk add PACKAGE",
        "setpriv --reuid=0 --regid=0 --clear-groups COMMAND",
        "root only inside the isolated guest",
        "safeyolo agent shell --root",
        "Linux gVisor discards installed OS-package files",
    ):
        assert expected in content

    guest_tools = (SKILL_SOURCE / "references/guest-tools.md").read_text()
    for expected in (
        "Guest root is not host root",
        "`sudo -n`",
        "for routine work",
        "expected to fail in a hardware microVM",
        "not a remedy for proxy policy, approval, or budget blocks",
    ):
        assert expected in guest_tools


def test_coord_guidance_requires_a_harness_visible_foreground_wait() -> None:
    baseline = BASELINE_SOURCE.read_text()
    coord = (SKILL_SOURCE / "references/coord.md").read_text()

    for expected in (
        "foreground",
        "wait_for_coord",
        "Do not use a detached/background shell process",
        "foreground/harness-visible",
    ):
        assert expected in baseline

    for expected in (
        "Primary foreground idle wait",
        "without returning that cursor as adoptable",
        "Do not use a detached or background shell process",
        "foreground, harness-visible operation",
        "retained context or deliberate catch-up",
    ):
        assert expected in coord


@pytest.mark.parametrize(
    "script_name",
    ("codex-host-setup.sh", "claude-host-setup.sh"),
)
def test_alpine_bootstrap_uses_noninteractive_guest_sudo(script_name: str) -> None:
    """First-boot package setup must never wait for a guest password."""
    source = (REPO_ROOT / "contrib" / script_name).read_text()

    assert "sudo -n apk add nodejs npm" in source
    assert "sudo apk add nodejs npm" not in source


def _codex_command_env(agent_home: Path, fake_bin: Path, tmp_path: Path) -> dict:
    env = os.environ.copy()
    for key in list(env):
        if key.startswith(("MISE_", "__MISE_")) or key == "BASH_ENV":
            env.pop(key)
    env.update({
        "HOME": str(agent_home),
        "PATH": f"{fake_bin}:/usr/bin:/bin",
        "TEST_CODEX_SHIM": str(fake_bin / "codex"),
        "TEST_EXEC_LOG": str(tmp_path / "codex-exec-args.bin"),
        "TEST_MISE_LOG": str(tmp_path / "codex-mise.log"),
        "TEST_INSTALLED_STATE": str(tmp_path / "installed-version"),
        "TEST_HEALTHY_CODEX": _HEALTHY_CODEX,
        "TEST_REMOTE_VERSION": "9.9.9",
    })
    return env


_HEALTHY_CODEX = (
    "#!/bin/sh\n"
    "if [ \"$1\" = --version ]; then echo 'codex-cli 0.0.0-test'; exit 0; fi\n"
    "printf '%s\\0' \"$@\" > \"$TEST_EXEC_LOG\"\n"
)

# A wrapper whose platform-native executable is gone: it is still present and
# on PATH, so `command -v codex` succeeds, but it cannot run. This is the state
# macOS Gatekeeper leaves behind when it trashes the vendored Mach-O over a
# revoked signing certificate, and the state a skipped npm postinstall leaves.
_BROKEN_CODEX = (
    "#!/bin/sh\n"
    "echo 'Error: could not find codex-aarch64-apple-darwin' >&2\n"
    "exit 1\n"
)

# Repairs the wrapper when asked to install, so the command can go on to exec.
_FAKE_MISE = (
    "#!/usr/bin/env python3\n"
    "import os, sys\n"
    "from pathlib import Path\n"
    "argv = sys.argv[1:]\n"
    "with Path(os.environ['TEST_MISE_LOG']).open('a') as f:\n"
    "    f.write(' '.join(argv) + '\\n')\n"
    "state = Path(os.environ['TEST_INSTALLED_STATE'])\n"
    "def installed():\n"
    "    return state.read_text().strip() if state.exists() else ''\n"
    "if argv[:2] == ['settings', 'get']:\n"
    "    if os.environ.get('TEST_MISE_HAS_MIN_AGE') == '1':\n"
    "        print('24h'); sys.exit(0)\n"
    "    print('Unknown setting', file=sys.stderr); sys.exit(1)\n"
    "if argv[:1] == ['latest']:\n"
    "    if '--installed' in argv:\n"
    "        v = installed()\n"
    "        print(v) if v else None\n"
    "        sys.exit(0)\n"
    "    remote = os.environ.get('TEST_REMOTE_VERSION', '')\n"
    "    if not remote:\n"
    "        sys.exit(1)\n"
    "    print(remote); sys.exit(0)\n"
    "if argv[:2] == ['use', '-g'] and 'codex' in argv[-1]:\n"
    "    state.write_text(argv[-1].split('@')[-1])\n"
    "    shim = Path(os.environ['TEST_CODEX_SHIM'])\n"
    "    shim.write_text(os.environ['TEST_HEALTHY_CODEX'])\n"
    "    shim.chmod(0o755)\n"
)


def test_codex_bootstrap_repairs_a_wrapper_whose_native_binary_is_gone(
    tmp_path: Path,
) -> None:
    """`command -v` is not a liveness check; `--version` has to be.

    Regression for the gap that let a Codex agent sit permanently unable to
    launch: the npm wrapper survived, so the install guard was skipped, and
    the following exec then failed every run with nothing repairing it.
    """
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    fake_bin = tmp_path / "bin"
    operator_home.mkdir()
    fake_bin.mkdir()

    _run_setup("codex-host-setup.sh", operator_home, agent_home, tmp_path)

    broken = fake_bin / "codex"
    broken.write_text(_BROKEN_CODEX)
    broken.chmod(0o755)
    (fake_bin / "mise").write_text(_FAKE_MISE)
    (fake_bin / "mise").chmod(0o755)

    env = _codex_command_env(agent_home, fake_bin, tmp_path)
    env["TEST_HEALTHY_CODEX"] = _HEALTHY_CODEX

    # The precondition the old guard got wrong.
    assert shutil.which("codex", path=str(fake_bin)), "wrapper should be on PATH"
    probe = subprocess.run([str(broken), "--version"], capture_output=True)
    assert probe.returncode != 0, "fixture wrapper should fail --version"

    result = subprocess.run(
        [str(agent_home / ".safeyolo-command"), "--probe"],
        env=env, capture_output=True, text=True,
    )

    assert result.returncode == 0, result.stderr
    mise_calls = Path(env["TEST_MISE_LOG"]).read_text().splitlines()
    assert any(c.startswith("use ") and "npm:@openai/codex@" in c
               for c in mise_calls), (
        f"install was skipped for a broken wrapper; mise calls were {mise_calls}"
    )
    args = Path(env["TEST_EXEC_LOG"]).read_bytes().decode().split("\0")
    assert "--probe" in args, "repaired codex was never exec'd"
    assert "danger-full-access" in args


def test_codex_bootstrap_does_not_reinstall_a_healthy_wrapper(
    tmp_path: Path,
) -> None:
    """The guard must stay a repair path, not an every-run reinstall."""
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    fake_bin = tmp_path / "bin"
    operator_home.mkdir()
    fake_bin.mkdir()

    _run_setup("codex-host-setup.sh", operator_home, agent_home, tmp_path)

    healthy = fake_bin / "codex"
    healthy.write_text(_HEALTHY_CODEX)
    healthy.chmod(0o755)
    (fake_bin / "mise").write_text(_FAKE_MISE)
    (fake_bin / "mise").chmod(0o755)

    env = _codex_command_env(agent_home, fake_bin, tmp_path)
    env["TEST_HEALTHY_CODEX"] = _HEALTHY_CODEX

    result = subprocess.run(
        [str(agent_home / ".safeyolo-command"), "--probe"],
        env=env, capture_output=True, text=True,
    )

    assert result.returncode == 0, result.stderr
    # Version queries are expected; an *install* is not.
    calls = Path(env["TEST_MISE_LOG"]).read_text().splitlines()
    assert not any(c.startswith("use ") for c in calls), (
        f"healthy wrapper triggered an install: {calls}"
    )
    assert "--probe" in Path(env["TEST_EXEC_LOG"]).read_bytes().decode().split("\0")


def test_codex_repair_installs_an_explicitly_resolved_remote_version(
    tmp_path: Path,
) -> None:
    """Repair must not lean on `@latest`.

    mise resolves `latest` against what is already installed, so on the repair
    path it can decide the broken install already satisfies the spec and do
    nothing. The remote version has to be resolved explicitly and installed by
    exact value.
    """
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    fake_bin = tmp_path / "bin"
    operator_home.mkdir()
    fake_bin.mkdir()
    _run_setup("codex-host-setup.sh", operator_home, agent_home, tmp_path)

    (fake_bin / "codex").write_text(_BROKEN_CODEX)
    (fake_bin / "codex").chmod(0o755)
    (fake_bin / "mise").write_text(_FAKE_MISE)
    (fake_bin / "mise").chmod(0o755)

    env = _codex_command_env(agent_home, fake_bin, tmp_path)
    Path(env["TEST_INSTALLED_STATE"]).write_text("0.130.0")   # the stale build

    result = subprocess.run(
        [str(agent_home / ".safeyolo-command"), "--probe"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr

    calls = Path(env["TEST_MISE_LOG"]).read_text().splitlines()
    assert any(c.startswith("latest npm:@openai/codex") and "--installed" not in c
               for c in calls), f"never resolved a remote version: {calls}"
    assert any("use -g --force npm:@openai/codex@9.9.9" in c for c in calls), (
        f"did not install the resolved version by exact value: {calls}"
    )
    assert not any(c.endswith("npm:@openai/codex@latest") and "use" in c
                   for c in calls), f"fell back to @latest: {calls}"


def test_codex_reports_but_does_not_take_a_newer_version(tmp_path: Path) -> None:
    """A healthy install is pinned; the operator is told, not upgraded."""
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    fake_bin = tmp_path / "bin"
    operator_home.mkdir()
    fake_bin.mkdir()
    _run_setup("codex-host-setup.sh", operator_home, agent_home, tmp_path)

    (fake_bin / "codex").write_text(_HEALTHY_CODEX)
    (fake_bin / "codex").chmod(0o755)
    (fake_bin / "mise").write_text(_FAKE_MISE)
    (fake_bin / "mise").chmod(0o755)

    env = _codex_command_env(agent_home, fake_bin, tmp_path)
    Path(env["TEST_INSTALLED_STATE"]).write_text("0.130.0")

    result = subprocess.run(
        [str(agent_home / ".safeyolo-command"), "--probe"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "codex 0.130.0" in result.stderr, result.stderr
    assert "9.9.9 is available" in result.stderr, result.stderr
    calls = Path(env["TEST_MISE_LOG"]).read_text().splitlines()
    assert not any(c.startswith("use ") for c in calls), (
        f"a healthy install was upgraded: {calls}"
    )


def test_codex_still_launches_when_remote_resolution_fails(tmp_path: Path) -> None:
    """Offline, or a registry outage, must not stop a broken agent repairing."""
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    fake_bin = tmp_path / "bin"
    operator_home.mkdir()
    fake_bin.mkdir()
    _run_setup("codex-host-setup.sh", operator_home, agent_home, tmp_path)

    (fake_bin / "codex").write_text(_BROKEN_CODEX)
    (fake_bin / "codex").chmod(0o755)
    (fake_bin / "mise").write_text(_FAKE_MISE)
    (fake_bin / "mise").chmod(0o755)

    env = _codex_command_env(agent_home, fake_bin, tmp_path)
    env["TEST_REMOTE_VERSION"] = ""          # remote lookup fails
    Path(env["TEST_INSTALLED_STATE"]).write_text("0.130.0")

    result = subprocess.run(
        [str(agent_home / ".safeyolo-command"), "--probe"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "could not resolve a remote version" in result.stderr
    calls = Path(env["TEST_MISE_LOG"]).read_text().splitlines()
    assert any("npm:@openai/codex@latest" in c and c.startswith("use") for c in calls)


def test_codex_warns_when_mise_lacks_min_release_age(tmp_path: Path) -> None:
    """Don't assume delayed-deployment protection that isn't there.

    mise only grew min_release_age recently; sandboxes provisioned with an
    older mise silently have no delay at all, so it has to be verified rather
    than exported and hoped for.
    """
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    fake_bin = tmp_path / "bin"
    operator_home.mkdir()
    fake_bin.mkdir()
    _run_setup("codex-host-setup.sh", operator_home, agent_home, tmp_path)

    (fake_bin / "codex").write_text(_HEALTHY_CODEX)
    (fake_bin / "codex").chmod(0o755)
    (fake_bin / "mise").write_text(_FAKE_MISE)
    (fake_bin / "mise").chmod(0o755)

    env = _codex_command_env(agent_home, fake_bin, tmp_path)
    Path(env["TEST_INSTALLED_STATE"]).write_text("9.9.9")

    unsupported = subprocess.run(
        [str(agent_home / ".safeyolo-command"), "--probe"],
        env=env, capture_output=True, text=True,
    )
    assert unsupported.returncode == 0, unsupported.stderr
    assert "no delayed-deployment protection" in unsupported.stderr

    supported = subprocess.run(
        [str(agent_home / ".safeyolo-command"), "--probe"],
        env={**env, "TEST_MISE_HAS_MIN_AGE": "1"}, capture_output=True, text=True,
    )
    assert supported.returncode == 0, supported.stderr
    assert "no delayed-deployment protection" not in supported.stderr


_HEALTHY_CLAUDE = (
    "#!/bin/sh\n"
    "if [ \"$1\" = --version ]; then echo '9.9.9 (Claude Code)'; exit 0; fi\n"
    "printf '%s\\0' \"$@\" > \"$TEST_EXEC_LOG\"\n"
)

# Wrapper present and on PATH, native binary gone: `command -v` succeeds,
# `--version` does not. Same shape as the Codex case.
_BROKEN_CLAUDE = (
    "#!/bin/sh\n"
    "echo 'Error: could not find @anthropic-ai/claude-code-linux-arm64' >&2\n"
    "exit 1\n"
)

_FAKE_MISE_CLAUDE = (
    "#!/usr/bin/env python3\n"
    "import os, sys\n"
    "from pathlib import Path\n"
    "argv = sys.argv[1:]\n"
    "with Path(os.environ['TEST_MISE_LOG']).open('a') as f:\n"
    "    f.write(' '.join(argv) + '\\n')\n"
    "state = Path(os.environ['TEST_INSTALLED_STATE'])\n"
    "if argv[:2] == ['settings', 'get']:\n"
    "    sys.exit(1)\n"
    "if argv[:1] == ['latest']:\n"
    "    if '--installed' in argv:\n"
    "        v = state.read_text().strip() if state.exists() else ''\n"
    "        if v: print(v)\n"
    "        sys.exit(0)\n"
    "    remote = os.environ.get('TEST_REMOTE_VERSION', '')\n"
    "    if not remote: sys.exit(1)\n"
    "    print(remote); sys.exit(0)\n"
    "if argv[:2] == ['use', '-g'] and 'claude-code' in argv[-1]:\n"
    "    state.write_text(argv[-1].split('@')[-1])\n"
    "    shim = Path(os.environ['TEST_CLAUDE_SHIM'])\n"
    "    shim.write_text(os.environ['TEST_HEALTHY_CLAUDE'])\n"
    "    shim.chmod(0o755)\n"
    "if argv[:1] == ['where']:\n"
    "    print(os.environ.get('TEST_CLAUDE_INSTALL_DIR', '/nonexistent'))\n"
)


def _claude_command_env(agent_home: Path, fake_bin: Path, tmp_path: Path) -> dict:
    env = os.environ.copy()
    for key in list(env):
        if key.startswith(("MISE_", "__MISE_")) or key == "BASH_ENV":
            env.pop(key)
    env.update({
        "HOME": str(agent_home),
        "PATH": f"{fake_bin}:/usr/bin:/bin",
        "TEST_CLAUDE_SHIM": str(fake_bin / "claude"),
        "TEST_EXEC_LOG": str(tmp_path / "claude-exec-args.bin"),
        "TEST_MISE_LOG": str(tmp_path / "claude-mise.log"),
        "TEST_INSTALLED_STATE": str(tmp_path / "claude-installed-version"),
        "TEST_HEALTHY_CLAUDE": _HEALTHY_CLAUDE,
        "TEST_REMOTE_VERSION": "9.9.9",
    })
    return env


def _stage_claude(tmp_path: Path, wrapper: str):
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    fake_bin = tmp_path / "bin"
    operator_home.mkdir()
    fake_bin.mkdir()
    _run_setup("claude-host-setup.sh", operator_home, agent_home, tmp_path)
    (fake_bin / "claude").write_text(wrapper)
    (fake_bin / "claude").chmod(0o755)
    (fake_bin / "mise").write_text(_FAKE_MISE_CLAUDE)
    (fake_bin / "mise").chmod(0o755)
    return agent_home, fake_bin


def test_claude_repair_installs_an_explicitly_resolved_remote_version(
    tmp_path: Path,
) -> None:
    """Parity with the Codex path, and the reason it needed its own test.

    The pre-existing Claude fixture's mise stub predated `latest`, so the
    script fell through to the `@latest` fallback and the test passed without
    ever exercising remote resolution.
    """
    agent_home, fake_bin = _stage_claude(tmp_path, _BROKEN_CLAUDE)
    env = _claude_command_env(agent_home, fake_bin, tmp_path)
    Path(env["TEST_INSTALLED_STATE"]).write_text("2.1.100")   # stale build

    result = subprocess.run(
        [str(agent_home / ".safeyolo-command"), "--probe"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr

    calls = Path(env["TEST_MISE_LOG"]).read_text().splitlines()
    assert any(c.startswith("latest npm:@anthropic-ai/claude-code")
               and "--installed" not in c for c in calls), (
        f"never resolved a remote version: {calls}")
    assert any("use -g --force npm:@anthropic-ai/claude-code@9.9.9" in c
               for c in calls), (
        f"did not install the resolved version by exact value: {calls}")
    assert not any(c.startswith("use") and c.endswith("claude-code@latest")
                   for c in calls), f"fell back to @latest: {calls}"
    assert "--probe" in Path(env["TEST_EXEC_LOG"]).read_bytes().decode().split("\0")


def test_claude_reports_but_does_not_take_a_newer_version(tmp_path: Path) -> None:
    agent_home, fake_bin = _stage_claude(tmp_path, _HEALTHY_CLAUDE)
    env = _claude_command_env(agent_home, fake_bin, tmp_path)
    Path(env["TEST_INSTALLED_STATE"]).write_text("2.1.100")

    result = subprocess.run(
        [str(agent_home / ".safeyolo-command"), "--probe"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "claude 2.1.100" in result.stderr, result.stderr
    assert "9.9.9 is available" in result.stderr, result.stderr
    calls = Path(env["TEST_MISE_LOG"]).read_text().splitlines()
    assert not any(c.startswith("use ") for c in calls), (
        f"a healthy install was upgraded: {calls}")
