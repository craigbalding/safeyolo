"""Executable regression tests for first-party agent host setup scripts."""

import os
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE_SOURCE = REPO_ROOT / "docs" / "AGENTS.md"
SKILL_SOURCE = REPO_ROOT / "contrib" / "skills" / "safeyolo"
MANAGED_SKILL_REL = Path(".safeyolo/skills/safeyolo")
SKILL_LINK_TARGET = "../../.safeyolo/skills/safeyolo"


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
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(REPO_ROOT / "contrib" / script_name)],
        check=check,
        env=_setup_env(operator_home, agent_home, folder),
        capture_output=True,
        text=True,
    )


def _assert_managed_context(agent_home: Path, consumer_dir: str | None) -> None:
    assert (agent_home / ".safeyolo/AGENTS.md").read_bytes() == BASELINE_SOURCE.read_bytes()

    managed_skill = agent_home / MANAGED_SKILL_REL
    source_files = {
        path.relative_to(SKILL_SOURCE)
        for path in SKILL_SOURCE.rglob("*")
        if path.is_file()
    }
    managed_files = {
        path.relative_to(managed_skill)
        for path in managed_skill.rglob("*")
        if path.is_file()
    }
    assert managed_files == source_files
    for relative in source_files:
        assert (managed_skill / relative).read_bytes() == (SKILL_SOURCE / relative).read_bytes()

    if consumer_dir is not None:
        link = agent_home / consumer_dir / "skills" / "safeyolo"
        assert link.is_symlink()
        assert os.readlink(link) == SKILL_LINK_TARGET
        assert link.resolve() == managed_skill.resolve()


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
    stale = agent_home / MANAGED_SKILL_REL / "references" / "removed.md"
    stale.write_text("stale managed content\n")
    (agent_home / MANAGED_SKILL_REL / "SKILL.md").write_text("old managed content\n")

    _run_setup(script_name, operator_home, agent_home, tmp_path)

    _assert_managed_context(agent_home, consumer_dir)
    assert not stale.exists()
    assert instruction.read_text() == "user-owned instructions\n"
    assert personal_skill.read_text() == "user-owned skill\n"


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
    assert (agent_home / ".claude/skills/safeyolo/SKILL.md").read_bytes() == (
        SKILL_SOURCE / "SKILL.md"
    ).read_bytes()


def test_mise_shell_stages_vendor_neutral_context_without_agent_links(tmp_path: Path) -> None:
    operator_home = tmp_path / "operator"
    agent_home = tmp_path / "agent"
    operator_home.mkdir()

    _run_setup("mise-shell-host-setup.sh", operator_home, agent_home, tmp_path)

    _assert_managed_context(agent_home, None)
    assert not (agent_home / ".agents").exists()
    assert not (agent_home / ".claude").exists()


def test_shared_skill_has_cross_agent_frontmatter_and_direct_references() -> None:
    content = (SKILL_SOURCE / "SKILL.md").read_text()
    _, frontmatter, body = content.split("---", 2)
    metadata = yaml.safe_load(frontmatter)

    assert set(metadata) == {"name", "description"}
    assert metadata["name"] == "safeyolo"
    assert "SafeYolo" in metadata["description"]
    for reference in ("agent-api.md", "troubleshooting.md", "guest-tools.md"):
        assert f"references/{reference}" in body
        assert (SKILL_SOURCE / "references" / reference).is_file()


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


@pytest.mark.parametrize(
    "script_name",
    ("codex-host-setup.sh", "claude-host-setup.sh"),
)
def test_alpine_bootstrap_uses_noninteractive_guest_sudo(script_name: str) -> None:
    """First-boot package setup must never wait for a guest password."""
    source = (REPO_ROOT / "contrib" / script_name).read_text()

    assert "sudo -n apk add nodejs npm" in source
    assert "sudo apk add nodejs npm" not in source
