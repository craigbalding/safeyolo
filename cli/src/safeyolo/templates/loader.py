"""Agent configuration loader from TOML files."""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CURRENT_SCHEMA_VERSION = 1


@dataclass
class InstallConfig:
    """Agent installation configuration."""
    mise: str  # e.g., "npm:@openai/codex"
    binary: str  # e.g., "codex"


@dataclass
class RunConfig:
    """Agent run configuration."""
    command: str  # e.g., "codex"
    args: list[str] = field(default_factory=list)  # Always included
    auto_args: list[str] = field(default_factory=list)  # Only with --auto flag

    @property
    def full_command(self) -> str:
        """Return command with args joined (without auto_args)."""
        if self.args:
            return f"{self.command} {' '.join(self.args)}"
        return self.command

    @property
    def auto_args_str(self) -> str:
        """Return auto_args as space-separated string."""
        return ' '.join(self.auto_args) if self.auto_args else ''


@dataclass
class AuthConfig:
    """Agent authentication configuration."""
    env_var: str  # e.g., "OPENAI_API_KEY"
    oauth_file: str  # e.g., ".codex/auth.json" (relative to $HOME)
    setup_hint: str  # e.g., "Run: codex login --device-auth"


@dataclass
class HostConfig:
    """Host directories/files to mount."""
    config_dirs: list[str] = field(default_factory=list)  # e.g., [".codex"]
    config_files: list[str] = field(default_factory=list)  # e.g., [".claude.json"]


@dataclass
class DockerConfig:
    """Docker escape hatch for custom configuration."""
    env: dict[str, str] = field(default_factory=dict)
    capabilities: list[str] = field(default_factory=list)
    sysctls: dict[str, str] = field(default_factory=dict)
    image: str | None = None  # Override base image


@dataclass
class InstructionsConfig:
    """Agent-specific instructions for container environment.

    Injection types:
    - system_file: Write to a system-level file (e.g., /etc/claude-code/CLAUDE.md)
    - cli_arg: Pass as CLI argument to run command
    """
    content: str = ""  # The actual instructions
    injection_type: str = "system_file"  # "system_file" or "cli_arg"
    path: str | None = None  # For system_file: e.g., "/etc/claude-code/CLAUDE.md"
    arg_name: str | None = None  # For cli_arg: e.g., "developer_instructions"


@dataclass
class AgentConfig:
    """Complete agent configuration."""
    name: str
    description: str
    install: InstallConfig
    run: RunConfig
    auth: AuthConfig
    host: HostConfig
    docker: DockerConfig
    instructions: InstructionsConfig
    schema_version: int = CURRENT_SCHEMA_VERSION


class AgentConfigError(Exception):
    """Error loading agent configuration."""
    pass


def load_agent_config(agent_dir: Path) -> AgentConfig:
    """Load agent configuration from agent.toml file.

    Args:
        agent_dir: Path to agent template directory containing agent.toml

    Returns:
        Parsed AgentConfig dataclass

    Raises:
        AgentConfigError: If file not found or invalid
    """
    toml_path = agent_dir / "agent.toml"
    if not toml_path.exists():
        raise AgentConfigError(f"agent.toml not found in {agent_dir}")

    try:
        data = tomllib.loads(toml_path.read_text())
    except tomllib.TOMLDecodeError as err:
        raise AgentConfigError(f"Invalid TOML in {toml_path}: {err}") from err

    # Validate schema version
    schema_version = data.get("schema_version", 1)
    if schema_version > CURRENT_SCHEMA_VERSION:
        raise AgentConfigError(
            f"agent.toml schema version {schema_version} is newer than supported {CURRENT_SCHEMA_VERSION}"
        )

    # Parse sections
    agent = data.get("agent", {})
    install = data.get("install", {})
    run = data.get("run", {})
    auth = data.get("auth", {})
    host = data.get("host", {})
    docker = data.get("docker", {})
    instructions = data.get("instructions", {})
    injection = instructions.get("injection", {})

    return AgentConfig(
        name=agent.get("name", agent_dir.name),
        description=agent.get("description", ""),
        install=InstallConfig(
            mise=install.get("mise", ""),
            binary=install.get("binary", ""),
        ),
        run=RunConfig(
            command=run.get("command", ""),
            args=run.get("args", []),
            auto_args=run.get("auto_args", []),
        ),
        auth=AuthConfig(
            env_var=auth.get("env_var", ""),
            oauth_file=auth.get("oauth_file", ""),
            setup_hint=auth.get("setup_hint", ""),
        ),
        host=HostConfig(
            config_dirs=host.get("config_dirs", []),
            config_files=host.get("config_files", []),
        ),
        docker=DockerConfig(
            env=docker.get("env", {}),
            capabilities=docker.get("capabilities", []),
            sysctls=docker.get("sysctls", {}),
            image=docker.get("image"),
        ),
        instructions=InstructionsConfig(
            content=instructions.get("content", ""),
            injection_type=injection.get("type", "system_file"),
            path=injection.get("path"),
            arg_name=injection.get("arg_name"),
        ),
        schema_version=schema_version,
    )
