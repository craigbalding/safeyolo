"""Template management for agent configurations."""

import os
from dataclasses import dataclass, field
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from ..config import (
    CA_VOLUME_NAME,
    PROXY_CONTAINER_NAME,
)
from ..discovery import get_compose_network_name
from .loader import AgentConfig, AgentConfigError, load_agent_config


class TemplateError(Exception):
    """Template operation failed."""
    pass


TEMPLATES_DIR = Path(__file__).parent / "agents"


@dataclass
class HostConfigStatus:
    """Status of detected host config files/directories."""
    found_dirs: list[str] = field(default_factory=list)
    found_files: list[str] = field(default_factory=list)


def detect_host_config_for_agent(agent_config: AgentConfig) -> HostConfigStatus:
    """Detect which host config files exist for this agent.

    Args:
        agent_config: Agent configuration specifying what to look for

    Returns:
        HostConfigStatus with lists of found dirs and files
    """
    home = Path.home()
    status = HostConfigStatus()

    for dir_name in agent_config.host.config_dirs:
        if (home / dir_name).is_dir():
            status.found_dirs.append(dir_name)

    for file_name in agent_config.host.config_files:
        if (home / file_name).is_file():
            status.found_files.append(file_name)

    return status


def get_available_templates() -> dict[str, str]:
    """Get dict of template_name -> description from agent.toml files."""
    available = {}
    for template_dir in TEMPLATES_DIR.iterdir():
        if template_dir.is_dir() and not template_dir.name.startswith("_"):
            try:
                config = load_agent_config(template_dir)
                available[config.name] = config.description
            except AgentConfigError:
                # Skip directories without valid agent.toml
                continue
    return available


def get_agent_config(template_name: str) -> AgentConfig:
    """Load agent configuration for a template.

    Args:
        template_name: Name of template (e.g., 'claude-code')

    Returns:
        AgentConfig for the template

    Raises:
        TemplateError: If template not found or invalid
    """
    template_dir = TEMPLATES_DIR / template_name
    if not template_dir.exists():
        available = ", ".join(get_available_templates().keys())
        raise TemplateError(
            f"Unknown template: {template_name}. Available: {available}"
        )

    try:
        return load_agent_config(template_dir)
    except AgentConfigError as err:
        raise TemplateError(str(err)) from err


def render_template(
    template_name: str,
    output_dir: Path,
    project_dir: str,
    instance_name: str | None = None,
) -> list[Path]:
    """Render a template to the output directory.

    Args:
        template_name: Name of template (e.g., 'claude-code')
        output_dir: Directory to write rendered files
        project_dir: Folder to mount in agent container
        instance_name: Instance name (used as service name and hostname).
                      Defaults to template name if not provided.

    Returns:
        List of created file paths

    Raises:
        TemplateError: If template not found or rendering fails
    """
    template_dir = TEMPLATES_DIR / template_name
    agent_config = get_agent_config(template_name)

    output_dir.mkdir(parents=True, exist_ok=True)

    # Detect host config based on agent's requirements
    host_status = detect_host_config_for_agent(agent_config)

    # Instance name defaults to agent name
    effective_name = instance_name or agent_config.name

    # Template variables from agent config
    variables = {
        # Infrastructure
        "proxy_hostname": PROXY_CONTAINER_NAME,
        "network_name": get_compose_network_name(),
        "certs_volume": CA_VOLUME_NAME,
        "project_dir": project_dir,
        # Agent config (full object available)
        "agent": agent_config,
        # Convenience accessors
        "agent_name": agent_config.name,
        "instance_name": effective_name,
        "mise_package": agent_config.install.mise,
        "run_command": agent_config.run.full_command,
        "binary": agent_config.install.binary,
        "auth_env_var": agent_config.auth.env_var,
        "oauth_file": agent_config.auth.oauth_file,
        "setup_hint": agent_config.auth.setup_hint,
        # Host config detection
        "found_dirs": host_status.found_dirs,
        "found_files": host_status.found_files,
        # Docker customization
        "docker_env": agent_config.docker.env,
        # Instructions injection
        "instructions": agent_config.instructions,
        "instructions_content": agent_config.instructions.content,
        "instructions_type": agent_config.instructions.injection_type,
        "instructions_path": agent_config.instructions.path,
        "instructions_arg": agent_config.instructions.arg_name,
    }

    # Generate .env file with host UID/GID and user's folder
    user_dirname = Path(project_dir).name
    env_content = (
        f"SAFEYOLO_UID={os.getuid()}\n"
        f"SAFEYOLO_GID={os.getgid()}\n"
        f"USER_DIR={project_dir}\n"
        f"USER_DIRNAME={user_dirname}\n"
    )
    env_path = output_dir / ".env"
    env_path.write_text(env_content)

    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        keep_trailing_newline=True,
    )

    created_files = [env_path]

    for file_path in template_dir.iterdir():
        # Skip hidden files, agent.toml, and directories
        if file_path.name.startswith("_") or file_path.name.startswith("."):
            continue
        if file_path.name == "agent.toml":
            continue
        if file_path.is_dir():
            continue

        if file_path.suffix == ".j2":
            # Render Jinja2 template
            template = env.get_template(file_path.name)
            output_name = file_path.stem  # Remove .j2 suffix
            output_path = output_dir / output_name
            output_path.write_text(template.render(**variables))
        else:
            # Copy static file as-is
            output_path = output_dir / file_path.name
            output_path.write_text(file_path.read_text())

        created_files.append(output_path)

    return created_files


# Re-export for backward compatibility during refactor
__all__ = [
    "TemplateError",
    "HostConfigStatus",
    "get_available_templates",
    "get_agent_config",
    "render_template",
    "detect_host_config_for_agent",
]
