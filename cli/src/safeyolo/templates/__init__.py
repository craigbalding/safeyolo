"""Template management for agent configurations."""

import os
from dataclasses import dataclass
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from ..config import (
    CERTS_VOLUME_NAME,
    INTERNAL_NETWORK_NAME,
    SAFEYOLO_INTERNAL_IP,
    get_agent_ip,
)


@dataclass
class HostConfigStatus:
    """Status of host config file/directory detection."""
    claude_dir: bool = False      # ~/.claude exists
    claude_json: bool = False     # ~/.claude.json exists
    codex_dir: bool = False       # ~/.codex exists


def detect_host_config() -> HostConfigStatus:
    """Detect which agent config files exist on the host."""
    home = Path.home()
    return HostConfigStatus(
        claude_dir=(home / ".claude").is_dir(),
        claude_json=(home / ".claude.json").is_file(),
        codex_dir=(home / ".codex").is_dir(),
    )


class TemplateError(Exception):
    """Template operation failed."""
    pass


TEMPLATES_DIR = Path(__file__).parent / "agents"

# Template metadata: name -> description
TEMPLATE_INFO = {
    "claude-code": "Claude Code (Anthropic) - Node.js based AI coding assistant",
    "openai-codex": "OpenAI Codex CLI - Terminal-based coding agent",
}


def get_available_templates() -> dict[str, str]:
    """Get dict of template_name -> description."""
    available = {}
    for template_dir in TEMPLATES_DIR.iterdir():
        if template_dir.is_dir() and not template_dir.name.startswith("_"):
            name = template_dir.name
            available[name] = TEMPLATE_INFO.get(name, "No description")
    return available


def render_template(
    template_name: str,
    output_dir: Path,
    project_dir: str,
    host_config: HostConfigStatus | None = None,
) -> list[Path]:
    """Render a template to the output directory.

    Args:
        template_name: Name of template (e.g., 'claude-code')
        output_dir: Directory to write rendered files
        project_dir: Project directory to mount in agent container
        host_config: Detected host config status (auto-detected if None)

    Returns:
        List of created file paths

    Raises:
        TemplateError: If template not found or rendering fails
    """
    template_dir = TEMPLATES_DIR / template_name
    if not template_dir.exists():
        available = ", ".join(get_available_templates().keys())
        raise TemplateError(
            f"Unknown template: {template_name}. Available: {available}"
        )

    output_dir.mkdir(parents=True, exist_ok=True)

    # Detect host config if not provided
    if host_config is None:
        host_config = detect_host_config()

    # Template variables
    agent_ip = get_agent_ip(template_name)
    variables = {
        "safeyolo_ip": SAFEYOLO_INTERNAL_IP,
        "network_name": INTERNAL_NETWORK_NAME,
        "certs_volume": CERTS_VOLUME_NAME,
        "project_dir": project_dir,
        "agent_ip": agent_ip,
        # Host config detection results
        "has_claude_dir": host_config.claude_dir,
        "has_claude_json": host_config.claude_json,
        "has_codex_dir": host_config.codex_dir,
    }

    # Generate .env file with host UID/GID for non-root execution
    env_content = f"SAFEYOLO_UID={os.getuid()}\nSAFEYOLO_GID={os.getgid()}\n"
    env_path = output_dir / ".env"
    env_path.write_text(env_content)

    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        keep_trailing_newline=True,
    )

    created_files = [env_path]

    for file_path in template_dir.iterdir():
        if file_path.name.startswith("_"):
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
