"""Template management for agent configurations."""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from ..config import (
    CERTS_VOLUME_NAME,
    INTERNAL_NETWORK_NAME,
    SAFEYOLO_INTERNAL_IP,
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
) -> list[Path]:
    """Render a template to the output directory.

    Args:
        template_name: Name of template (e.g., 'claude-code')
        output_dir: Directory to write rendered files
        project_dir: Project directory to mount in agent container

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

    # Template variables
    variables = {
        "safeyolo_ip": SAFEYOLO_INTERNAL_IP,
        "network_name": INTERNAL_NETWORK_NAME,
        "certs_volume": CERTS_VOLUME_NAME,
        "project_dir": project_dir,
    }

    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        keep_trailing_newline=True,
    )

    created_files = []

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
