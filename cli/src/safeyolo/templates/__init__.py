"""Template management for agent configurations."""

from pathlib import Path

from .loader import AgentConfig, AgentConfigError, load_agent_config


class TemplateError(Exception):
    """Template operation failed."""
    pass


TEMPLATES_DIR = Path(__file__).parent / "agents"


def get_available_templates() -> dict[str, str]:
    """Get dict of template_name -> description from agent.toml files."""
    available = {}
    for template_dir in TEMPLATES_DIR.iterdir():
        if template_dir.is_dir() and not template_dir.name.startswith("_"):
            try:
                config = load_agent_config(template_dir)
                available[config.name] = config.description
            except AgentConfigError:
                continue
    return available


def get_agent_config(template_name: str) -> AgentConfig:
    """Load agent configuration for a template."""
    template_dir = TEMPLATES_DIR / template_name
    if not template_dir.exists():
        available = ", ".join(get_available_templates().keys())
        raise TemplateError(f"Unknown template: {template_name}. Available: {available}")

    try:
        return load_agent_config(template_dir)
    except AgentConfigError as err:
        raise TemplateError(str(err)) from err


def detect_host_config_for_agent(agent_config: AgentConfig) -> list[str]:
    """Detect which host config directories exist for this agent."""
    home = Path.home()
    found = []
    for dir_name in agent_config.host.config_dirs:
        if (home / dir_name).is_dir():
            found.append(dir_name)
    return found


__all__ = [
    "TemplateError",
    "get_available_templates",
    "get_agent_config",
    "detect_host_config_for_agent",
]
