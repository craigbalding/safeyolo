"""Initialize SafeYolo configuration."""

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from ..config import (
    DEFAULT_CONFIG,
    PROJECT_DIR_NAME,
    ensure_directories,
    get_config_dir,
    get_config_path,
    get_rules_path,
    save_config,
)
from ..docker import check_docker, write_compose_file

console = Console()

# Default credential rules for common providers
DEFAULT_RULES = {
    "credentials": [
        {
            "name": "openai",
            "pattern": "sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}",
            "allowed_hosts": ["api.openai.com"],
        },
        {
            "name": "openai_project",
            "pattern": "sk-proj-[a-zA-Z0-9_-]{80,}",
            "allowed_hosts": ["api.openai.com"],
        },
        {
            "name": "anthropic",
            "pattern": "sk-ant-api[a-zA-Z0-9-]{90,}",
            "allowed_hosts": ["api.anthropic.com"],
        },
        {
            "name": "github",
            "pattern": "gh[ps]_[a-zA-Z0-9]{36}",
            "allowed_hosts": ["api.github.com", "github.com"],
        },
    ],
    "entropy_detection": {
        "enabled": True,
        "min_length": 20,
        "min_charset_diversity": 0.5,
        "min_shannon_entropy": 3.5,
    },
}


def init(
    directory: Path = typer.Option(
        None,
        "--dir", "-d",
        help="Directory to initialize (default: ./safeyolo)",
    ),
    force: bool = typer.Option(
        False,
        "--force", "-f",
        help="Overwrite existing configuration",
    ),
) -> None:
    """Initialize SafeYolo configuration in current directory."""

    # Determine target directory
    if directory:
        config_dir = directory
    else:
        config_dir = Path.cwd() / PROJECT_DIR_NAME

    config_path = config_dir / "config.yaml"
    rules_path = config_dir / "rules.json"

    # Check for existing config
    if config_path.exists() and not force:
        console.print(
            f"[yellow]Configuration already exists at {config_dir}[/yellow]"
        )
        console.print("Use --force to overwrite")
        raise typer.Exit(1)

    # Check Docker availability
    if not check_docker():
        console.print(
            Panel(
                "[yellow]Docker is not available.[/yellow]\n\n"
                "SafeYolo requires Docker to run. Please install Docker:\n"
                "  macOS: https://docs.docker.com/desktop/mac/install/\n"
                "  Linux: https://docs.docker.com/engine/install/",
                title="Warning",
            )
        )
        # Continue anyway - user might install Docker later

    console.print(f"\n[bold]Initializing SafeYolo in {config_dir}[/bold]\n")

    # Create directories
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "logs").mkdir(exist_ok=True)
    (config_dir / "certs").mkdir(exist_ok=True)
    (config_dir / "policies").mkdir(exist_ok=True)
    (config_dir / "data").mkdir(exist_ok=True)

    # Write config.yaml
    config = DEFAULT_CONFIG.copy()
    save_config(config)
    console.print(f"  [green]Created[/green] {config_path}")

    # Write rules.json
    rules_path.write_text(json.dumps(DEFAULT_RULES, indent=2))
    console.print(f"  [green]Created[/green] {rules_path}")

    # Write docker-compose.yml
    compose_path = write_compose_file()
    console.print(f"  [green]Created[/green] {compose_path}")

    # Summary
    console.print(
        Panel(
            f"[green]SafeYolo initialized successfully![/green]\n\n"
            f"Configuration: {config_dir}\n\n"
            f"Next steps:\n"
            f"  1. Review and customize config.yaml\n"
            f"  2. Add your API providers to rules.json\n"
            f"  3. Run: [bold]safeyolo start[/bold]\n"
            f"  4. Configure your agent to use proxy at localhost:8080",
            title="Success",
        )
    )
