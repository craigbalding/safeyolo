"""Initialize SafeYolo configuration."""

import json
import secrets
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from ..config import (
    DEFAULT_CONFIG,
    PROJECT_DIR_NAME,
    save_config,
)
from ..docker import check_docker, write_compose_file

console = Console()

# Available API providers with their rules
API_PROVIDERS = {
    "openai": {
        "name": "OpenAI",
        "rules": [
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
        ],
    },
    "anthropic": {
        "name": "Anthropic",
        "rules": [
            {
                "name": "anthropic",
                "pattern": "sk-ant-api[a-zA-Z0-9-]{90,}",
                "allowed_hosts": ["api.anthropic.com"],
            },
        ],
    },
    "github": {
        "name": "GitHub",
        "rules": [
            {
                "name": "github",
                "pattern": "gh[ps]_[a-zA-Z0-9]{36}",
                "allowed_hosts": ["api.github.com", "github.com"],
            },
        ],
    },
    "google": {
        "name": "Google AI",
        "rules": [
            {
                "name": "google_ai",
                "pattern": "AIza[a-zA-Z0-9_-]{35}",
                "allowed_hosts": ["generativelanguage.googleapis.com"],
            },
        ],
    },
    "aws": {
        "name": "AWS",
        "rules": [
            {
                "name": "aws_access_key",
                "pattern": "AKIA[A-Z0-9]{16}",
                "allowed_hosts": ["*.amazonaws.com"],
            },
        ],
    },
}

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


def _select_providers_interactive() -> list[str]:
    """Interactively select API providers."""
    console.print("\n[bold]Select API providers to protect:[/bold]\n")

    # Show available providers
    table = Table(show_header=True, header_style="bold")
    table.add_column("#", style="dim", width=3)
    table.add_column("Provider")
    table.add_column("Protected Hosts")

    for idx, (_key, provider) in enumerate(API_PROVIDERS.items(), 1):
        hosts = ", ".join(provider["rules"][0]["allowed_hosts"])
        table.add_row(str(idx), provider["name"], hosts)

    console.print(table)
    console.print()

    # Get selection
    choices = Prompt.ask(
        "Enter numbers to enable (comma-separated, or 'all')",
        default="1,2,3"  # OpenAI, Anthropic, GitHub by default
    )

    if choices.lower() == "all":
        return list(API_PROVIDERS.keys())

    selected = []
    provider_keys = list(API_PROVIDERS.keys())
    for part in choices.split(","):
        part = part.strip()
        if part.isdigit():
            idx = int(part) - 1
            if 0 <= idx < len(provider_keys):
                selected.append(provider_keys[idx])

    return selected or ["openai", "anthropic", "github"]


def _build_rules(providers: list[str]) -> dict:
    """Build rules config from selected providers."""
    rules = []
    for provider_key in providers:
        if provider_key in API_PROVIDERS:
            rules.extend(API_PROVIDERS[provider_key]["rules"])

    return {
        "credentials": rules,
        "entropy_detection": {
            "enabled": True,
            "min_length": 20,
            "min_charset_diversity": 0.5,
            "min_shannon_entropy": 3.5,
        },
    }


def _generate_admin_token(config_dir: Path) -> str:
    """Generate and save admin API token."""
    token = secrets.token_urlsafe(32)
    data_dir = config_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    token_path = data_dir / "admin_token"
    token_path.write_text(token)
    token_path.chmod(0o600)
    return token


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
    interactive: bool = typer.Option(
        True,
        "--interactive/--no-interactive", "-i",
        help="Run interactive setup wizard",
    ),
    providers: str = typer.Option(
        None,
        "--providers", "-p",
        help="Comma-separated providers (openai,anthropic,github,google,aws)",
    ),
    try_mode: bool = typer.Option(
        False,
        "--try",
        help="Use Try Mode (bypassable) instead of Sandbox Mode",
    ),
) -> None:
    """Initialize SafeYolo configuration.

    Creates configuration files for the SafeYolo security proxy. By default,
    uses Sandbox Mode with network isolation where bypass attempts fail.

    Use --try for evaluation without network isolation (agents can bypass).

    Examples:

        safeyolo init                    # Sandbox Mode (secure default)
        safeyolo init --try              # Try Mode for evaluation
        safeyolo init --no-interactive   # Use defaults
        safeyolo init -p openai,anthropic  # Specify providers
    """
    # Sandbox is default, --try disables it
    sandbox = not try_mode

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
    docker_available = check_docker()
    if not docker_available:
        console.print(
            Panel(
                "[yellow]Docker is not available.[/yellow]\n\n"
                "SafeYolo requires Docker to run. Please install Docker:\n"
                "  macOS: https://docs.docker.com/desktop/mac/install/\n"
                "  Linux: https://docs.docker.com/engine/install/",
                title="Warning",
            )
        )
        if interactive:
            if not Confirm.ask("Continue anyway?", default=True):
                raise typer.Exit(1)

    console.print(f"\n[bold]Initializing SafeYolo in {config_dir}[/bold]")

    # Select providers
    if providers:
        selected_providers = [p.strip() for p in providers.split(",")]
    elif interactive:
        selected_providers = _select_providers_interactive()
    else:
        selected_providers = ["openai", "anthropic", "github"]

    console.print(f"\n[dim]Providers: {', '.join(selected_providers)}[/dim]\n")

    # Create directories
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "logs").mkdir(exist_ok=True)
    (config_dir / "certs").mkdir(exist_ok=True)
    (config_dir / "policies").mkdir(exist_ok=True)
    (config_dir / "data").mkdir(exist_ok=True)

    # Generate admin token
    _generate_admin_token(config_dir)
    console.print("  [green]Created[/green] admin token")

    # Write config.yaml
    config = DEFAULT_CONFIG.copy()
    config["sandbox"] = sandbox
    save_config(config)
    console.print(f"  [green]Created[/green] {config_path}")

    # Write rules.json
    rules = _build_rules(selected_providers)
    rules_path.write_text(json.dumps(rules, indent=2))
    console.print(f"  [green]Created[/green] {rules_path}")

    # Write docker-compose.yml
    compose_path = write_compose_file(sandbox=sandbox)
    console.print(f"  [green]Created[/green] {compose_path}")

    # Summary
    provider_names = [API_PROVIDERS.get(p, {}).get("name", p) for p in selected_providers]
    mode_label = "[bold green]Sandbox Mode[/bold green]" if sandbox else "Try Mode"

    if sandbox:
        next_steps = (
            "Next steps:\n"
            "  1. Run: [bold]safeyolo start[/bold]\n"
            "  2. Run: [bold]safeyolo agent add claude-code[/bold]\n"
            "  3. Run your agent from [bold]./safeyolo/agents/claude-code/[/bold]"
        )
    else:
        next_steps = (
            "Next steps:\n"
            "  1. Run: [bold]safeyolo start[/bold]\n"
            "  2. Configure your agent to use proxy at localhost:8080\n"
            "  3. Run: [bold]safeyolo watch[/bold] to handle approvals"
        )

    console.print(
        Panel(
            f"[green]SafeYolo initialized![/green]\n\n"
            f"Mode: {mode_label}\n"
            f"Protected providers: {', '.join(provider_names)}\n"
            f"Configuration: {config_dir}\n\n"
            f"{next_steps}",
            title="Success",
        )
    )
