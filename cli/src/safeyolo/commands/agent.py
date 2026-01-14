"""Agent management commands."""

import json
import logging
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..config import find_config_dir, get_agents_dir, load_config
from ..discovery import get_compose_network_name, regenerate_services
from ..docker import is_running, wait_for_healthy
from ..docker import start as docker_start
from ..templates import TemplateError, get_agent_config, get_available_templates, render_template

log = logging.getLogger("safeyolo.agent")
console = Console()

# Subprocess timeout (seconds)
DOCKER_COMPOSE_TIMEOUT_SECONDS = 30


def _ensure_host_config(template_name: str, ephemeral: bool) -> None:
    """Ensure host config directories exist for the agent.

    Creates directories from agent.toml [host] config if they don't exist.
    """
    try:
        agent_config = get_agent_config(template_name)
    except TemplateError:
        return  # Will fail later in render_template

    home = Path.home()
    console.print("\n[bold]Host config:[/bold]")

    has_any = False

    # Check/create directories
    for dir_name in agent_config.host.config_dirs:
        dir_path = home / dir_name
        if dir_path.exists():
            console.print(f"  [green]Found[/green] {dir_path} (will mount)")
            has_any = True
        elif ephemeral:
            console.print("  [yellow]Ephemeral mode[/yellow] - settings lost on container exit")
        else:
            dir_path.mkdir(mode=0o700, exist_ok=True)
            console.print(f"  [green]Created[/green] {dir_path}")
            has_any = True

    # Check files (don't create, just report)
    for file_name in agent_config.host.config_files:
        file_path = home / file_name
        if file_path.exists():
            console.print(f"  [green]Found[/green] {file_path} (will mount)")
            has_any = True

    if not has_any and not ephemeral:
        console.print("  [dim]No host config found[/dim]")

    console.print()


agent_app = typer.Typer(
    name="agent",
    help="Manage AI agent containers for Sandbox Mode.",
    no_args_is_help=True,
)


def _check_project_ownership(project_path: Path, allow_unowned: bool) -> None:
    """Check that user owns the project directory."""
    import os
    try:
        stat_info = project_path.stat()
        if stat_info.st_uid != os.getuid():
            if allow_unowned:
                console.print(
                    f"[yellow]Warning: You don't own {project_path}[/yellow]"
                )
            else:
                console.print(
                    f"[red]You don't own {project_path}[/red]\n"
                    "Use --dangerously-allow-unowned to override."
                )
                raise typer.Exit(1)
    except OSError as err:
        console.print(f"[red]Cannot access {project_path}:[/red] {err}")
        raise typer.Exit(1)


def _get_service_name(instance_name: str) -> str:
    """Get service name for an instance.

    Service name equals instance name (used in docker-compose).
    """
    return instance_name


# RFC 1123 hostname: lowercase alphanumeric, hyphens allowed (not at start/end), max 63 chars
HOSTNAME_PATTERN = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')


def _validate_instance_name(name: str) -> None:
    """Validate instance name follows hostname conventions."""
    if not name:
        console.print("[red]Instance name cannot be empty[/red]")
        raise typer.Exit(1)
    if len(name) > 63:
        console.print(f"[red]Instance name too long ({len(name)} chars, max 63)[/red]")
        raise typer.Exit(1)
    if not HOSTNAME_PATTERN.match(name):
        console.print(
            f"[red]Invalid instance name: {name}[/red]\n"
            "Must be lowercase alphanumeric with hyphens (not at start/end)."
        )
        raise typer.Exit(1)


def _load_agent_metadata(name: str) -> dict:
    """Load agent metadata from .safeyolo.json."""
    metadata_file = get_agents_dir() / name / ".safeyolo.json"
    if metadata_file.exists():
        try:
            return json.loads(metadata_file.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _get_agent_binary(metadata: dict) -> str | None:
    """Get the agent binary name from template config."""
    template_name = metadata.get("template")
    if not template_name:
        return None
    try:
        agent_config = get_agent_config(template_name)
        return agent_config.install.binary
    except TemplateError:
        return None


def _run_agent(
    name: str,
    folder_override: str | None = None,
    yolo: bool = False,
    dangerously_allow_unowned: bool = False,
    agent_args: list[str] | None = None,
    skip_default_args: bool = False,
) -> int:
    """Run an agent container. Returns exit code.

    Shared logic used by both `add` (auto-run) and `run` commands.

    Args:
        agent_args: Extra arguments to pass to the agent CLI (after --)
        skip_default_args: If True, ignore user_default_args even if no agent_args
    """
    agent_dir = get_agents_dir() / name
    compose_file = agent_dir / "docker-compose.yml"

    if not compose_file.exists():
        console.print(f"[red]Agent not found: {name}[/red]")
        console.print("Run [bold]safeyolo agent add <name> <template> <folder>[/bold] first.")
        raise typer.Exit(1)

    # Load metadata for user_default_args and binary name
    metadata = _load_agent_metadata(name)
    binary = _get_agent_binary(metadata)

    # Check SafeYolo is running
    if not is_running():
        console.print("[yellow]SafeYolo is not running. Starting...[/yellow]")
        try:
            docker_start()
            if not wait_for_healthy(timeout=30):
                console.print("[red]SafeYolo failed to start.[/red]")
                raise typer.Exit(1)
            console.print("[green]SafeYolo started.[/green]\n")

            try:
                regenerate_services()
            except Exception as err:
                log.debug(f"Service regeneration skipped: {type(err).__name__}: {err}")

        except Exception as err:
            console.print(f"[red]Failed to start SafeYolo:[/red] {type(err).__name__}: {err}")
            raise typer.Exit(1)

    # Run the agent container
    console.print(f"Starting {name}...\n")

    # Build image quietly (only shows output on actual build, not cache hits)
    build_result = subprocess.run(
        ["docker", "compose", "--progress=quiet", "-f", str(compose_file), "build"],
        cwd=agent_dir,
    )
    if build_result.returncode != 0:
        console.print("[red]Failed to build agent image.[/red]")
        raise typer.Exit(build_result.returncode)

    # Get service name from instance name
    service_name = _get_service_name(name)

    # Run with inherited stdin/stdout for interactive use
    cmd = ["docker", "compose", "-f", str(compose_file), "run", "--rm"]
    if folder_override:
        folder_path = Path(folder_override).expanduser().resolve()
        if not folder_path.is_dir():
            console.print(f"[red]Folder not found: {folder_path}[/red]")
            raise typer.Exit(1)
        _check_project_ownership(folder_path, dangerously_allow_unowned)
        cmd.extend(["-e", f"USER_DIR={folder_path}"])
        cmd.extend(["-e", f"USER_DIRNAME={folder_path.name}"])
    if yolo:
        cmd.extend(["-e", "SAFEYOLO_YOLO_MODE=1"])
    cmd.append(service_name)

    # Add agent-specific args (passthrough or defaults)
    # Must prepend binary name since docker replaces CMD with these args
    if agent_args:
        if binary:
            cmd.append(binary)
        cmd.extend(agent_args)
    elif not skip_default_args and metadata.get("user_default_args"):
        if binary:
            cmd.append(binary)
        cmd.extend(metadata["user_default_args"])

    result = subprocess.run(cmd, cwd=agent_dir)
    return result.returncode


def _parse_user_default_args(value: str | None) -> list[str] | None:
    """Parse user_default_args string into list."""
    if not value:
        return None
    try:
        return shlex.split(value)
    except ValueError:
        # If shlex fails, fall back to simple split
        return value.split()


@agent_app.command()
def add(
    name: str = typer.Argument(
        ...,
        help="Instance name (used for run/shell/remove commands)",
    ),
    template: str = typer.Argument(
        ...,
        help="Agent template (e.g., claude-code, openai-codex)",
    ),
    folder: str = typer.Argument(
        ...,
        help="Folder to mount in agent container",
    ),
    force: bool = typer.Option(
        False,
        "--force", "-f",
        help="Overwrite existing agent configuration",
    ),
    no_run: bool = typer.Option(
        False,
        "--no-run",
        help="Don't run the agent after adding (just create config)",
    ),
    ephemeral: bool = typer.Option(
        False,
        "--ephemeral",
        help="Don't persist config (credentials lost on container exit)",
    ),
    user_default_args: str = typer.Option(
        None,
        "--user-default-args",
        help="Default args to pass to agent CLI (e.g., '--continue')",
    ),
    dangerously_allow_unowned: bool = typer.Option(
        False,
        "--dangerously-allow-unowned",
        help="Allow mounting directories you don't own",
    ),
) -> None:
    """Add an AI agent and run it.

    Creates config for the specified agent template, then runs it.
    If agent already exists with same config, just runs it (idempotent).

    Examples:

        safeyolo agent add myproject claude-code .
        safeyolo agent add work claude-code ~/projects/myapp
        safeyolo agent add assistant openai-codex ~/code --no-run
        safeyolo agent add boris claude-code . --user-default-args="--continue"
    """
    # Validate instance name (hostname rules)
    _validate_instance_name(name)

    config_dir = find_config_dir()
    if not config_dir:
        console.print(
            "[red]No SafeYolo configuration found.[/red]\n"
            "Run [bold]safeyolo init --sandbox[/bold] first."
        )
        raise typer.Exit(1)

    config = load_config()
    if not config.get("sandbox"):
        console.print(
            "[yellow]Warning: SafeYolo is not in Sandbox Mode.[/yellow]\n"
            "Agent containers may be able to bypass the proxy.\n"
            "Run [bold]safeyolo init --sandbox[/bold] to enable network isolation.\n"
        )

    # Validate folder early
    folder_path = Path(folder).expanduser().resolve()
    if not folder_path.is_dir():
        console.print(f"[red]Folder not found: {folder_path}[/red]")
        raise typer.Exit(1)
    _check_project_ownership(folder_path, dangerously_allow_unowned)
    folder_str = str(folder_path)

    # Validate template exists
    try:
        get_agent_config(template)
    except TemplateError as err:
        console.print(f"[red]Template error:[/red] {err}")
        raise typer.Exit(1)

    # Instance directory = instance name
    agent_dir = get_agents_dir() / name
    metadata_file = agent_dir / ".safeyolo.json"

    # Check if agent already exists
    if agent_dir.exists():
        # Load existing metadata to check if config matches
        if metadata_file.exists():
            try:
                existing = json.loads(metadata_file.read_text())
                existing_template = existing.get("template")
                existing_folder = existing.get("folder")

                if existing_template == template and existing_folder == folder_str:
                    # Same config - idempotent, just run
                    console.print(f"Agent '{name}' already configured.")
                    if not no_run:
                        exit_code = _run_agent(name, dangerously_allow_unowned=dangerously_allow_unowned)
                        raise typer.Exit(exit_code)
                    return
                else:
                    # Different config
                    if not force:
                        console.print(
                            f"[yellow]Agent '{name}' exists with different config:[/yellow]\n"
                            f"  Current:  {existing_template} → {existing_folder}\n"
                            f"  Requested: {template} → {folder_str}\n"
                            "Use --force to overwrite, or 'safeyolo agent run' to run existing."
                        )
                        raise typer.Exit(1)
                    # With --force, continue to overwrite below
            except (json.JSONDecodeError, OSError):
                # Corrupted metadata, treat as needing --force
                if not force:
                    console.print(f"[yellow]Agent '{name}' exists but metadata is corrupted.[/yellow]")
                    console.print("Use --force to overwrite")
                    raise typer.Exit(1)
        else:
            # No metadata file, treat as needing --force
            if not force:
                console.print(f"[yellow]Agent '{name}' already exists[/yellow]")
                console.print("Use --force to overwrite")
                raise typer.Exit(1)

    # Ensure host config directories exist
    _ensure_host_config(template, ephemeral)

    # Render template
    try:
        files = render_template(
            template_name=template,
            output_dir=agent_dir,
            project_dir=folder_str,
            instance_name=name,
        )
    except TemplateError as err:
        console.print(f"[red]Template error:[/red] {err}")
        raise typer.Exit(1)

    # Write metadata file
    metadata = {"template": template, "folder": folder_str}
    parsed_args = _parse_user_default_args(user_default_args)
    if parsed_args:
        metadata["user_default_args"] = parsed_args
    metadata_file.write_text(json.dumps(metadata, indent=2) + "\n")

    # Show created files
    for filepath in files:
        console.print(f"  [green]Created[/green] {filepath}")

    panel_lines = [
        f"[green]Agent '{name}' added![/green]\n",
        f"Template: {template}",
        f"Folder: {folder_str}",
    ]
    if parsed_args:
        panel_lines.append(f"Default args: {' '.join(parsed_args)}")
    panel_lines.extend([
        f"Network: {get_compose_network_name()}",
        "Proxy: http://safeyolo:8080 (Docker DNS)",
    ])
    console.print(Panel("\n".join(panel_lines), title="Success"))

    # Auto-run unless --no-run
    if not no_run:
        console.print()
        exit_code = _run_agent(name, dangerously_allow_unowned=dangerously_allow_unowned)
        raise typer.Exit(exit_code)


@agent_app.command(name="list")
def list_agents() -> None:
    """List available agent templates and instances."""
    # Show templates
    templates = get_available_templates()
    if templates:
        table = Table(title="Available Templates")
        table.add_column("Template", style="bold")
        table.add_column("Description")
        for tpl_name, description in templates.items():
            table.add_row(tpl_name, description)
        console.print(table)
        console.print()

    # Show instances
    agents_dir = get_agents_dir()
    if agents_dir.exists():
        instances = [
            d for d in agents_dir.iterdir()
            if d.is_dir() and (d / "docker-compose.yml").exists()
        ]
        if instances:
            table = Table(title="Configured Agents")
            table.add_column("Name", style="bold")
            table.add_column("Template")
            table.add_column("Folder")
            for inst_dir in sorted(instances, key=lambda d: d.name):
                # Read metadata
                metadata_file = inst_dir / ".safeyolo.json"
                if metadata_file.exists():
                    try:
                        metadata = json.loads(metadata_file.read_text())
                        template = metadata.get("template", "?")
                        folder = metadata.get("folder", "?")
                    except (json.JSONDecodeError, OSError):
                        template, folder = "?", "?"
                else:
                    template, folder = "?", "?"
                table.add_row(inst_dir.name, template, folder)
            console.print(table)
        else:
            console.print("[dim]No agents configured.[/dim]")
    else:
        console.print("[dim]No agents configured.[/dim]")


@agent_app.command()
def remove(
    name: str = typer.Argument(..., help="Agent instance name to remove"),
    clean: bool = typer.Option(
        False, "--clean", help="Also stop containers and remove images/volumes"
    ),
) -> None:
    """Remove an agent configuration.

    Deletes the agent's compose file and configuration directory.

    Examples:

        safeyolo agent remove claude-code
        safeyolo agent remove claude-code --clean  # Also remove containers/images
    """
    config_dir = find_config_dir()
    if not config_dir:
        console.print("[red]No SafeYolo configuration found.[/red]")
        raise typer.Exit(1)

    agent_dir = get_agents_dir() / name
    if not agent_dir.exists():
        console.print(f"[yellow]Agent not found: {name}[/yellow]")
        raise typer.Exit(1)

    if clean:
        console.print(f"[dim]Stopping containers and removing images for {name}...[/dim]")
        subprocess.run(
            ["docker", "compose", "down", "--rmi", "local", "-v", "--remove-orphans"],
            cwd=agent_dir,
            capture_output=True,
            timeout=DOCKER_COMPOSE_TIMEOUT_SECONDS,
        )

    shutil.rmtree(agent_dir)
    console.print(f"[green]Removed agent: {name}[/green]")

    # Update service mappings if safeyolo is running
    if is_running():
        try:
            regenerate_services()
        except Exception as err:
            log.debug(f"Service regeneration skipped: {type(err).__name__}: {err}")


@agent_app.command(
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True}
)
def run(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Agent instance name to run"),
    folder: str = typer.Option(
        None, "--folder", "-f", help="Override folder to mount (default: from agent add)"
    ),
    yolo: bool = typer.Option(
        False, "--yolo", help="Enable auto-accept mode (skips permission prompts)"
    ),
    fresh: bool = typer.Option(
        False, "--fresh", help="Ignore user_default_args, start fresh session"
    ),
    dangerously_allow_unowned: bool = typer.Option(
        False,
        "--dangerously-allow-unowned",
        help="Allow mounting directories you don't own",
    ),
) -> None:
    """Run an existing agent container.

    Starts SafeYolo if not running, then launches the agent container.
    Use this as shorthand after initial 'agent add'.

    Pass agent-specific flags after '--':

        safeyolo agent run boris -- --continue
        safeyolo agent run boris -- --resume my-session

    If user_default_args is configured (via 'agent config'), those args
    are used by default. Use --fresh to ignore them.

    Examples:

        safeyolo agent run myproject
        safeyolo agent run myproject -f ~/other/folder
        safeyolo agent run myproject --yolo
        safeyolo agent run myproject -- --continue
        safeyolo agent run myproject --fresh
    """
    # ctx.args contains everything after '--'
    agent_args = ctx.args if ctx.args else None

    exit_code = _run_agent(
        name,
        folder_override=folder,
        yolo=yolo,
        dangerously_allow_unowned=dangerously_allow_unowned,
        agent_args=agent_args,
        skip_default_args=fresh,
    )
    raise typer.Exit(exit_code)


@agent_app.command()
def shell(
    name: str = typer.Argument(..., help="Agent instance name"),
    root: bool = typer.Option(
        False,
        "--root",
        help="Open shell as root (default: non-root agent user)",
    ),
) -> None:
    """Open a shell in a running agent container.

    By default, opens as the non-root agent user. Use --root for root access.

    Examples:

        safeyolo agent shell myproject
        safeyolo agent shell myproject --root
    """
    config_dir = find_config_dir()
    if not config_dir:
        console.print("[red]No SafeYolo configuration found.[/red]")
        raise typer.Exit(1)

    agent_dir = get_agents_dir() / name
    compose_file = agent_dir / "docker-compose.yml"

    if not compose_file.exists():
        console.print(f"[red]Agent not found: {name}[/red]")
        raise typer.Exit(1)

    # Get service name from instance name
    service_name = _get_service_name(name)

    # Build exec command - default to non-root agent user
    cmd = ["docker", "compose", "-f", str(compose_file), "exec"]
    if not root:
        cmd.extend(["--user", "agent"])
    cmd.extend([service_name, "bash"])

    result = subprocess.run(cmd, cwd=agent_dir)

    raise typer.Exit(result.returncode)


@agent_app.command()
def config(
    name: str = typer.Argument(..., help="Agent instance name"),
    user_default_args: str = typer.Option(
        None,
        "--user-default-args",
        help="Set default args for agent CLI (use '' to clear)",
    ),
    show: bool = typer.Option(
        False,
        "--show",
        help="Show current configuration",
    ),
) -> None:
    """View or update agent configuration.

    Examples:

        safeyolo agent config boris --show
        safeyolo agent config boris --user-default-args="--continue"
        safeyolo agent config boris --user-default-args=""
    """
    agent_dir = get_agents_dir() / name
    metadata_file = agent_dir / ".safeyolo.json"

    if not metadata_file.exists():
        console.print(f"[red]Agent not found: {name}[/red]")
        raise typer.Exit(1)

    try:
        metadata = json.loads(metadata_file.read_text())
    except (json.JSONDecodeError, OSError) as err:
        console.print(f"[red]Failed to read agent config:[/red] {type(err).__name__}: {err}")
        raise typer.Exit(1)

    if show or user_default_args is None:
        # Show current config
        table = Table(title=f"Agent: {name}")
        table.add_column("Setting", style="bold")
        table.add_column("Value")
        table.add_row("Template", metadata.get("template", "?"))
        table.add_row("Folder", metadata.get("folder", "?"))
        current_args = metadata.get("user_default_args")
        if current_args:
            table.add_row("Default args", " ".join(current_args))
        else:
            table.add_row("Default args", "[dim]not set[/dim]")
        console.print(table)
        return

    # Update user_default_args
    if user_default_args == "":
        # Clear the setting
        if "user_default_args" in metadata:
            del metadata["user_default_args"]
        console.print(f"[green]Cleared user_default_args for {name}[/green]")
    else:
        parsed_args = _parse_user_default_args(user_default_args)
        if parsed_args:
            metadata["user_default_args"] = parsed_args
            console.print(f"[green]Set user_default_args for {name}:[/green] {' '.join(parsed_args)}")
        else:
            console.print("[yellow]No args provided[/yellow]")
            return

    metadata_file.write_text(json.dumps(metadata, indent=2) + "\n")


@agent_app.command(name="help")
def agent_help(
    name: str = typer.Argument(..., help="Agent instance name"),
) -> None:
    """Show agent CLI help.

    Runs the agent's --help command inside the container to show available flags.
    Use 'safeyolo agent shell <name>' to experiment with other flags interactively.

    Examples:

        safeyolo agent help boris
    """
    # Use passthrough with --help (or configured help_arg)
    metadata = _load_agent_metadata(name)
    template_name = metadata.get("template")

    help_arg = "--help"
    if template_name:
        try:
            agent_config = get_agent_config(template_name)
            help_arg = agent_config.run.help_arg
        except TemplateError:
            pass  # Optional - continue with default --help if template lookup fails

    # Parse help_arg in case it has multiple parts
    help_args = help_arg.split()

    exit_code = _run_agent(name, agent_args=help_args, skip_default_args=True)

    # Suggest shell for experimentation
    console.print(f"\n[dim]To experiment with flags: safeyolo agent shell {name}[/dim]")

    raise typer.Exit(exit_code)
