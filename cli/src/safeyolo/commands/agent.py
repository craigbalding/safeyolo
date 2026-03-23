"""Agent management commands."""

import getpass
import logging
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from ..agents_store import load_agent as _store_load_agent
from ..agents_store import load_all_agents, migrate_from_json, save_agent
from ..agents_store import remove_agent as _store_remove_agent
from ..config import COMPOSE_NETWORK_NAME, find_config_dir, get_agents_dir, load_config
from ..docker import is_running, wait_for_healthy
from ..docker import start as docker_start
from ..events import EventKind, Severity, write_event
from ..templates import TemplateError, get_agent_config, get_available_templates, render_template
from ._service_discovery import find_service
from .mount import is_path_protected

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
                console.print(f"[yellow]Warning: You don't own {project_path}[/yellow]")
            else:
                console.print(f"[red]You don't own {project_path}[/red]\nUse --dangerously-allow-unowned to override.")
                raise typer.Exit(1)
    except OSError as err:
        console.print(f"[red]Cannot access {escape(str(project_path))}:[/red] {escape(str(err))}")
        raise typer.Exit(1)


def _get_service_name(instance_name: str) -> str:
    """Get service name for an instance.

    Service name equals instance name (used in docker-compose).
    """
    return instance_name


# RFC 1123 hostname: lowercase alphanumeric, hyphens allowed (not at start/end), max 63 chars
HOSTNAME_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


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
            f"[red]Invalid instance name: {escape(name)}[/red]\n"
            "Must be lowercase alphanumeric with hyphens (not at start/end)."
        )
        raise typer.Exit(1)


def _load_agent_metadata(name: str) -> dict:
    """Load agent metadata from agents.yaml, migrating from .safeyolo.json if needed."""
    metadata = _store_load_agent(name)
    if metadata:
        return metadata
    # Fallback: migrate legacy .safeyolo.json
    json_file = get_agents_dir() / name / ".safeyolo.json"
    if json_file.exists():
        return migrate_from_json(name)
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
    extra_mounts: list[str] | None = None,
    extra_ports: list[str] | None = None,
) -> int:
    """Run an agent container. Returns exit code.

    Shared logic used by both `add` (auto-run) and `run` commands.

    Args:
        agent_args: Extra arguments to pass to the agent CLI (after --)
        skip_default_args: If True, ignore user_default_args even if no agent_args
        extra_mounts: Transient mount specs (/local/path:/container/path[:ro]) for this run only
        extra_ports: Transient port specs (127.0.0.1:host:container) for this run only
    """
    _validate_instance_name(name)

    agent_dir = get_agents_dir() / name
    compose_file = agent_dir / "docker-compose.yml"

    if not compose_file.exists():
        console.print(f"[red]Agent not found: {escape(name)}[/red]")
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

        except Exception as err:
            console.print(f"[red]Failed to start SafeYolo:[/red] {escape(str(err))}")
            raise typer.Exit(1)

    # Run the agent container
    console.print(f"Starting {name}...\n")

    # Build compose env: override USER_DIR/USER_DIRNAME for volume interpolation
    compose_env = os.environ.copy()
    if folder_override:
        folder_path = Path(folder_override).expanduser().resolve()
        if not folder_path.is_dir():
            console.print(f"[red]Folder not found: {folder_path}[/red]")
            raise typer.Exit(1)
        _check_project_ownership(folder_path, dangerously_allow_unowned)
        compose_env["USER_DIR"] = str(folder_path)
        compose_env["USER_DIRNAME"] = folder_path.name

    # Build image quietly (only shows output on actual build, not cache hits)
    build_result = subprocess.run(
        ["docker", "compose", "--progress=quiet", "-f", str(compose_file), "build"],
        cwd=agent_dir,
        env=compose_env,
    )
    if build_result.returncode != 0:
        console.print("[red]Failed to build agent image.[/red]")
        raise typer.Exit(build_result.returncode)

    # Get service name from instance name
    service_name = _get_service_name(name)

    # Check if a container with this name is already running
    check_running = subprocess.run(
        ["docker", "ps", "-q", "-f", f"name=^/{name}$"],
        capture_output=True,
        text=True,
    )
    if check_running.stdout.strip():
        console.print(f"[red]Agent '{name}' is already running.[/red]")
        console.print(
            f"To open a shell in it:  [bold]safeyolo agent shell {name}[/bold]\n"
            f"To stop it first:       [bold]safeyolo agent stop {name}[/bold]\n"
            f"To run another agent:   [bold]safeyolo agent add <new-name> <template> <folder>[/bold]"
        )
        raise typer.Exit(1)

    # Clean up stale container from unclean shutdown (no-op if absent)
    subprocess.run(
        ["docker", "rm", name],
        capture_output=True,
    )

    # Run with inherited stdin/stdout for interactive use
    cmd = ["docker", "compose", "-f", str(compose_file), "run", "--rm", "--name", name]
    if yolo:
        cmd.extend(["-e", "SAFEYOLO_YOLO_MODE=1"])

    # Combine persistent mounts (from metadata) with transient mounts (from --mount)
    all_mounts = list(metadata.get("mounts", []))
    if extra_mounts:
        all_mounts.extend(extra_mounts)
    for mount in all_mounts:
        cmd.extend(["-v", mount])

    # Combine persistent ports (from metadata) with transient ports (from --port)
    all_ports = list(metadata.get("ports", []))
    if extra_ports:
        all_ports.extend(extra_ports)
    for port in all_ports:
        cmd.extend(["-p", port])

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

    write_event("agent.started", kind=EventKind.AGENT, severity=Severity.LOW, summary=f"Agent {name} started", agent=name)
    result = subprocess.run(cmd, cwd=agent_dir, env=compose_env)
    write_event("agent.stopped", kind=EventKind.AGENT, severity=Severity.LOW, summary=f"Agent {name} stopped (exit {result.returncode})", agent=name, details={"exit_code": result.returncode})
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


def _parse_mount(mount_spec: str) -> str:
    """Validate and normalize a mount spec (/local/path:/container/path[:ro]).

    Returns normalized string with resolved host path.

    Raises:
        typer.Exit: If mount spec is invalid or host path doesn't exist.
    """
    parts = mount_spec.split(":")
    if len(parts) < 2 or len(parts) > 3:
        console.print(
            f"[red]Invalid mount format:[/red] {escape(mount_spec)}\nExpected: /host/path:/container/path[:ro]"
        )
        raise typer.Exit(1)

    host_path = Path(parts[0]).expanduser().resolve()
    container_path = parts[1]

    if not container_path.startswith("/"):
        console.print(f"[red]Container path must be absolute:[/red] {escape(container_path)}")
        raise typer.Exit(1)

    if not host_path.exists():
        console.print(f"[red]Host path not found:[/red] {host_path}")
        raise typer.Exit(1)

    is_ro = len(parts) == 3 and parts[2] == "ro"

    if len(parts) == 3 and not is_ro:
        console.print(f"[red]Invalid mount option:[/red] {escape(parts[2])} (only 'ro' supported)")
        raise typer.Exit(1)

    # Enforce protected paths
    protected_by = is_path_protected(str(host_path))
    if protected_by and not is_ro:
        console.print(
            f"[red]Refused:[/red] {host_path} is under protected path {protected_by}\n"
            f"Protected paths must be mounted read-only.\n"
            f"Use: {host_path}:{container_path}:ro"
        )
        raise typer.Exit(1)

    if is_ro:
        return f"{host_path}:{container_path}:ro"

    return f"{host_path}:{container_path}"


_RESERVED_PORTS = {8080, 9090}


def _parse_port(port_spec: str) -> str:
    """Validate and normalize a port spec (host:container or bind:host:container).

    Always normalizes to 127.0.0.1:host:container.

    Raises:
        typer.Exit: If port spec is invalid.
    """
    parts = port_spec.split(":")
    if len(parts) == 2:
        bind_addr = "127.0.0.1"
        host_port_str, container_port_str = parts
    elif len(parts) == 3:
        bind_addr, host_port_str, container_port_str = parts
    else:
        console.print(
            f"[red]Invalid port format:[/red] {escape(port_spec)}\n"
            "Expected: host_port:container_port or 127.0.0.1:host_port:container_port"
        )
        raise typer.Exit(1)

    if bind_addr != "127.0.0.1":
        console.print(
            f"[red]Only localhost bind address allowed:[/red] {escape(bind_addr)}\n"
            "Use 127.0.0.1:host_port:container_port (or omit bind address)"
        )
        raise typer.Exit(1)

    for label, val in [("host", host_port_str), ("container", container_port_str)]:
        try:
            port_int = int(val)
        except ValueError:
            console.print(f"[red]Invalid {label} port (not an integer):[/red] {escape(val)}")
            raise typer.Exit(1)
        if port_int < 1 or port_int > 65535:
            console.print(f"[red]Invalid {label} port (must be 1-65535):[/red] {escape(val)}")
            raise typer.Exit(1)

    container_port = int(container_port_str)
    if container_port in _RESERVED_PORTS:
        console.print(f"[red]Container port {container_port} is reserved[/red] (used by SafeYolo proxy/admin)")
        raise typer.Exit(1)

    return f"127.0.0.1:{host_port_str}:{container_port_str}"


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
        "--force",
        "-f",
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
    mount: list[str] = typer.Option(
        [],
        "--mount",
        "-m",
        help="Extra folder to mount (/local/path:/container/path[:ro], repeatable)",
    ),
    port: list[str] = typer.Option(
        [],
        "--port",
        help="Expose container port to host (host_port:container_port, repeatable)",
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
        safeyolo agent add boris claude-code . --mount ~/data:/data --mount ~/refs:/refs:ro
    """
    # Validate instance name (hostname rules)
    _validate_instance_name(name)

    config_dir = find_config_dir()
    if not config_dir:
        console.print("[red]No SafeYolo configuration found.[/red]\nRun [bold]safeyolo init[/bold] first.")
        raise typer.Exit(1)

    config = load_config()
    if not config.get("sandbox"):
        console.print(
            "[yellow]Warning: SafeYolo is not in Sandbox Mode.[/yellow]\n"
            "Agent containers may be able to bypass the proxy.\n"
            "Run [bold]safeyolo init[/bold] to enable network isolation (sandbox is the default).\n"
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
        console.print(f"[red]Template error:[/red] {escape(str(err))}")
        raise typer.Exit(1)

    # Instance directory = instance name
    agent_dir = get_agents_dir() / name

    # Check if agent already exists
    existing = _load_agent_metadata(name)
    if agent_dir.exists():
        if existing:
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
        else:
            # No metadata, treat as needing --force
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
        console.print(f"[red]Template error:[/red] {escape(str(err))}")
        raise typer.Exit(1)

    # Validate and normalize mount specs
    parsed_mounts = [_parse_mount(m) for m in mount]

    # Validate and normalize port specs
    parsed_ports = [_parse_port(p) for p in port]

    # Write metadata to agents.yaml
    metadata = {"template": template, "folder": folder_str}
    parsed_args = _parse_user_default_args(user_default_args)
    if parsed_args:
        metadata["user_default_args"] = parsed_args
    if parsed_mounts:
        metadata["mounts"] = parsed_mounts
    if parsed_ports:
        metadata["ports"] = parsed_ports
    save_agent(name, metadata)

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
    if parsed_mounts:
        panel_lines.append(f"Mounts: {len(parsed_mounts)}")
        for m in parsed_mounts:
            panel_lines.append(f"  {m}")
    if parsed_ports:
        panel_lines.append(f"Ports: {len(parsed_ports)}")
        for p in parsed_ports:
            panel_lines.append(f"  {p}")
    panel_lines.extend(
        [
            f"Network: {COMPOSE_NETWORK_NAME}",
            "Proxy: http://safeyolo:8080 (Docker DNS)",
        ]
    )
    console.print(Panel("\n".join(panel_lines), title="Success"))

    write_event("agent.added", kind=EventKind.AGENT, severity=Severity.LOW, summary=f"Agent {name} added (template={template})", agent=name, details={"template": template, "folder": folder_str})

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
    all_agents = load_all_agents()

    if agents_dir.exists():
        instances = [d for d in agents_dir.iterdir() if d.is_dir() and (d / "docker-compose.yml").exists()]
        # Auto-migrate any legacy .safeyolo.json files
        for inst_dir in instances:
            if inst_dir.name not in all_agents and (inst_dir / ".safeyolo.json").exists():
                migrate_from_json(inst_dir.name, inst_dir)
        # Re-read after migration
        all_agents = load_all_agents()

        if instances:
            table = Table(title="Configured Agents")
            table.add_column("Name", style="bold")
            table.add_column("Template")
            table.add_column("Folder")
            for inst_dir in sorted(instances, key=lambda d: d.name):
                metadata = all_agents.get(inst_dir.name, {})
                template = metadata.get("template", "?")
                folder = metadata.get("folder", "?")
                table.add_row(inst_dir.name, template, folder)
            console.print(table)
        else:
            console.print("[dim]No agents configured.[/dim]")
    else:
        console.print("[dim]No agents configured.[/dim]")


@agent_app.command()
def remove(
    name: str = typer.Argument(..., help="Agent instance name to remove"),
    clean: bool = typer.Option(False, "--clean", help="Also stop containers and remove images/volumes"),
) -> None:
    """Remove an agent configuration.

    Deletes the agent's compose file and configuration directory.

    Examples:

        safeyolo agent remove claude-code
        safeyolo agent remove claude-code --clean  # Also remove containers/images
    """
    _validate_instance_name(name)

    config_dir = find_config_dir()
    if not config_dir:
        console.print("[red]No SafeYolo configuration found.[/red]")
        raise typer.Exit(1)

    agent_dir = get_agents_dir() / name
    if not agent_dir.exists():
        console.print(f"[yellow]Agent not found: {escape(name)}[/yellow]")
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
    _store_remove_agent(name)
    write_event("agent.removed", kind=EventKind.AGENT, severity=Severity.LOW, summary=f"Agent {name} removed", agent=name, details={"clean": clean})
    console.print(f"[green]Removed agent: {name}[/green]")


@agent_app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def run(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Agent instance name to run"),
    folder: str = typer.Option(None, "--folder", "-f", help="Override folder to mount (default: from agent add)"),
    yolo: bool = typer.Option(True, "--yolo/--no-yolo", help="Auto-accept mode (skips permission prompts)"),
    fresh: bool = typer.Option(False, "--fresh", help="Ignore user_default_args, start fresh session"),
    mount: list[str] = typer.Option(
        [],
        "--mount",
        "-m",
        help="Extra folder to mount (/local/path:/container/path[:ro], repeatable, one-off)",
    ),
    port: list[str] = typer.Option(
        [],
        "--port",
        help="Expose container port to host (host_port:container_port, repeatable, one-off)",
    ),
    dangerously_allow_unowned: bool = typer.Option(
        False,
        "--dangerously-allow-unowned",
        help="Allow mounting directories you don't own",
    ),
) -> None:
    """Run an existing agent container.

    Starts SafeYolo if not running, then launches the agent container.
    Yolo mode is on by default (auto-accepts permission prompts).
    Use --no-yolo to require manual approval.

    Pass agent-specific flags after '--':

        safeyolo agent run boris -- --continue
        safeyolo agent run boris -- --resume my-session

    If user_default_args is configured (via 'agent config'), those args
    are used by default. Use --fresh to ignore them.

    Persistent mounts (from 'agent add --mount' or 'agent config --add-mount')
    are always included. Use --mount/-m here for additional one-off mounts.

    Examples:

        safeyolo agent run myproject
        safeyolo agent run myproject -f ~/other/folder
        safeyolo agent run myproject --no-yolo
        safeyolo agent run myproject --mount ~/data:/data:ro
        safeyolo agent run myproject --port 6080:6080
        safeyolo agent run myproject -- --continue
        safeyolo agent run myproject --fresh
    """
    # ctx.args contains everything after '--'
    agent_args = ctx.args if ctx.args else None

    # Validate transient mount specs
    parsed_mounts = [_parse_mount(m) for m in mount]

    # Validate transient port specs
    parsed_ports = [_parse_port(p) for p in port]

    exit_code = _run_agent(
        name,
        folder_override=folder,
        yolo=yolo,
        dangerously_allow_unowned=dangerously_allow_unowned,
        agent_args=agent_args,
        skip_default_args=fresh,
        extra_mounts=parsed_mounts if parsed_mounts else None,
        extra_ports=parsed_ports if parsed_ports else None,
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
    _validate_instance_name(name)

    config_dir = find_config_dir()
    if not config_dir:
        console.print("[red]No SafeYolo configuration found.[/red]")
        raise typer.Exit(1)

    agent_dir = get_agents_dir() / name
    compose_file = agent_dir / "docker-compose.yml"

    if not compose_file.exists():
        console.print(f"[red]Agent not found: {escape(name)}[/red]")
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
def stop(
    name: str = typer.Argument(..., help="Agent instance name to stop"),
) -> None:
    """Stop a running agent container.

    Examples:

        safeyolo agent stop myproject
    """
    _validate_instance_name(name)

    agent_dir = get_agents_dir() / name
    compose_file = agent_dir / "docker-compose.yml"

    if not compose_file.exists():
        console.print(f"[red]Agent not found: {escape(name)}[/red]")
        raise typer.Exit(1)

    # Check if actually running
    check = subprocess.run(
        ["docker", "ps", "-q", "-f", f"name=^/{name}$"],
        capture_output=True,
        text=True,
    )
    if not check.stdout.strip():
        console.print(f"Agent '{name}' is not running.")
        raise typer.Exit(0)

    console.print(f"Stopping {name}...")
    subprocess.run(["docker", "stop", name], capture_output=True)
    subprocess.run(["docker", "rm", name], capture_output=True)
    write_event("agent.stopped", kind=EventKind.AGENT, severity=Severity.LOW, summary=f"Agent {name} stopped by user", agent=name, details={"reason": "user_request"})
    console.print(f"[green]Stopped {name}.[/green]")


@agent_app.command()
def config(
    name: str = typer.Argument(..., help="Agent instance name"),
    user_default_args: str = typer.Option(
        None,
        "--user-default-args",
        help="Set default args for agent CLI (use '' to clear)",
    ),
    add_mount: list[str] = typer.Option(
        [],
        "--add-mount",
        help="Add persistent mount (/local/path:/container/path[:ro], repeatable)",
    ),
    remove_mount: list[str] = typer.Option(
        [],
        "--remove-mount",
        help="Remove persistent mount by container path (repeatable)",
    ),
    clear_mounts: bool = typer.Option(
        False,
        "--clear-mounts",
        help="Remove all persistent mounts",
    ),
    add_port: list[str] = typer.Option(
        [],
        "--add-port",
        help="Add persistent port mapping (host_port:container_port, repeatable)",
    ),
    remove_port: list[str] = typer.Option(
        [],
        "--remove-port",
        help="Remove persistent port mapping by container port (repeatable)",
    ),
    clear_ports: bool = typer.Option(
        False,
        "--clear-ports",
        help="Remove all persistent port mappings",
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
        safeyolo agent config boris --add-mount ~/data:/data
        safeyolo agent config boris --add-mount ~/refs:/refs:ro
        safeyolo agent config boris --remove-mount /data
        safeyolo agent config boris --clear-mounts
        safeyolo agent config boris --add-port 6080:6080
        safeyolo agent config boris --remove-port 6080
        safeyolo agent config boris --clear-ports
    """
    _validate_instance_name(name)

    metadata = _load_agent_metadata(name)
    if not metadata:
        console.print(f"[red]Agent not found: {escape(name)}[/red]")
        raise typer.Exit(1)

    has_updates = (
        user_default_args is not None
        or add_mount
        or remove_mount
        or clear_mounts
        or add_port
        or remove_port
        or clear_ports
    )

    if show or not has_updates:
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
        current_mounts = metadata.get("mounts", [])
        if current_mounts:
            table.add_row("Mounts", "\n".join(current_mounts))
        else:
            table.add_row("Mounts", "[dim]none[/dim]")
        current_ports = metadata.get("ports", [])
        if current_ports:
            table.add_row("Ports", "\n".join(current_ports))
        else:
            table.add_row("Ports", "[dim]none[/dim]")
        console.print(table)
        return

    # Update user_default_args
    if user_default_args is not None:
        if user_default_args == "":
            if "user_default_args" in metadata:
                del metadata["user_default_args"]
            console.print(f"[green]Cleared user_default_args for {name}[/green]")
        else:
            parsed_args = _parse_user_default_args(user_default_args)
            if parsed_args:
                metadata["user_default_args"] = parsed_args
                console.print(f"[green]Set user_default_args for {name}:[/green] {' '.join(parsed_args)}")

    # Handle mount updates
    current_mounts = list(metadata.get("mounts", []))

    if clear_mounts:
        current_mounts = []
        console.print(f"[green]Cleared all mounts for {name}[/green]")

    for spec in remove_mount:
        # Match by container path (the part after the first colon)
        before = len(current_mounts)
        current_mounts = [m for m in current_mounts if m.split(":")[1] != spec.rstrip("/")]
        removed = before - len(current_mounts)
        if removed:
            console.print(f"[green]Removed mount for {spec}[/green]")
        else:
            console.print(f"[yellow]No mount found for container path: {spec}[/yellow]")

    for spec in add_mount:
        parsed = _parse_mount(spec)
        # Check for duplicate container path
        container_path = parsed.split(":")[1]
        current_mounts = [m for m in current_mounts if m.split(":")[1] != container_path]
        current_mounts.append(parsed)
        console.print(f"[green]Added mount: {parsed}[/green]")

    if current_mounts:
        metadata["mounts"] = current_mounts
    elif "mounts" in metadata:
        del metadata["mounts"]

    # Handle port updates
    current_ports = list(metadata.get("ports", []))

    if clear_ports:
        current_ports = []
        console.print(f"[green]Cleared all ports for {name}[/green]")

    for spec in remove_port:
        # Match by container port (last colon-separated part)
        before = len(current_ports)
        current_ports = [p for p in current_ports if p.rsplit(":", 1)[-1] != spec]
        removed = before - len(current_ports)
        if removed:
            console.print(f"[green]Removed port mapping for container port {spec}[/green]")
        else:
            console.print(f"[yellow]No port mapping found for container port: {spec}[/yellow]")

    for spec in add_port:
        parsed = _parse_port(spec)
        # Dedup by container port (last colon-separated part)
        container_port = parsed.rsplit(":", 1)[-1]
        current_ports = [p for p in current_ports if p.rsplit(":", 1)[-1] != container_port]
        current_ports.append(parsed)
        console.print(f"[green]Added port: {parsed}[/green]")

    if current_ports:
        metadata["ports"] = current_ports
    elif "ports" in metadata:
        del metadata["ports"]

    save_agent(name, metadata)

    # Build list of what changed for the event
    changes = []
    if user_default_args is not None:
        changes.append("user_default_args")
    if add_mount or remove_mount or clear_mounts:
        changes.append("mounts")
    if add_port or remove_port or clear_ports:
        changes.append("ports")
    write_event("agent.config_changed", kind=EventKind.AGENT, severity=Severity.LOW, summary=f"Agent {name} config changed: {', '.join(changes)}", agent=name, details={"changes": changes})


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
    _validate_instance_name(name)

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


def _load_vault():
    """Import Vault class and return an unlocked vault instance.

    Returns (Vault, VaultCredential) tuple.
    """
    from .vault import _load_vault as vault_loader

    return vault_loader()


def _auto_credential_name(service_name: str, existing_names: list[str]) -> str:
    """Generate a unique credential name like {service}-cred, {service}-cred-2, etc."""
    base = f"{service_name}-cred"
    if base not in existing_names:
        return base
    n = 2
    while f"{base}-{n}" in existing_names:
        n += 1
    return f"{base}-{n}"


def _load_policy_hosts() -> dict:
    """Load hosts section from policy.yaml."""
    from ..config import _get_config_dir_path

    policy_path = _get_config_dir_path() / "policy.yaml"
    if not policy_path.exists():
        return {}
    try:
        raw = yaml.safe_load(policy_path.read_text())
        if raw and isinstance(raw, dict):
            return raw.get("hosts", {})
    except (OSError, yaml.YAMLError):
        pass  # Best-effort: missing or invalid policy is not fatal here
    return {}


@agent_app.command()
def authorize(
    agent_name: str = typer.Argument(..., help="Agent instance name"),
    service_name: str = typer.Argument(..., help="Service to authorize"),
    role: str = typer.Option(None, "--role", "-r", "--capability", help="Capability within the service"),
    token: str = typer.Option(None, "--token", help="Credential value (inline)"),
    token_file: Path = typer.Option(None, "--token-file", help="Read credential from file"),
    token_env: str = typer.Option(None, "--token-env", help="Read credential from environment variable"),
    credential_name: str = typer.Option(None, "--credential-name", "-n", help="Reuse existing vault credential"),
) -> None:
    """Authorize an agent to use a service.

    Resolves the service, picks a capability, stores the credential, and updates
    agents.yaml. One command takes an agent from "no access" to "authorized."

    Examples:

        safeyolo agent authorize boris gmail --capability read_and_send --token-env GMAIL_TOKEN
        safeyolo agent authorize boris slack --token-file ~/slack.key
        safeyolo agent authorize boris gmail --credential-name gmail-oauth2
    """
    # 1. Validate agent exists
    _validate_instance_name(agent_name)

    metadata = _load_agent_metadata(agent_name)
    if not metadata:
        console.print(f"[red]Error:[/red] Agent '{escape(agent_name)}' not found")
        raise typer.Exit(1)

    # 2. Resolve service
    svc = find_service(service_name)
    if not svc:
        console.print(f"[red]Error:[/red] Service '{escape(service_name)}' not found")
        raise typer.Exit(1)

    capabilities = svc.get("capabilities", {})
    if not capabilities:
        console.print(f"[red]Error:[/red] Service '{escape(service_name)}' has no capabilities defined")
        raise typer.Exit(1)

    # 3. Resolve capability
    cap_names = list(capabilities.keys())
    if role:
        if role not in capabilities:
            console.print(f"[red]Error:[/red] Capability '{escape(role)}' not found in {escape(service_name)}")
            console.print(f"Available capabilities: {', '.join(escape(c) for c in cap_names)}")
            raise typer.Exit(1)
        selected_role = role
    elif len(cap_names) == 1:
        selected_role = cap_names[0]
        console.print(f"Auto-selected capability: [cyan]{escape(selected_role)}[/cyan]")
    else:
        console.print("Available capabilities:")
        for i, cn in enumerate(cap_names, 1):
            desc = capabilities[cn].get("description", "")
            desc_str = f" — {escape(desc)}" if desc else ""
            console.print(f"  \\[{i}] {escape(cn)}{desc_str}")
        choice = input("Select capability [1]: ").strip()
        if not choice:
            choice = "1"
        try:
            idx = int(choice) - 1
            if idx < 0 or idx >= len(cap_names):
                raise ValueError
            selected_role = cap_names[idx]
        except ValueError:
            console.print("[red]Error:[/red] Invalid selection")
            raise typer.Exit(1)

    # Auth type comes from service-level auth (v1 schema)
    auth_config = svc.get("auth", {})
    auth_type = auth_config.get("type", "bearer")

    # 4. Resolve credential
    vault = None
    VaultCredential = None
    cred_name = None

    if credential_name:
        # Reuse existing vault entry
        vault, VaultCredential = _load_vault()
        existing = vault.get(credential_name)
        if not existing:
            console.print(f"[red]Error:[/red] Credential '{escape(credential_name)}' not found in vault")
            names = vault.list_names()
            if names:
                console.print(f"Available: {', '.join(escape(n) for n in names)}")
            raise typer.Exit(1)
        cred_name = credential_name
    elif token or token_file or token_env:
        # Store new credential in vault
        if token:
            cred_value = token
        elif token_file:
            if not token_file.exists():
                console.print(f"[red]Error:[/red] File not found: {token_file}")
                raise typer.Exit(1)
            cred_value = token_file.read_text().strip()
        else:
            cred_value = os.environ.get(token_env, "")
            if not cred_value:
                console.print(f"[red]Error:[/red] Environment variable '{escape(token_env)}' is empty or not set")
                raise typer.Exit(1)

        vault, VaultCredential = _load_vault()
        existing_names = vault.list_names()
        cred_name = _auto_credential_name(service_name, existing_names)
        cred = VaultCredential(name=cred_name, type=auth_type, value=cred_value)
        vault.store(cred)
        console.print(f"[green]Stored credential:[/green] {escape(cred_name)} (type={escape(auth_type)})")
    else:
        # Interactive flow
        vault, VaultCredential = _load_vault()
        existing_names = vault.list_names()
        matching = [n for n in existing_names if n.startswith(f"{service_name}-")]

        if matching:
            console.print("Existing credentials:")
            for i, n in enumerate(matching, 1):
                console.print(f"  \\[{i}] {escape(n)}")
            console.print(f"  \\[{len(matching) + 1}] Paste new")
            choice = input("Select [1]: ").strip()
            if not choice:
                choice = "1"
            try:
                idx = int(choice) - 1
                if idx < 0 or idx > len(matching):
                    raise ValueError
                if idx < len(matching):
                    cred_name = matching[idx]
                else:
                    # Paste new
                    cred_value = getpass.getpass("Credential value: ")
                    if not cred_value:
                        console.print("[red]Error:[/red] Empty credential value")
                        raise typer.Exit(1)
                    cred_name = _auto_credential_name(service_name, existing_names)
                    cred = VaultCredential(name=cred_name, type=auth_type, value=cred_value)
                    vault.store(cred)
                    console.print(f"[green]Stored credential:[/green] {escape(cred_name)} (type={escape(auth_type)})")
            except ValueError:
                console.print("[red]Error:[/red] Invalid selection")
                raise typer.Exit(1)
        else:
            cred_value = getpass.getpass("Credential value: ")
            if not cred_value:
                console.print("[red]Error:[/red] Empty credential value")
                raise typer.Exit(1)
            cred_name = _auto_credential_name(service_name, existing_names)
            cred = VaultCredential(name=cred_name, type=auth_type, value=cred_value)
            vault.store(cred)
            console.print(f"[green]Stored credential:[/green] {escape(cred_name)} (type={escape(auth_type)})")

    # 6. Write to agents.yaml
    services = metadata.setdefault("services", {})
    services[service_name] = {"capability": selected_role, "token": cred_name}
    save_agent(agent_name, metadata)

    esc_agent = escape(agent_name)
    esc_svc = escape(service_name)
    esc_cap = escape(selected_role)
    esc_cred = escape(cred_name)

    console.print(f"\n[green]Authorized:[/green] {esc_agent} → {esc_svc} (capability={esc_cap}, credential={esc_cred})")

    # 7. Check policy.yaml for host binding
    default_host = svc.get("default_host", "")
    if default_host:
        esc_host = escape(default_host)
        hosts = _load_policy_hosts()
        host_config = hosts.get(default_host)
        if isinstance(host_config, dict) and host_config.get("service") == service_name:
            console.print(f"[green]Host binding found:[/green] {esc_host}")
        elif host_config is not None:
            console.print("\n[yellow]Final step:[/yellow] Add service binding to existing host entry in policy.yaml:")
            console.print(f"    [bold]{esc_host}: {{ service: {esc_svc}, ... }}[/bold]")
        else:
            console.print("\n[yellow]Final step:[/yellow] Add host binding to policy.yaml:")
            console.print(f"    [bold]{esc_host}: {{ service: {esc_svc} }}[/bold]")
    else:
        console.print(f"\n[yellow]Final step:[/yellow] Add a host binding for '{esc_svc}' in policy.yaml")
        console.print("  This service has no default_host, so you'll need to map the target host manually:")
        console.print(f"    [bold]your-host.example.com: {{ service: {esc_svc} }}[/bold]")


@agent_app.command()
def revoke(
    agent_name: str = typer.Argument(..., help="Agent instance name"),
    service_name: str = typer.Argument(..., help="Service to revoke"),
) -> None:
    """Revoke an agent's access to a service.

    Removes the service binding from agents.yaml. The vault credential
    is preserved (print reminder to remove manually).

    Examples:

        safeyolo agent revoke boris gmail
    """
    # 1. Load agent metadata
    _validate_instance_name(agent_name)

    metadata = _load_agent_metadata(agent_name)
    if not metadata:
        console.print(f"[red]Error:[/red] Agent '{escape(agent_name)}' not found")
        raise typer.Exit(1)

    services = metadata.get("services", {})
    if service_name not in services:
        console.print(f"[red]Error:[/red] Agent '{escape(agent_name)}' is not authorized for '{escape(service_name)}'")
        raise typer.Exit(1)

    # 2. Note credential name before removing
    service_entry = services[service_name]
    cred_name = service_entry.get("token", "") if isinstance(service_entry, dict) else ""

    # 3. Remove service entry
    del services[service_name]
    if not services:
        del metadata["services"]
    save_agent(agent_name, metadata)

    # 4. Confirm
    console.print(f"[green]Revoked:[/green] {escape(agent_name)} → {escape(service_name)}")

    # 5. Credential reminder
    if cred_name:
        console.print(
            f"Credential '{escape(cred_name)}' still in vault. "
            f"To remove: [bold]safeyolo vault remove {escape(cred_name)}[/bold]"
        )
