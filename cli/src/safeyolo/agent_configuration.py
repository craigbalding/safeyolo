"""Agent name, memory, and host-mount configuration validation."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

import typer
from rich.console import Console
from rich.markup import escape

from .mount_protection import is_path_protected

console = Console()

DEFAULT_AGENT_MEMORY_MB = 4096

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


def _effective_agent_memory_mb(metadata: dict) -> int:
    """Return a validated per-agent memory allocation in MiB."""
    value = metadata.get("memory_mb", DEFAULT_AGENT_MEMORY_MB)
    if type(value) is not int or value <= 0:
        raise ValueError("agent memory_mb must be a positive integer")
    return value


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
    if ".." in PurePosixPath(container_path).parts:
        console.print(f"[red]Container path cannot contain '..':[/red] {escape(container_path)}")
        raise typer.Exit(1)
    container_path = str(PurePosixPath(container_path))
    protected_destinations = {
        "/",
        "/home/agent",
        "/workspace",
    }
    protected_trees = ("/dev", "/proc", "/safeyolo", "/safeyolo-status", "/sys")
    if container_path in protected_destinations or any(
        container_path == root or container_path.startswith(f"{root}/") for root in protected_trees
    ):
        console.print(f"[red]Container mount destination is reserved:[/red] {escape(container_path)}")
        raise typer.Exit(1)

    if not host_path.exists():
        console.print(f"[red]Host path not found:[/red] {host_path}")
        raise typer.Exit(1)

    is_ro = len(parts) == 3 and parts[2] == "ro"

    if len(parts) == 3 and not is_ro:
        console.print(f"[red]Invalid mount option:[/red] {escape(parts[2])} (only 'ro' supported)")
        raise typer.Exit(1)

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


def _mount_spec_to_share(mount_spec: str) -> tuple[str, str, bool]:
    """Convert a validated mount string to (host, guest destination, read-only)."""
    parts = mount_spec.split(":")
    return parts[0], parts[1], len(parts) == 3


def _resolve_extra_shares(
    metadata: dict,
    transient_mounts: list[str] | None,
) -> list[tuple[str, str, bool]]:
    """Merge persistent and one-off mounts, with one-off destinations winning."""
    persistent = metadata.get("mounts", []) or []
    if not isinstance(persistent, list) or not all(isinstance(item, str) for item in persistent):
        console.print("[red]Agent mount metadata is invalid; expected a list of strings.[/red]")
        raise typer.Exit(1)

    by_destination: dict[str, tuple[str, str, bool]] = {}
    for spec in [*persistent, *(transient_mounts or [])]:
        normalized = _parse_mount(spec)
        share = _mount_spec_to_share(normalized)
        # Reinsert so a transient override also takes the later mount's order.
        by_destination.pop(share[1], None)
        by_destination[share[1]] = share
    return list(by_destination.values())
