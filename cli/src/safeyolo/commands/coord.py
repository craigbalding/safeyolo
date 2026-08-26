"""Coord plane v0 CLI — bootstrap, rooms, chat.

Disposable v0 substrate for #371 dogfood. `safeyolo coord ...` is a separate
tree from proxy / policy / vault. Agents themselves are managed by the
existing `safeyolo agent add` command; this module never mints agent IDs.
"""

from __future__ import annotations

import json
import sys
import time
from datetime import UTC, datetime

import typer
from rich.console import Console
from rich.table import Table

from ..agents_store import get_or_mint_agent_id, load_all_agents
from ..coord import api

coord_app = typer.Typer(
    name="coord",
    help="Coordination-plane v0 (dogfood substrate for #371).",
    no_args_is_help=True,
)

console = Console()


def _fmt_ts(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=UTC).isoformat(timespec="seconds")


def _render_message(m: dict) -> None:
    kind = m["sender_kind"]
    who = m.get("sender_agent_id") or "operator"
    ts = _fmt_ts(m["sent_at"])
    style = "bold yellow" if kind == "operator" else "bold cyan"
    console.print(f"[{style}]{who}[/] [dim]{ts} seq={m['sequence']}[/]")
    console.print(m["body"])
    console.print()


def _resolve_agent_id(name: str) -> str:
    """Look up the durable agent_id for `name`. Raises Exit(1) if unknown."""
    if name not in load_all_agents():
        console.print(f"[red]agent {name!r} not registered (run `safeyolo agent add {name} ...`)[/]")
        raise typer.Exit(1)
    return get_or_mint_agent_id(name)


@coord_app.command()
def init() -> None:
    """Initialize coord store; mint instance identity if absent. Idempotent."""
    instance_id = api.bootstrap()
    console.print(f"[green]coord initialized[/]  instance_id={instance_id}")


room_app = typer.Typer(name="room", help="Room commands.", no_args_is_help=True)
coord_app.add_typer(room_app, name="room")


@room_app.command("create")
def room_create(
    name: str = typer.Argument(..., help="Room name"),
    members: list[str] = typer.Option(
        [], "--member", "-m",
        help="Registered agent name(s) to grant send+receive on the room. Repeatable.",
    ),
    with_operator: bool = typer.Option(
        True, "--with-operator/--no-operator",
        help="Grant the operator send+receive on the room.",
    ),
) -> None:
    """Create a room; optionally grant listed agents + the operator."""
    api.bootstrap()
    try:
        room_id = api.create_room(name)
    except api.ConflictError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)

    granted = []
    for member_name in members:
        agent_id = _resolve_agent_id(member_name)
        api.grant(name, "agent", agent_id)
        granted.append(member_name)

    if with_operator:
        api.grant(name, "operator", "operator")

    console.print(f"[green]room created[/]  name={name}  room_id={room_id}")
    if granted:
        console.print(f"[green]granted agents[/]: {', '.join(granted)}")
    if with_operator:
        console.print("[green]granted operator[/]")


@room_app.command("list")
def room_list() -> None:
    """List all rooms."""
    api.bootstrap()
    rooms = api.list_rooms()
    if not rooms:
        console.print("[dim]no rooms yet[/]")
        return
    table = Table("name", "room_id", "created_at")
    for r in rooms:
        table.add_row(r["name"], r["room_id"], _fmt_ts(r["created_at"]))
    console.print(table)


@coord_app.command()
def grant(
    room: str = typer.Argument(..., help="Room name"),
    agent_name: str = typer.Argument(..., help="Registered agent name"),
    permissions: str = typer.Option(
        "send,receive", "--perm", help="Comma-separated permissions"
    ),
) -> None:
    """Grant a registered agent permissions on a room."""
    api.bootstrap()
    agent_id = _resolve_agent_id(agent_name)
    perms = [p.strip() for p in permissions.split(",") if p.strip()]
    api.grant(room, "agent", agent_id, permissions=perms)
    console.print(f"[green]granted[/]  {agent_name} on {room}: {perms}")


@coord_app.command()
def chat(
    room: str = typer.Argument(..., help="Room name"),
    observe: bool = typer.Option(
        False, "--observe/--interactive",
        help="Read-only tail; do not accept operator input.",
    ),
    since: int = typer.Option(
        0, "--since", help="Start displaying messages with sequence > SINCE (0 = all).",
    ),
) -> None:
    """Attach to a room as operator. Interactive by default; --observe for read-only tail."""
    api.bootstrap()
    try:
        api.join_room(room, "operator", "operator")
    except (api.NotFoundError, api.GrantError) as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)

    console.print(f"[bold]attached to room[/] {room}  (mode={'observe' if observe else 'interactive'})")
    console.print("[dim]---[/]")

    cursor = since
    while True:
        page = api.read_room(room, "operator", "operator",
                             since_sequence=cursor, limit=api.READ_PAGE_MAX)
        for m in page["messages"]:
            _render_message(m)
        cursor = page["next_cursor"]
        if not page["has_more"]:
            break

    if observe:
        _observe_loop(room, cursor)
    else:
        _interactive_loop(room, cursor)


def _observe_loop(room: str, cursor: int) -> None:
    console.print("[dim]--- observing (Ctrl-C to detach) ---[/]")
    try:
        while True:
            page = api.read_room(room, "operator", "operator",
                                 since_sequence=cursor, limit=api.READ_PAGE_MAX)
            for m in page["messages"]:
                _render_message(m)
            cursor = page["next_cursor"]
            if not page["has_more"]:
                time.sleep(0.5)
    except KeyboardInterrupt:
        console.print("\n[dim]detached[/]")


def _interactive_loop(room: str, cursor: int) -> None:
    console.print("[dim]--- interactive (empty line polls; :q to quit) ---[/]")
    try:
        while True:
            try:
                line = input("op> ")
            except EOFError:
                break
            if line.strip() == ":q":
                break
            if line.strip():
                try:
                    api.send(room, "operator", None, line)
                except api.GrantError as e:
                    console.print(f"[red]{e}[/]")
                    break
            while True:
                page = api.read_room(room, "operator", "operator",
                                     since_sequence=cursor, limit=api.READ_PAGE_MAX)
                for m in page["messages"]:
                    _render_message(m)
                cursor = page["next_cursor"]
                if not page["has_more"]:
                    break
    except KeyboardInterrupt:
        pass
    console.print("\n[dim]detached[/]")


@coord_app.command("mcp-config")
def mcp_config() -> None:
    """Print the MCP server config for Claude Code sessions.

    The same config works for every agent's sandbox: identity comes from the
    per-agent proxy attribution (transport-derived per #371), not from any
    env var. Drop this into each agent's `.mcp.json`.
    """
    python = sys.executable
    config = {
        "mcpServers": {
            "safeyolo-coord": {
                "command": python,
                "args": ["-m", "safeyolo.coord.mcp_server"],
            }
        }
    }
    console.print(json.dumps(config, indent=2))
