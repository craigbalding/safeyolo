"""Coord plane v0 CLI — bootstrap, agents, rooms, chat.

Disposable v0 substrate for #371 dogfood. `safeyolo coord ...` is a separate
tree from the main SafeYolo CLI; nothing here touches proxy, policy, or the
existing agent registry.
"""

from __future__ import annotations

import json
import shlex
import sys
import time
from datetime import UTC, datetime

import typer
from rich.console import Console
from rich.table import Table

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


@coord_app.command()
def init() -> None:
    """Initialize coord store; mint instance identity if absent. Idempotent."""
    instance_id = api.bootstrap()
    console.print(f"[green]coord initialized[/]  instance_id={instance_id}")


agent_app = typer.Typer(name="agent", help="Agent identity commands.", no_args_is_help=True)
coord_app.add_typer(agent_app, name="agent")


@agent_app.command("add")
def agent_add(name: str = typer.Argument(..., help="Human name for the agent")) -> None:
    """Mint a new agent_id for `name` and print it."""
    api.bootstrap()
    try:
        agent_id = api.add_agent(name)
    except api.ConflictError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)
    console.print(f"[green]agent added[/]  name={name}  agent_id={agent_id}")


@agent_app.command("list")
def agent_list() -> None:
    """List all agents."""
    api.bootstrap()
    agents = api.list_agents()
    if not agents:
        console.print("[dim]no agents yet[/]")
        return
    table = Table("name", "agent_id", "created_at")
    for a in agents:
        table.add_row(a["name"], a["agent_id"], _fmt_ts(a["created_at"]))
    console.print(table)


room_app = typer.Typer(name="room", help="Room commands.", no_args_is_help=True)
coord_app.add_typer(room_app, name="room")


@room_app.command("create")
def room_create(
    name: str = typer.Argument(..., help="Room name"),
    members: list[str] = typer.Option(
        [], "--member", "-m",
        help="Agent name(s) to grant send+receive on the room. Repeatable.",
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
        agents = [a for a in api.list_agents() if a["name"] == member_name]
        if not agents:
            console.print(f"[red]agent {member_name!r} not found; skipping[/]")
            continue
        api.grant(name, "agent", agents[0]["agent_id"])
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
    agent_name: str = typer.Argument(..., help="Agent name"),
    permissions: str = typer.Option(
        "send,receive", "--perm", help="Comma-separated permissions"
    ),
) -> None:
    """Grant an agent send+receive permissions on a room."""
    api.bootstrap()
    agents = [a for a in api.list_agents() if a["name"] == agent_name]
    if not agents:
        console.print(f"[red]agent {agent_name!r} not found[/]")
        raise typer.Exit(1)
    perms = [p.strip() for p in permissions.split(",") if p.strip()]
    api.grant(room, "agent", agents[0]["agent_id"], permissions=perms)
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
    # Print retained history first
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
            # Drain any new messages after send or empty poll
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
def mcp_config(
    agent_name: str = typer.Argument(..., help="Agent name previously added via `coord agent add`"),
) -> None:
    """Print an MCP server config snippet for Claude Code, keyed to this agent."""
    api.bootstrap()
    agents = [a for a in api.list_agents() if a["name"] == agent_name]
    if not agents:
        console.print(f"[red]agent {agent_name!r} not found[/]", err=True)
        raise typer.Exit(1)
    agent_id = agents[0]["agent_id"]

    python = shlex.quote(sys.executable)
    config = {
        "mcpServers": {
            "safeyolo-coord": {
                "command": python,
                "args": ["-m", "safeyolo.coord.mcp_server"],
                "env": {
                    "SAFEYOLO_COORD_AGENT_ID": agent_id,
                },
            }
        }
    }
    console.print(json.dumps(config, indent=2))
