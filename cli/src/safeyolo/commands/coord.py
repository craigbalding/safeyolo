"""Coord plane v0 CLI — bootstrap, rooms, chat.

Disposable v0 substrate for #371 dogfood. `safeyolo coord ...` is a separate
tree from proxy / policy / vault. Agents themselves are managed by the
existing `safeyolo agent add` command; this module never mints agent IDs.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime

import typer
from rich.console import Console
from rich.table import Table

from ..agents_store import get_or_mint_agent_id, load_all_agents
from ..coord import api

# One-shot CLI commands (room create, grant, revoke) each spin up a
# fresh event loop with `asyncio.run` — cheap and no lifetime issues.
# Long-running commands (chat / observe) hold a single event loop for
# their duration via `_ChatRuntime` below so the NATS client survives
# across polls rather than being torn down and rebuilt every iteration
# (reviewer round-4 point 3).
_run = asyncio.run

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
    # Prefer sender_agent_name (#22 display metadata) when present; fall
    # back to agent_id for pre-#22 rows that have no name persisted.
    if kind == "operator":
        who = "operator"
    else:
        who = m.get("sender_agent_name") or m.get("sender_agent_id") or "?"
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
        room_id = _run(api.create_room(name))
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
def revoke(
    room: str = typer.Argument(..., help="Room name"),
    agent_name: str = typer.Argument(..., help="Registered agent name"),
) -> None:
    """Revoke a registered agent's active grant on a room.

    Room semantic per #371: agent loses access while revoked; retained
    history is not erased. A subsequent `grant` re-exposes whatever is
    still retained.
    """
    api.bootstrap()
    agent_id = _resolve_agent_id(agent_name)
    try:
        changed = api.revoke_grant(room, "agent", agent_id)
    except api.NotFoundError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)
    if changed:
        console.print(f"[green]revoked[/]  {agent_name} on {room}")
    else:
        console.print(f"[yellow]no active grant to revoke[/]  {agent_name} on {room}")


class _ChatRuntime:
    """One event loop + one NATS connection for the lifetime of a
    single `safeyolo coord chat` invocation.

    Without this, observe/interactive loops call `asyncio.run(...)` per
    poll, which spins a fresh event loop each iteration. The NATS
    client is loop-bound and deliberately abandons/recreates its
    connection on loop change (a test workaround) — good for tests,
    terrible as a production operator path because every poll pays a
    NATS reconnect. Hold one loop for the command's lifetime instead.
    """

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()

    def run(self, coro):
        return self._loop.run_until_complete(coro)

    def close(self) -> None:
        try:
            from ..coord import nats_client
            self._loop.run_until_complete(nats_client.close())
        except Exception:  # noqa: BLE001
            pass  # best-effort teardown
        self._loop.close()


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
    """Attach to a room as operator. Interactive by default; --observe for read-only tail.

    Interactive mode polls only when you press Enter (empty line is a
    poll-and-print). For live scrolling of incoming messages, run a second
    terminal pane with `safeyolo coord chat <room> --observe` — that mode
    polls continuously and prints new messages as they arrive. Two panes:
    interactive on one, observe on the other.
    """
    api.bootstrap()
    try:
        api.join_room(room, "operator", "operator")
    except (api.NotFoundError, api.GrantError) as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)

    console.print(f"[bold]attached to room[/] {room}  (mode={'observe' if observe else 'interactive'})")
    console.print("[dim]---[/]")

    runtime = _ChatRuntime()
    try:
        cursor = since
        while True:
            page = runtime.run(api.read_room(room, "operator", "operator",
                                             since_sequence=cursor, limit=api.READ_PAGE_MAX))
            for m in page["messages"]:
                _render_message(m)
            cursor = page["next_cursor"]
            if not page["has_more"]:
                break

        if observe:
            _observe_loop(runtime, room, cursor)
        else:
            _interactive_loop(runtime, room, cursor)
    finally:
        runtime.close()


def _observe_loop(runtime: _ChatRuntime, room: str, cursor: int) -> None:
    console.print("[dim]--- observing (Ctrl-C to detach) ---[/]")
    try:
        while True:
            page = runtime.run(api.read_room(room, "operator", "operator",
                                             since_sequence=cursor, limit=api.READ_PAGE_MAX))
            for m in page["messages"]:
                _render_message(m)
            cursor = page["next_cursor"]
            if not page["has_more"]:
                time.sleep(0.5)
    except KeyboardInterrupt:
        console.print("\n[dim]detached[/]")


def _interactive_loop(runtime: _ChatRuntime, room: str, cursor: int) -> None:
    console.print("[dim]--- interactive (empty line polls; :q to quit) ---[/]")
    console.print(
        f"[dim]tip: for live scrolling, run `safeyolo coord chat {room} "
        "--observe` in a second pane[/]"
    )
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
                    runtime.run(api.send(room, "operator", None, line))
                except api.GrantError as e:
                    console.print(f"[red]{e}[/]")
                    break
            while True:
                page = runtime.run(api.read_room(room, "operator", "operator",
                                                 since_sequence=cursor, limit=api.READ_PAGE_MAX))
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
    """Print instructions and MCP config for wiring an agent to the coord API.

    The MCP server is a standalone one-file adapter shipped at
    `contrib/safeyolo-coord-mcp.py`. It only depends on `mcp` and `httpx` and
    calls the coord Agent API via `http://_safeyolo.proxy.internal`, so the
    agent sandbox does NOT need SafeYolo (and mitmproxy) installed.

    Identity is transport-derived: whichever sandbox the MCP server runs in
    is attributed to that agent by the SafeYolo proxy. Same config works for
    every agent.
    """
    console.print("""[bold]1. Stage the standalone MCP server inside the agent sandbox[/]

Copy `contrib/safeyolo-coord-mcp.py` from this checkout into the sandbox
(via mount, host-script, or the agent's own tooling). Make it executable.

[bold]2. Install its two dependencies inside the sandbox[/]

  [dim]uv pip install --system 'mcp>=2.0' 'httpx>=0.25'[/]
    (or your sandbox's usual python package tool)

[bold]3. Add the MCP config to your agent's harness[/]

Below is a minimal `.mcp.json` snippet. Adjust `command` to the path where
you staged the script inside the sandbox.
""")
    config = {
        "mcpServers": {
            "safeyolo-coord": {
                "command": "python3",
                "args": ["/path/to/safeyolo-coord-mcp.py"],
            }
        }
    }
    console.print(json.dumps(config, indent=2))
    console.print("""
[bold]Notes[/]

- No agent_id env var needed. Identity comes from proxy attribution.
- Bearer token is read fresh from /app/agent_token per call (rotation-safe).
- Overrides (rarely needed):
    SAFEYOLO_COORD_BASE_URL   default http://_safeyolo.proxy.internal
    SAFEYOLO_COORD_TOKEN_PATH default /app/agent_token
""")
