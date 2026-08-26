"""Coord plane v0 CLI — bootstrap, rooms, chat.

Disposable v0 substrate for #371 dogfood. `safeyolo coord ...` is a separate
tree from proxy / policy / vault. Agents themselves are managed by the
existing `safeyolo agent add` command; this module never mints agent IDs.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import time
from datetime import UTC, datetime

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

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


# Unicode bidi ordering controls (TR9 / core spec ch.23). Left active in a
# terminal these visually reorder a body, so a message can display as text it
# does not contain.
_BIDI_CONTROLS = {
    0x061C: "ALM", 0x200E: "LRM", 0x200F: "RLM",
    0x202A: "LRE", 0x202B: "RLE", 0x202C: "PDF", 0x202D: "LRO", 0x202E: "RLO",
    0x2066: "LRI", 0x2067: "RLI", 0x2068: "FSI", 0x2069: "PDI",
}


def _visible_controls(text: str) -> str:
    """Render terminal- and bidi-active characters inert but visible.

    Bodies are peer-authored. Raw ESC lets one drive the operator's terminal
    -- move the cursor, erase what is already on screen, rewrite the
    provenance header printed above it -- which defeats envelope trust
    without ever touching the envelope. Disabling console markup is not
    sufficient: markup=False still emits ESC unchanged.

    Nothing is silently dropped. An operator should be able to see that a
    body tried, so the characters are shown rather than deleted.
    """
    out = []
    for ch in text:
        cp = ord(ch)
        if ch in ("\n", "\t"):
            out.append(ch)
        elif cp in _BIDI_CONTROLS:
            out.append(f"\u27e6{_BIDI_CONTROLS[cp]} U+{cp:04X}\u27e7")
        elif cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F:
            out.append(f"\\x{cp:02x}")
        else:
            out.append(ch)
    return "".join(out)


def _render_body(body: str) -> None:
    """Print a peer-authored body inside a visual namespace of its own.

    Text() is used rather than console markup so the body can never be
    parsed as styling, and every *physical* line is gutter-prefixed so
    ordinary plaintext cannot masquerade as a top-level provenance header.
    """
    gutter = Text("\u2502 ", style="dim")
    width = max(20, console.width - 2)
    for line in _visible_controls(body).split("\n"):
        # Wrap here rather than letting the console do it. Console wrapping
        # puts continuation lines at column 0 with no gutter, so a body needed
        # only one long line for part of itself to render as top-level text --
        # which is exactly what the gutter exists to prevent.
        segments = Text(line).wrap(console, width, overflow="fold") or [Text("")]
        for segment in segments:
            console.print(gutter + segment)


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
    console.print(
        f"[{style}]{escape(_visible_controls(who))}[/] "
        f"[dim]{ts} seq={m['sequence']}[/]"
    )
    _render_body(m["body"])
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


# Short aliases matter at a chat prompt -- these get typed constantly.
_PASTE_CMDS = (":paste", ":p")
_EDIT_CMDS = (":edit", ":e")


def _read_clipboard() -> tuple[str | None, str]:
    """Read the host clipboard verbatim. Returns (text, error).

    Terminal input mangles embedded control bytes -- ^R is REPRINT under
    IEXTEN, or reverse-i-search when readline drives input() -- so pasted
    terminal output arrives truncated. Reading the clipboard directly skips
    the line discipline entirely.
    """
    candidates = (
        ["pbpaste"],                                   # macOS
        ["wl-paste", "--no-newline"],                  # Wayland
        ["xclip", "-selection", "clipboard", "-o"],    # X11
        ["xsel", "--clipboard", "--output"],           # X11, alternative
    )
    tried = []
    for argv in candidates:
        if shutil.which(argv[0]) is None:
            continue
        tried.append(argv[0])
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=10)
        except (OSError, subprocess.SubprocessError) as e:  # noqa: PERF203
            return None, f"{argv[0]} failed: {e}"
        if proc.returncode == 0:
            return proc.stdout.decode("utf-8", errors="replace"), ""
    if not tried:
        return None, "no clipboard tool found (need pbpaste, wl-paste, xclip or xsel)"
    return None, f"clipboard read failed via {', '.join(tried)}"


def _read_editor() -> tuple[str | None, str]:
    """Compose a message in $EDITOR. Portable fallback to :paste."""
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi"
    fd, path = tempfile.mkstemp(suffix=".md", prefix="safeyolo-coord-")
    os.close(fd)
    try:
        # shell=True so a multi-word $EDITOR ("code -w", "emacsclient -nw")
        # works the way the user configured it.
        rc = subprocess.call(f"{editor} {shlex.quote(path)}", shell=True)
        if rc != 0:
            return None, f"{editor} exited {rc}; nothing sent"
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(), ""
    except OSError as e:
        return None, f"could not run {editor}: {e}"
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _confirm_send(body: str) -> bool:
    """Preview a composed body and ask before it goes to the room."""
    n_bytes = len(body.encode("utf-8"))
    if n_bytes > api.MAX_BODY_BYTES:
        console.print(
            f"[red]{n_bytes} bytes exceeds the {api.MAX_BODY_BYTES} byte "
            "limit; not sent[/]"
        )
        return False
    lines = body.splitlines()
    head = lines[0][:70] if lines else ""
    console.print(
        Text(f"{len(lines)} lines, {n_bytes} bytes -- ", style="dim")
        + Text(_visible_controls(head) + "...", style="dim")
    )
    try:
        return input("send? [Y/n] ").strip().lower() in ("", "y", "yes")
    except EOFError:
        return False


def _interactive_loop(runtime: _ChatRuntime, room: str, cursor: int) -> None:
    console.print(
        "[dim]--- interactive (empty line polls; :paste/:p clipboard, "
        ":edit/:e in $EDITOR, :q to quit) ---[/]"
    )
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
            command = line.strip()
            if command == ":q":
                break
            body: str | None = None
            if command in _PASTE_CMDS or command in _EDIT_CMDS:
                # Typing at the prompt routes bytes through the terminal line
                # discipline, which eats embedded control characters. Both of
                # these read the text from somewhere the tty never sees.
                body, err = (
                    _read_clipboard() if command in _PASTE_CMDS else _read_editor()
                )
                if body is None:
                    console.print(f"[red]{err}[/]")
                    body = None
                else:
                    body = body.rstrip("\n")
                    if not body.strip():
                        console.print("[dim]empty; nothing sent[/]")
                        body = None
                    elif not _confirm_send(body):
                        console.print("[dim]cancelled[/]")
                        body = None
            elif command:
                body = line
            if body is not None:
                try:
                    runtime.run(api.send(room, "operator", None, body))
                except ValueError as e:
                    console.print(f"[red]{e}[/]")
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
