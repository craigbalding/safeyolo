"""Coordination-plane CLI for rooms, trusted state, and messaging.

`safeyolo coord ...` is a separate tree from proxy / policy / vault. Agents
themselves are managed by the existing `safeyolo agent add` command; this
module never mints agent IDs.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import UTC, date, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from ..agents_store import get_or_mint_agent_id, load_all_agents
from ..coord import api
from ..coord.identity import new_operation_id
from ..coord.nats_client import (
    CoordDataError,
    NatsPublishOutcomeUnknown,
    NatsUnavailable,
)
from ..factory_contract import FactoryContractError, factories_dir, load_active_snapshot

if TYPE_CHECKING:
    from prompt_toolkit import PromptSession

# One-shot CLI commands (room create, grant, revoke) each spin up a
# fresh event loop with `asyncio.run` — cheap and no lifetime issues.
# Long-running commands (chat / observe) hold a single event loop for
# their duration via `_ChatRuntime` below so the NATS client survives
# across polls rather than being torn down and rebuilt every iteration
# (reviewer round-4 point 3).
_run = asyncio.run

coord_app = typer.Typer(
    name="coord",
    help="Coordination-plane rooms, trusted state, and messaging.",
    no_args_is_help=True,
)

mattermost_app = typer.Typer(
    name="mattermost",
    help="Project selected coord rooms to one authenticated Mattermost operator.",
    no_args_is_help=True,
)
coord_app.add_typer(mattermost_app, name="mattermost")

console = Console()


def _default_mattermost_config() -> Path:
    from ..config import get_config_dir

    return get_config_dir() / "coord-mattermost.toml"


async def _mattermost_check(config_path: Path) -> None:
    from ..coord.mattermost import (
        HTTPMattermostAPI,
        MattermostAdapter,
        MattermostState,
        load_config,
        read_bot_token,
    )

    config = load_config(config_path)
    token = read_bot_token(config.bot_token_file)
    state = MattermostState(config)
    async with HTTPMattermostAPI(config, token) as client:
        adapter = MattermostAdapter(config, state, client)
        await adapter.verify()
        await adapter.verify_action_listener()


async def _mattermost_run(config_path: Path, *, once: bool) -> None:
    from ..coord.mattermost import (
        HTTPMattermostAPI,
        MattermostAdapter,
        MattermostState,
        load_config,
        read_bot_token,
    )

    config = load_config(config_path)
    token = read_bot_token(config.bot_token_file)
    state = MattermostState(config)
    async with HTTPMattermostAPI(config, token) as client:
        adapter = MattermostAdapter(config, state, client)
        if once:
            await adapter.run_once(verify=True)
        else:
            await adapter.run_forever()


@mattermost_app.command("check")
def mattermost_check(
    config: Path = typer.Option(
        None,
        "--config",
        help="External adapter TOML (default: ~/.safeyolo/coord-mattermost.toml).",
    ),
) -> None:
    """Validate identities, mapping, grants, and the optional callback bind."""

    from ..coord.mattermost import MattermostAdapterError

    path = config or _default_mattermost_config()
    try:
        _run(_mattermost_check(path))
    except (MattermostAdapterError, OSError, ValueError) as exc:
        console.print(f"[red]Mattermost adapter check failed:[/red] {escape(str(exc))}")
        raise typer.Exit(1) from None
    console.print("[green]Mattermost adapter configuration is valid.[/green]")


@mattermost_app.command("run")
def mattermost_run(
    config: Path = typer.Option(
        None,
        "--config",
        help="External adapter TOML (default: ~/.safeyolo/coord-mattermost.toml).",
    ),
    once: bool = typer.Option(False, "--once", help="Run one bounded sync cycle and exit."),
) -> None:
    """Run the foreground Mattermost adapter (use a host supervisor in production)."""

    from ..coord.mattermost import MattermostAdapterError

    path = config or _default_mattermost_config()
    try:
        _run(_mattermost_run(path, once=once))
    except KeyboardInterrupt:
        return
    except (MattermostAdapterError, OSError, ValueError) as exc:
        console.print(f"[red]Mattermost adapter stopped:[/red] {escape(str(exc))}")
        raise typer.Exit(1) from None


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


def _explain_coord_failure(exc: Exception) -> str:
    """Turn a coord runtime failure into something an operator can act on.

    These reach the chat loop as bare exceptions and rich renders a full
    traceback, which buries the one line that matters. NatsUnavailable in
    particular often carries an empty message, so the exception text alone
    tells the operator nothing.
    """
    if isinstance(exc, CoordDataError):
        return (f"coord storage problem: {exc}\n"
                "The room is registered but its message stream is missing or "
                "corrupt. This is data loss, not a transient fault — do not "
                "retry blindly; check `safeyolo coord doctor` and the "
                "nats-server logs.")
    detail = str(exc).strip()
    if not detail or detail.endswith(":"):
        detail = "no detail reported (often a timeout misreported as a fault)"
    return (f"coord runtime unreachable: {detail}\n"
            "The NATS runtime backing coord is not answering. Check it is up "
            "(`safeyolo status`), then reattach.")


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
    intent = m.get("attention_intent")
    intent_label = ""
    if isinstance(intent, dict) and intent.get("mode") in {"none", "room", "targeted"}:
        intent_label = f" attention={intent['mode']}"
    console.print(
        f"[{style}]{escape(_visible_controls(who))}[/] "
        f"[dim]{ts} seq={m['sequence']}{intent_label}[/]"
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

brief_app = typer.Typer(
    name="brief",
    help="Trusted versioned operator brief commands.",
    no_args_is_help=True,
)
coord_app.add_typer(brief_app, name="brief")

inventory_app = typer.Typer(
    name="inventory",
    help="Room-visible capability and provider-resource advertisements.",
    no_args_is_help=True,
)
coord_app.add_typer(inventory_app, name="inventory")


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
        api.grant(
            name,
            "agent",
            agent_id,
            operation_id=new_operation_id(),
        )
        granted.append(member_name)

    if with_operator:
        api.grant(
            name,
            "operator",
            "operator",
            operation_id=new_operation_id(),
        )

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


@brief_app.command("show")
def brief_show(
    room: str = typer.Argument(..., help="Room name"),
    revision: int | None = typer.Option(
        None,
        "--revision",
        "-r",
        min=1,
        help="Show one immutable revision instead of current state.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit the canonical brief object as JSON.",
    ),
) -> None:
    """Show the current trusted brief or one immutable prior revision."""
    api.bootstrap()
    try:
        current = api.show_brief(room, revision=revision)
    except api.NotFoundError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(1)
    if json_output:
        console.print_json(json.dumps(current, ensure_ascii=False))
        return
    if current["revision"] == 0:
        console.print(f"[dim]room {room!r} has no operator brief[/dim]")
        return
    console.print(
        f"[bold]operator brief[/bold]  room={room}  "
        f"revision={current['revision']}  hash={current['content_hash']}"
    )
    _render_body(current["markdown"])


@brief_app.command("history")
def brief_history(
    room: str = typer.Argument(..., help="Room name"),
    since_revision: int = typer.Option(
        0,
        "--since",
        min=0,
        help="Return revisions greater than this value.",
    ),
    limit: int = typer.Option(50, "--limit", min=1, max=200),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """List immutable brief revision metadata without replaying Markdown."""
    api.bootstrap()
    try:
        page = api.list_brief_history(
            room,
            since_revision=since_revision,
            limit=limit,
        )
    except api.NotFoundError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(1)
    if json_output:
        console.print_json(json.dumps(page, ensure_ascii=False))
        return
    table = Table("revision", "content_hash", "actor", "operation_id", "created_at")
    for item in page["revisions"]:
        table.add_row(
            str(item["revision"]),
            item["content_hash"],
            item["actor_id"],
            item["operation_id"],
            _fmt_ts(item["created_at"]),
        )
    console.print(table)
    if page["has_more"]:
        console.print(
            f"[dim]more revisions available after {page['next_revision']}[/dim]"
        )


@brief_app.command("set")
def brief_set(
    room: str = typer.Argument(..., help="Room name"),
    text: str | None = typer.Argument(
        None,
        help="Markdown text (quote multi-word text); mutually exclusive with --file.",
    ),
    file: Path | None = typer.Option(
        None,
        "--file",
        "-f",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Read Markdown from this file.",
    ),
    expected_revision: int = typer.Option(
        ...,
        "--expected-revision",
        min=0,
        help="Required optimistic-concurrency revision (0 for the first brief).",
    ),
    operation_id: str | None = typer.Option(
        None,
        "--operation-id",
        help="Retry handle; generated when omitted.",
    ),
) -> None:
    """Set trusted operator intent with explicit optimistic concurrency."""
    if (text is None) == (file is None):
        console.print("[red]provide exactly one of TEXT or --file[/red]")
        raise typer.Exit(1)
    if file is not None:
        try:
            markdown = file.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            console.print(f"[red]could not read brief file: {type(exc).__name__}[/red]")
            raise typer.Exit(1)
    else:
        assert text is not None
        markdown = text
    api.bootstrap()
    operation_id = operation_id or new_operation_id()
    try:
        result = _run(
            api.set_brief(
                room,
                markdown,
                expected_revision=expected_revision,
                operation_id=operation_id,
            )
        )
    except api.RevisionConflictError as exc:
        console.print(f"[red]{exc}[/]  operation_id={operation_id}")
        raise typer.Exit(1)
    except api.OperationConflictError as exc:
        console.print(f"[red]{exc}[/]  operation_id={operation_id}")
        raise typer.Exit(1)
    except (api.NotFoundError, ValueError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(1)
    console.print(
        f"[green]operator brief updated[/]  room={room}  "
        f"revision={result['revision']}  hash={result['content_hash']}  "
        f"operation_id={operation_id}"
    )


@coord_app.command("state")
def room_state(
    room: str = typer.Argument(..., help="Room name"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Show current authoritative room identity/capability/resource state."""
    api.bootstrap()
    try:
        state = _run(api.get_room_state(room))
    except (api.NotFoundError, ValueError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(1)
    if json_output:
        console.print_json(json.dumps(state, ensure_ascii=False))
        return

    console.print(
        f"[bold]room state[/bold]  room={room}  "
        f"brief_revision={state['brief']['revision']}"
    )
    members = Table(
        "name",
        "agent_id",
        "configured",
        "room permissions",
        "verified",
        "declared",
    )
    for member in state["members"]:
        verified = "\n".join(
            f"{item['capability']} [{item['availability']}]"
            for item in member["verified"]
        )
        declared = "\n".join(
            item["capability"] for item in member["declared"]
        )
        members.add_row(
            member["display_name"] or "-",
            member["agent_id"],
            "yes" if member["configured"] else "no",
            ",".join(member["room_permissions"]),
            verified or "-",
            declared or "-",
        )
    console.print(members)
    if state["resource_leases"]:
        leases = Table("provider", "resource", "state", "holder", "freshness")
        for lease in state["resource_leases"]:
            leases.add_row(
                lease["provider"],
                lease["resource"],
                lease["state"],
                lease["holder_display_name"] or lease["holder_agent_id"] or "-",
                lease["freshness"],
            )
        console.print(leases)


def _inventory_capability_change(
    room: str,
    agent_name: str,
    capability: str,
    *,
    advertised: bool,
    operation_id: str | None,
) -> None:
    api.bootstrap()
    agent_id = _resolve_agent_id(agent_name)
    operation_id = operation_id or new_operation_id()
    try:
        result = api.advertise_capability(
            room,
            agent_id,
            capability,
            advertised=advertised,
            operation_id=operation_id,
        )
    except (api.NotFoundError, api.OperationConflictError, ValueError) as exc:
        console.print(f"[red]{exc}[/]  operation_id={operation_id}")
        raise typer.Exit(1)
    transition = "advertised" if advertised else "unadvertised"
    console.print(
        f"[green]{transition}[/]  room={room}  agent={agent_name}  "
        f"capability={capability}  changed={result['changed']}  "
        f"operation_id={operation_id}"
    )


@inventory_app.command("advertise-capability")
def inventory_advertise_capability(
    room: str,
    agent_name: str,
    capability: str,
    operation_id: str | None = typer.Option(None, "--operation-id"),
) -> None:
    """Advertise one current SafeYolo grant as a room-visible label."""
    _inventory_capability_change(
        room,
        agent_name,
        capability,
        advertised=True,
        operation_id=operation_id,
    )


@inventory_app.command("unadvertise-capability")
def inventory_unadvertise_capability(
    room: str,
    agent_name: str,
    capability: str,
    operation_id: str | None = typer.Option(None, "--operation-id"),
) -> None:
    """Remove one room-visible capability label."""
    _inventory_capability_change(
        room,
        agent_name,
        capability,
        advertised=False,
        operation_id=operation_id,
    )


def _inventory_resource_change(
    room: str,
    provider: str,
    resource: str,
    *,
    advertised: bool,
    operation_id: str | None,
) -> None:
    api.bootstrap()
    operation_id = operation_id or new_operation_id()
    try:
        result = api.advertise_resource(
            room,
            provider,
            resource,
            advertised=advertised,
            operation_id=operation_id,
        )
    except (api.NotFoundError, api.OperationConflictError, ValueError) as exc:
        console.print(f"[red]{exc}[/]  operation_id={operation_id}")
        raise typer.Exit(1)
    transition = "advertised" if advertised else "unadvertised"
    console.print(
        f"[green]{transition}[/]  room={room}  provider={provider}  "
        f"resource={resource}  changed={result['changed']}  "
        f"operation_id={operation_id}"
    )


@inventory_app.command("advertise-resource")
def inventory_advertise_resource(
    room: str,
    provider: str,
    resource: str,
    operation_id: str | None = typer.Option(None, "--operation-id"),
) -> None:
    """Advertise one provider-owned resource label to the room."""
    _inventory_resource_change(
        room,
        provider,
        resource,
        advertised=True,
        operation_id=operation_id,
    )


@inventory_app.command("unadvertise-resource")
def inventory_unadvertise_resource(
    room: str,
    provider: str,
    resource: str,
    operation_id: str | None = typer.Option(None, "--operation-id"),
) -> None:
    """Remove one room-visible provider resource label."""
    _inventory_resource_change(
        room,
        provider,
        resource,
        advertised=False,
        operation_id=operation_id,
    )


@coord_app.command()
def grant(
    room: str = typer.Argument(..., help="Room name"),
    agent_name: str = typer.Argument(..., help="Registered agent name"),
    permissions: str = typer.Option(
        "send,receive", "--perm", help="Comma-separated permissions"
    ),
    operation_id: str | None = typer.Option(
        None,
        "--operation-id",
        help="Retry handle; generated when omitted.",
    ),
) -> None:
    """Grant a registered agent permissions on a room."""
    api.bootstrap()
    agent_id = _resolve_agent_id(agent_name)
    perms = [p.strip() for p in permissions.split(",") if p.strip()]
    operation_id = operation_id or new_operation_id()
    try:
        api.grant(
            room,
            "agent",
            agent_id,
            permissions=perms,
            operation_id=operation_id,
        )
    except api.OperationConflictError as exc:
        console.print(f"[red]{exc}[/]  operation_id={operation_id}")
        raise typer.Exit(1)
    console.print(
        f"[green]granted[/]  {agent_name} on {room}: {perms}  "
        f"operation_id={operation_id}"
    )


@coord_app.command()
def revoke(
    room: str = typer.Argument(..., help="Room name"),
    agent_name: str = typer.Argument(..., help="Registered agent name"),
    operation_id: str | None = typer.Option(
        None,
        "--operation-id",
        help="Retry handle; generated when omitted.",
    ),
) -> None:
    """Revoke a registered agent's active grant on a room.

    Room semantic per #371: agent loses access while revoked; retained
    history is not erased. A subsequent `grant` re-exposes whatever is
    still retained.
    """
    api.bootstrap()
    agent_id = _resolve_agent_id(agent_name)
    operation_id = operation_id or new_operation_id()
    try:
        changed = api.revoke_grant(
            room,
            "agent",
            agent_id,
            operation_id=operation_id,
        )
    except api.OperationConflictError as exc:
        console.print(f"[red]{exc}[/]  operation_id={operation_id}")
        raise typer.Exit(1)
    except api.NotFoundError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)
    if changed:
        console.print(
            f"[green]revoked[/]  {agent_name} on {room}  "
            f"operation_id={operation_id}"
        )
    else:
        console.print(
            f"[yellow]no active grant to revoke[/]  {agent_name} on {room}  "
            f"operation_id={operation_id}"
        )


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
        except Exception:  # noqa: BLE001, S110
            pass  # best-effort teardown
        self._loop.close()


def _active_factory_coordinator(room: str) -> str | None:
    """Resolve one room's applied factory coordinator without parsing prose."""
    root = factories_dir()
    if not root.is_dir():
        return None
    coordinators: set[str] = set()
    for candidate in sorted(root.iterdir(), key=lambda item: item.name):
        if not candidate.is_dir() or not (candidate / "active").is_file():
            continue
        _, _, payload = load_active_snapshot(candidate.name)
        if payload["room"] != room:
            continue
        destination = payload["operator_input"]["to"]
        coordinators.add(payload["roles"][destination]["agent"])
    if len(coordinators) > 1:
        raise FactoryContractError(
            f"room {room!r} has multiple active factory coordinators; use --to explicitly"
        )
    return next(iter(coordinators), None)


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
    to: str | None = typer.Option(
        None,
        "--to",
        metavar="AGENT",
        help="Notify only this receive-authorized room member when sending.",
    ),
) -> None:
    """Attach to a room as operator. Interactive by default; --observe for read-only tail.

    Interactive mode displays incoming messages while the operator types.
    The current draft remains at the prompt. Use --observe only when a
    read-only room tail is useful. Interactive mode requires a terminal on
    both stdin and stdout; use a terminal session for operator sends.
    """
    if not observe:
        missing = []
        if not sys.stdin.isatty():
            missing.append("stdin")
        if not sys.stdout.isatty():
            missing.append("stdout")
        if missing:
            typer.echo(
                "interactive coord chat requires a terminal on "
                f"{' and '.join(missing)}; piped input is not accepted. "
                "Use --observe for a non-interactive room tail.",
                err=True,
            )
            raise typer.Exit(2)
    api.bootstrap()
    if observe and to is not None:
        console.print("[red]--to requires interactive mode[/]")
        raise typer.Exit(1)
    try:
        api.join_room(room, "operator", "operator")
    except (api.NotFoundError, api.GrantError) as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)

    target = to
    if not observe and target is None:
        try:
            target = _active_factory_coordinator(room)
        except FactoryContractError as e:
            console.print(f"[red]{e}[/]")
            raise typer.Exit(1) from None

    console.print(f"[bold]attached to room[/] {room}  (mode={'observe' if observe else 'interactive'})")
    if target is not None:
        source = "--to" if to is not None else "active factory coordinator"
        console.print(f"[dim]operator messages target {target} ({source})[/]")
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
            _interactive_loop(runtime, room, cursor, target=target)
    except (NatsUnavailable, CoordDataError) as e:
        console.print(f"[red]{_explain_coord_failure(e)}[/]")
        raise typer.Exit(1) from None
    finally:
        runtime.close()


@coord_app.command("dispatch-trigger")
def dispatch_trigger(
    room: str = typer.Argument(..., help="Coord room that contains Relay"),
    for_date: str = typer.Option(
        ...,
        "--date",
        help="Explicit UTC production date (YYYY-MM-DD); the command never reads the clock.",
    ),
    weekly_on: str = typer.Option(
        "monday",
        "--weekly-on",
        help="UTC weekday that also requests the preceding seven-day snapshot.",
    ),
    publication_mode: str = typer.Option(
        "manual",
        "--publication-mode",
        help="manual (default) or operator-enabled automatic publication.",
    ),
) -> None:
    """Durably post one idempotent operator-authored Dispatch TASK to Relay."""
    from ..coord import dispatch_schedule

    try:
        run_date = date.fromisoformat(for_date)
        if run_date.isoformat() != for_date:
            raise ValueError
    except ValueError:
        console.print("[red]--date must be an exact YYYY-MM-DD date[/]")
        raise typer.Exit(2) from None
    api.bootstrap()
    try:
        result = _run(
            dispatch_schedule.deliver_task(
                room,
                run_date,
                weekly_on=weekly_on.lower(),
                publication_mode=publication_mode.lower(),
            )
        )
    except NatsPublishOutcomeUnknown as exc:
        console.print(
            "[yellow]Dispatch publish outcome is unknown; rerun the exact same "
            f"command to reconcile safely:[/] {escape(str(exc))}"
        )
        raise typer.Exit(1) from None
    except (
        api.GrantError,
        api.NotFoundError,
        dispatch_schedule.DispatchScheduleError,
        CoordDataError,
        NatsUnavailable,
        ValueError,
    ) as exc:
        console.print(f"[red]Dispatch task not delivered:[/] {escape(str(exc))}")
        raise typer.Exit(1) from None
    console.print(
        f"[green]{result.status}[/]  task_key={result.task_key}  "
        f"sequence={result.sequence}"
    )


def _observe_loop(runtime: _ChatRuntime, room: str, cursor: int) -> None:
    console.print("[dim]--- observing (Ctrl-C to detach) ---[/]")
    # Long-poll rather than sleep-poll. read_room opens and deletes its own
    # ephemeral pull consumer per call, so a 0.5s poll loop was ~2 consumer
    # create/delete cycles a second for as long as the observer ran.
    # wait_for_message holds one consumer for the whole call and blocks
    # server-side, so an idle room costs one consumer per wake window
    # instead of 120 a minute.
    #
    # exclude_self=False because "self" here is the operator: an observer
    # that filtered operator messages would miss exactly the traffic the
    # operator is watching for.
    #
    # A blip should not end the session, but a runtime that stays down must
    # not scroll the same error forever.
    consecutive_failures = 0
    try:
        while True:
            try:
                woke = runtime.run(api.wait_for_message(
                    room, "operator", "operator",
                    since_sequence=cursor,
                    timeout_seconds=_OBSERVE_WAIT_SECONDS,
                    # Only the edge is needed: the wake page is discarded and
                    # a canonical read_room follows, so asking for a full page
                    # here would fetch up to 200 messages and then fetch the
                    # same history again.
                    limit=1,
                    exclude_self=False,
                ))
            except CoordDataError as e:
                console.print(f"[red]{_explain_coord_failure(e)}[/]")
                raise typer.Exit(1) from None
            except NatsUnavailable as e:
                consecutive_failures += 1
                if consecutive_failures == 1:
                    console.print(f"[yellow]{_explain_coord_failure(e)}[/]")
                    console.print("[dim]retrying; Ctrl-C to detach[/]")
                elif consecutive_failures >= _OBSERVE_MAX_FAILURES:
                    console.print(
                        f"[red]still unreachable after "
                        f"{consecutive_failures} attempts; detaching[/]")
                    raise typer.Exit(1) from None
                time.sleep(1.0)
                continue
            if consecutive_failures:
                console.print("[green]coord runtime back; resuming[/]")
                consecutive_failures = 0
            if not woke["messages"]:
                continue                      # wake window expired, re-arm
            # Wake is only an edge. Catch up canonically from the cursor we
            # already hold -- wait's next_cursor can sit past messages this
            # observer has not rendered yet.
            while True:
                page = runtime.run(api.read_room(
                    room, "operator", "operator",
                    since_sequence=cursor, limit=api.READ_PAGE_MAX))
                for m in page["messages"]:
                    _render_message(m)
                cursor = page["next_cursor"]
                if not page["has_more"]:
                    break
    except KeyboardInterrupt:
        console.print("\n[dim]detached[/]")


# Give up observing after this many consecutive unreachable polls.
_OBSERVE_MAX_FAILURES = 10

# How long each observer wake window blocks server-side. Long enough that
# an idle room is cheap, short enough that Ctrl-C stays responsive.
_OBSERVE_WAIT_SECONDS = 30.0

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


async def _prompt_line(
    session: PromptSession,
    receiver: asyncio.Task,
    prompt: str,
) -> str:
    """Read one editable line, but stop promptly if the receiver fails."""
    async def stop_if_receiver_finishes() -> None:
        try:
            # Cancelling this short-lived monitor must not cancel the receiver.
            await asyncio.shield(receiver)
        except asyncio.CancelledError:
            return
        except BaseException as error:
            receiver_error = error
        else:
            receiver_error = EOFError()

        while not session.app.is_running:
            await asyncio.sleep(0)
        session.app.exit(exception=receiver_error)

    monitor = asyncio.create_task(stop_if_receiver_finishes())
    try:
        return await session.prompt_async(prompt)
    finally:
        monitor.cancel()
        await asyncio.gather(monitor, return_exceptions=True)


async def _confirm_send(
    session: PromptSession,
    receiver: asyncio.Task,
    body: str,
) -> bool:
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
        answer = await _prompt_line(session, receiver, "send? [Y/n] ")
        return answer.strip().lower() in ("", "y", "yes")
    except EOFError:
        return False


async def _receive_messages(
    room: str,
    cursor: int,
    render_ready: asyncio.Event,
) -> None:
    """Receive and render room messages while the operator prompt is open."""
    consecutive_failures = 0
    while True:
        try:
            woke = await api.wait_for_message(
                room,
                "operator",
                "operator",
                since_sequence=cursor,
                timeout_seconds=_OBSERVE_WAIT_SECONDS,
                limit=1,
                exclude_self=False,
            )
            if not woke["messages"]:
                if consecutive_failures:
                    console.print("[green]coord runtime back; receiving messages[/]")
                    consecutive_failures = 0
                continue

            messages = []
            read_cursor = cursor
            while True:
                page = await api.read_room(
                    room,
                    "operator",
                    "operator",
                    since_sequence=read_cursor,
                    limit=api.READ_PAGE_MAX,
                )
                messages.extend(page["messages"])
                read_cursor = page["next_cursor"]
                if not page["has_more"]:
                    break
        except NatsUnavailable as e:
            consecutive_failures += 1
            if consecutive_failures == 1:
                console.print(f"[yellow]{_explain_coord_failure(e)}[/]")
                console.print("[dim]retrying; the prompt remains available[/]")
            await asyncio.sleep(1.0)
            continue

        if consecutive_failures:
            console.print("[green]coord runtime back; receiving messages[/]")
            consecutive_failures = 0

        # An external editor owns the terminal while it runs. Keep the NATS
        # loop alive, but wait to print fetched messages until the editor exits.
        await render_ready.wait()
        for message in messages:
            _render_message(message)
        cursor = read_cursor


async def _interactive_session(
    room: str,
    cursor: int,
    *,
    target: str | None = None,
) -> None:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.patch_stdout import patch_stdout

    session = PromptSession()
    render_ready = asyncio.Event()
    render_ready.set()
    receiver = asyncio.create_task(
        _receive_messages(room, cursor, render_ready),
        name="coord-chat-receiver",
    )
    try:
        # Rich writes ANSI styling. raw=True preserves it while prompt_toolkit
        # moves each incoming write above the editable prompt and redraws the
        # operator's current draft.
        with patch_stdout(raw=True):
            while True:
                try:
                    line = await _prompt_line(session, receiver, "op> ")
                except EOFError:
                    break
                command = line.strip()
                if command == ":q":
                    break
                body: str | None = None
                if command in _PASTE_CMDS or command in _EDIT_CMDS:
                    # Read outside the terminal input path so control bytes in
                    # a pasted or edited message remain intact.
                    if command in _PASTE_CMDS:
                        body, err = await asyncio.to_thread(_read_clipboard)
                    else:
                        render_ready.clear()
                        try:
                            body, err = await asyncio.to_thread(_read_editor)
                        finally:
                            render_ready.set()
                    if body is None:
                        console.print(f"[red]{err}[/]")
                    else:
                        body = body.rstrip("\n")
                        if not body.strip():
                            console.print("[dim]empty; nothing sent[/]")
                            body = None
                        elif not await _confirm_send(session, receiver, body):
                            console.print("[dim]cancelled[/]")
                            body = None
                elif command:
                    body = line
                if body is None:
                    continue
                try:
                    result = await api.send(
                        room,
                        "operator",
                        None,
                        body,
                        notify=[target] if target is not None else "room",
                    )
                    intent = result.get("attention_intent")
                    mode = intent.get("mode") if isinstance(intent, dict) else None
                    intent_detail = (
                        f"attention={mode}{' target=' + target if mode == 'targeted' and target else ''}"
                        if mode in {"none", "room", "targeted"}
                        else "attention intent unavailable"
                    )
                    if result["attention_status"] == "pending":
                        console.print(f"[yellow]message accepted; {intent_detail}; delivery is pending[/]")
                    elif result["attention_status"] == "lost":
                        console.print(
                            f"[red]message accepted; {intent_detail}, but retention "
                            "removed it before attention materialization; its attention "
                            "is lost[/]"
                        )
                    else:
                        console.print(f"[dim]message accepted; {intent_detail}[/]")
                except ValueError as e:
                    console.print(f"[red]{e}[/]")
                except api.GrantError as e:
                    console.print(f"[red]{e}[/]")
                    break
                except NatsPublishOutcomeUnknown as e:
                    console.print(f"[yellow]{_explain_coord_failure(e)}[/]")
                    console.print(
                        "[yellow]message acceptance is UNKNOWN: JetStream may "
                        "have accepted it. Stage 1 has no caller-visible send "
                        "idempotency; inspect retained room history before "
                        "deciding whether to send another message.[/]"
                    )
                except (NatsUnavailable, CoordDataError) as e:
                    console.print(f"[red]{_explain_coord_failure(e)}[/]")
                    console.print("[red]message was not accepted; it was not sent[/]")
    finally:
        receiver.cancel()
        await asyncio.gather(receiver, return_exceptions=True)


def _interactive_loop(
    runtime: _ChatRuntime,
    room: str,
    cursor: int,
    *,
    target: str | None = None,
) -> None:
    console.print(
        "[dim]--- interactive (live messages; :paste/:p clipboard, "
        ":edit/:e in $EDITOR, :q to quit) ---[/]"
    )
    try:
        runtime.run(_interactive_session(room, cursor, target=target))
    except KeyboardInterrupt:
        pass
    console.print("\n[dim]detached[/]")


@coord_app.command("mcp-config")
def mcp_config() -> None:
    """Print custom-harness instructions for wiring coord MCP manually.

    The MCP server is a standalone one-file adapter shipped at
    `contrib/safeyolo-coord-mcp.py`. It only depends on `mcp` and `httpx` and
    calls the coord Agent API via `http://_safeyolo.proxy.internal`, so the
    agent sandbox does NOT need SafeYolo (and mitmproxy) installed.

    Identity is transport-derived: whichever sandbox the MCP server runs in
    is attributed to that agent by the SafeYolo proxy. Same config works for
    every agent.
    """
    console.print("""Bundled [bold]@claude[/] and [bold]@codex[/] host setup registers this server automatically.
The manual steps below are for custom harnesses.

[bold]1. Stage the standalone MCP server inside the agent sandbox[/]

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
