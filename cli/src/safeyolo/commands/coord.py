"""Coordination-plane CLI for rooms, trusted state, and messaging.

`safeyolo coord ...` is a separate tree from proxy / policy / vault. Agents
themselves are managed by the existing `safeyolo agent add` command; this
module never mints agent IDs.
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from ..agents_store import get_or_mint_agent_id, load_all_agents


def _run(awaitable):
    import asyncio

    return asyncio.run(awaitable)


class _LazyCoordAPI:
    """Load coord persistence and NATS dependencies only for coord commands."""

    def __getattr__(self, name: str):
        from ..coord import api as coord_api

        return getattr(coord_api, name)


api = _LazyCoordAPI()


def __getattr__(name: str):
    """Preserve lazy access to the NATS exception names re-exported here."""
    if name in {
        "CoordDataError",
        "NatsPublishOutcomeUnknown",
        "NatsUnavailable",
    }:
        from ..coord import nats_client

        return getattr(nats_client, name)
    raise AttributeError(name)


def new_operation_id() -> str:
    from ..coord.identity import new_operation_id as _new_operation_id

    return _new_operation_id()

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
    from ..coord.nats_client import (
        CoordDataError,
        NatsPublishOutcomeUnknown,
        NatsUnavailable,
    )

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


@coord_app.command("mcp-config")
def mcp_config() -> None:
    """Print native Coord MCP registration for a custom guest harness."""
    console.print("""Bundled @claude and @codex setup registers native Coord automatically.
For a custom harness, stage the installed product's matching Linux
assets/guest/safeyolo-coord executable inside the sandbox. The executable
uses the guest's HTTP proxy and fresh /app/agent_token on each call.
Do not copy an operator token or host login. Preserve the guest's proxy and
certificate environment when starting the adapter.

Register the guest executable at its actual path. With the bundled staging
path, a minimal .mcp.json registration is:""")
    console.print(json.dumps({"mcpServers": {"safeyolo-coord": {
        "command": "/home/agent/.safeyolo/safeyolo-coord-mcp-launcher",
        "args": [],
    }}}, indent=2))
    console.print("""The launcher executes safeyolo-coord mcp without Python packages.
For another staged path, set command to that executable and args to ["mcp"].
Identity comes from the proxy; room membership is checked on every operation.
SAFEYOLO_COORD_TOKEN_PATH selects another guest token file when explicitly
configured. No caller-selected agent_id is accepted.""")
