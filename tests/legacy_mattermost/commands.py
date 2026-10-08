"""Test-only CLI for the retained Python fixtures; not a product entry point."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape

coord_app = typer.Typer()


def _run(awaitable):
    return asyncio.run(awaitable)


mattermost_app = typer.Typer(
    name="mattermost",
    help="Project selected coord rooms to one authenticated Mattermost operator.",
    no_args_is_help=True,
)
coord_app.add_typer(mattermost_app, name="mattermost")

console = Console()


def _default_mattermost_config() -> Path:
    from safeyolo.config import get_config_dir

    return get_config_dir() / "coord-mattermost.toml"


async def _mattermost_check(config_path: Path) -> None:
    from .mattermost import (
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
    from .mattermost import (
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

    from .mattermost import MattermostAdapterError

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

    from .mattermost import MattermostAdapterError

    path = config or _default_mattermost_config()
    try:
        _run(_mattermost_run(path, once=once))
    except KeyboardInterrupt:
        return
    except (MattermostAdapterError, OSError, ValueError) as exc:
        console.print(f"[red]Mattermost adapter stopped:[/red] {escape(str(exc))}")
        raise typer.Exit(1) from None



if __name__ == "__main__":
    coord_app()
