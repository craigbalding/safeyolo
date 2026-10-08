"""Legacy trigger registration used only by retained Python contract tests."""

import asyncio
from datetime import date

import typer
from rich.console import Console
from rich.markup import escape

from safeyolo.coord import api

coord_app = typer.Typer()
console = Console()


@coord_app.callback()
def legacy_coord() -> None:
    """Keep the original grouped command shape for legacy contract tests."""


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
    from safeyolo.coord.nats_client import (
        CoordDataError,
        NatsPublishOutcomeUnknown,
        NatsUnavailable,
    )

    from . import dispatch_schedule

    try:
        run_date = date.fromisoformat(for_date)
        if run_date.isoformat() != for_date:
            raise ValueError
    except ValueError:
        console.print("[red]--date must be an exact YYYY-MM-DD date[/]")
        raise typer.Exit(2) from None
    api.bootstrap()
    try:
        result = asyncio.run(
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
