"""Attach to and scope the shared native traffic console."""

import typer
from rich.console import Console

from ..traffic_session import attach_session, session_exists

console = Console()


def get_api():
    """Load the admin API client only when traffic scope is changed."""
    from ..api import get_api as _get_api

    return _get_api()


def traffic(
    agent: str | None = typer.Option(None, "--agent", help="Trusted agent scope"),
    test_id: str | None = typer.Option(None, "--test", help="Test-case scope"),
    intent: str | None = typer.Option(None, "--intent", help="Test intent scope"),
    role: str | None = typer.Option(None, "--role", help="Test role scope"),
    expect: str | None = typer.Option(None, "--expect", help="Expected-result scope"),
    unattributed: bool = typer.Option(False, "--unattributed", help="Show only unattributed traffic"),
    attach: bool = typer.Option(True, "--attach/--no-attach", help="Attach the native console after updating scope"),
) -> None:
    """Scope and attach the existing shared traffic console."""
    from ..api import APIError

    if agent is not None and unattributed:
        console.print("[red]--agent and --unattributed are mutually exclusive.[/red]")
        raise typer.Exit(2)
    try:
        result = get_api().set_traffic_scope(
            agent=agent,
            unattributed=unattributed,
            test_id=test_id,
            intent=intent,
            role=role,
            expect=expect,
        )
    except APIError as exc:
        console.print(f"[red]Cannot update traffic scope:[/red] {exc}")
        raise typer.Exit(1) from exc

    scope = result.get("effective_filter") or "all traffic"
    console.print(f"[dim]Traffic scope: {scope}[/dim]")
    if not attach:
        return
    if not session_exists():
        console.print("[red]Shared traffic console is not running.[/red]")
        raise typer.Exit(1)
    try:
        return_code = attach_session()
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    if return_code:
        raise typer.Exit(return_code)
