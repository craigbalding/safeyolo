"""Attach to and scope the shared native traffic console."""

import typer
from rich.console import Console

from ..traffic_inspector import inspect_traffic, plain_text
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
    attach: bool = typer.Option(True, "--attach/--no-attach", help="Open the traffic inspector after updating scope"),
) -> None:
    """Scope traffic and open the running backend's inspector."""
    from ..api import APIError

    if agent is not None and unattributed:
        console.print("[red]--agent and --unattributed are mutually exclusive.[/red]")
        raise typer.Exit(2)
    try:
        api = get_api()
        result = api.set_traffic_scope(
            agent=agent,
            unattributed=unattributed,
            test_id=test_id,
            intent=intent,
            role=role,
            expect=expect,
        )
    except APIError as exc:
        console.print(f"Cannot update traffic scope: {plain_text(str(exc))}", markup=False)
        raise typer.Exit(1) from exc

    scope = result.get("effective_filter") or "all traffic"
    console.print(f"Traffic scope: {plain_text(scope)}", markup=False)
    if not attach:
        return
    if api.is_native:
        try:
            inspect_traffic(api)
        except RuntimeError as exc:
            console.print(plain_text(str(exc)), markup=False)
            raise typer.Exit(1) from exc
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
