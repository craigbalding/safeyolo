"""Token management commands for agent relay access.

Single-token model: one token at a time, stored as a plain file.
Creating a new token replaces the old one. Token is deleted on start/stop.
"""

import base64
import json
from datetime import UTC, datetime

import typer
from rich.console import Console

from ..config import get_admin_token, get_data_dir

console = Console()

token_app = typer.Typer(
    name="token",
    help="Manage readonly relay token for agent self-service.",
    no_args_is_help=True,
)

DEFAULT_TTL = "1h"


def _get_active_token_path():
    """Get path to active token file (mounted into agent containers)."""
    return get_data_dir() / "readonly_token"


def _parse_ttl(ttl_str: str) -> int:
    """Parse TTL string like '1h', '7d', '3600' into seconds."""
    ttl_str = ttl_str.strip().lower()
    if ttl_str.endswith("d"):
        return int(ttl_str[:-1]) * 86400
    if ttl_str.endswith("h"):
        return int(ttl_str[:-1]) * 3600
    if ttl_str.endswith("m"):
        return int(ttl_str[:-1]) * 60
    return int(ttl_str)


@token_app.command()
def create(
    ttl: str = typer.Option(DEFAULT_TTL, "--ttl", help="Token lifetime (e.g., 1h, 4h, 30m)"),
) -> None:
    """Create a readonly relay token.

    Replaces any existing token. The token is written to a file that agent
    containers mount. Agents use it via $SAFEYOLO_READONLY_TOKEN.

    Token survives proxy restarts but expires after the TTL (default: 1h).

    Examples:

        safeyolo token create              # 1h token (default)
        safeyolo token create --ttl 4h     # 4 hour token
        safeyolo token create --ttl 30m    # 30 minute token
    """
    admin_token = get_admin_token()
    if not admin_token:
        console.print("[red]Error:[/red] No admin token found.")
        console.print("Start SafeYolo first: [bold]safeyolo start[/bold]")
        raise typer.Exit(1)

    try:
        ttl_seconds = _parse_ttl(ttl)
    except ValueError:
        console.print(f"[red]Error:[/red] Invalid TTL format: {ttl}")
        console.print("Use: 1h, 4h, 30m, 3600, etc.")
        raise typer.Exit(1)

    from safeyolo.commands._token_ops import create_readonly_token

    token_str = create_readonly_token(admin_token, ttl_seconds)

    # Extract expiry for display
    payload_b64 = token_str.split(".")[0]
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    exp = payload["exp"]

    # Write active token file
    active_path = _get_active_token_path()
    active_path.parent.mkdir(parents=True, exist_ok=True)
    active_path.write_text(token_str)

    expires_str = datetime.fromtimestamp(exp, tz=UTC).strftime("%Y-%m-%d %H:%M UTC")
    console.print(f"[green]Token created[/green] (expires: {expires_str})")
    console.print(f"  Written to: {active_path}")
    console.print()
    console.print(f"[dim]Token: {token_str}[/dim]")
    console.print()
    console.print("[dim]Token survives restarts. Expires after TTL or use: safeyolo token revoke[/dim]")


@token_app.command(name="show")
def show() -> None:
    """Show the current relay token status.

    Examples:

        safeyolo token show
    """
    admin_token = get_admin_token()
    active_path = _get_active_token_path()

    if not active_path.exists():
        console.print("[dim]No active token.[/dim] Create one with: safeyolo token create")
        return

    token_str = active_path.read_text().strip()
    if not token_str:
        console.print("[dim]No active token.[/dim] Create one with: safeyolo token create")
        return

    # Decode to show expiry
    try:
        payload_b64 = token_str.split(".")[0]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        exp = payload.get("exp", 0)
        exp_dt = datetime.fromtimestamp(exp, tz=UTC)
        now = datetime.now(UTC)

        if now > exp_dt:
            console.print("[yellow]Token expired[/yellow]")
            console.print(f"  Expired: {exp_dt.strftime('%Y-%m-%d %H:%M UTC')}")
        else:
            remaining = exp_dt - now
            minutes = int(remaining.total_seconds() // 60)
            console.print("[green]Token active[/green]")
            console.print(f"  Expires: {exp_dt.strftime('%Y-%m-%d %H:%M UTC')} ({minutes}m remaining)")

        # Validate signature if admin token available
        if admin_token:
            from safeyolo.commands._token_ops import validate_readonly_token

            valid = validate_readonly_token(token_str, admin_token)
            if valid is None:
                console.print("  Signature: [red]invalid[/red]")
            else:
                console.print("  Signature: [green]valid[/green]")

    except (ValueError, json.JSONDecodeError, IndexError):
        console.print("[yellow]Token file exists but is malformed[/yellow]")

    console.print()
    console.print(f"[dim]Token: {token_str}[/dim]")


@token_app.command()
def revoke() -> None:
    """Delete the active relay token.

    The agent loses relay access immediately.

    Examples:

        safeyolo token revoke
    """
    active_path = _get_active_token_path()

    if not active_path.exists():
        console.print("[dim]No active token to revoke.[/dim]")
        return

    active_path.unlink()
    console.print("[green]Token revoked.[/green]")
