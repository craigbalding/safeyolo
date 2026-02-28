"""Token management commands for agent relay access."""

import json
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from ..config import get_admin_token, get_data_dir

console = Console()

token_app = typer.Typer(
    name="token",
    help="Manage readonly relay tokens for agent self-service.",
    no_args_is_help=True,
)


def _get_tokens_path() -> Path:
    """Get path to readonly tokens registry."""
    return get_data_dir() / "readonly_tokens.json"


def _get_active_token_path() -> Path:
    """Get path to active token file (mounted into agent containers)."""
    return get_data_dir() / "readonly_token"


def _load_tokens() -> list[dict]:
    """Load token registry from disk."""
    path = _get_tokens_path()
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def _save_tokens(tokens: list[dict]) -> None:
    """Save token registry to disk."""
    path = _get_tokens_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(tokens, indent=2))


def _parse_ttl(ttl_str: str) -> int:
    """Parse TTL string like '24h', '7d', '3600' into seconds."""
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
    ttl: str = typer.Option("24h", "--ttl", help="Token lifetime (e.g., 24h, 7d, 3600)"),
) -> None:
    """Create a new readonly relay token.

    The token is saved to the registry and written to the active token file
    that agent containers mount. Agents use it via $SAFEYOLO_READONLY_TOKEN.

    Examples:

        safeyolo token create              # 24h token (default)
        safeyolo token create --ttl 7d     # 7 day token
        safeyolo token create --ttl 1h     # 1 hour token
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
        console.print("Use: 24h, 7d, 3600, etc.")
        raise typer.Exit(1)

    from safeyolo.commands._token_ops import create_readonly_token

    token_str = create_readonly_token(admin_token, ttl_seconds)

    # Extract JTI from token for registry
    import base64

    payload_b64 = token_str.split(".")[0]
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    jti = payload["jti"]
    exp = payload["exp"]

    # Save to registry
    tokens = _load_tokens()
    tokens.append({
        "jti": jti,
        "created": datetime.now(UTC).isoformat(),
        "expires": datetime.fromtimestamp(exp, tz=UTC).isoformat(),
        "ttl": ttl,
        "status": "active",
    })
    _save_tokens(tokens)

    # Write active token file for agent containers
    active_path = _get_active_token_path()
    active_path.parent.mkdir(parents=True, exist_ok=True)
    active_path.write_text(token_str)

    console.print(f"[green]Token created[/green] (JTI: {jti})")
    console.print(f"  Expires: {datetime.fromtimestamp(exp, tz=UTC).strftime('%Y-%m-%d %H:%M UTC')}")
    console.print(f"  Written to: {active_path}")
    console.print()
    console.print(f"[dim]Token: {token_str}[/dim]")
    console.print()
    console.print("Agents will pick up the token on next container start.")


@token_app.command(name="list")
def list_tokens() -> None:
    """List all readonly relay tokens.

    Shows token ID, creation time, expiry, and status.

    Examples:

        safeyolo token list
    """
    tokens = _load_tokens()
    if not tokens:
        console.print("[dim]No tokens found. Create one with:[/dim] safeyolo token create")
        return

    table = Table(title="Readonly Relay Tokens")
    table.add_column("JTI", style="dim")
    table.add_column("Created")
    table.add_column("Expires")
    table.add_column("TTL")
    table.add_column("Status")

    now = datetime.now(UTC)
    for token_entry in tokens:
        status = token_entry.get("status", "unknown")
        expires_str = token_entry.get("expires", "")

        # Check if expired
        if status == "active" and expires_str:
            try:
                exp_dt = datetime.fromisoformat(expires_str)
                if now > exp_dt:
                    status = "expired"
            except ValueError:
                pass

        style = {
            "active": "green",
            "revoked": "red",
            "expired": "yellow",
        }.get(status, "dim")

        table.add_row(
            token_entry.get("jti", "?"),
            token_entry.get("created", "")[:19],
            expires_str[:19],
            token_entry.get("ttl", "?"),
            f"[{style}]{status}[/{style}]",
        )

    console.print(table)


@token_app.command()
def revoke(
    jti: str = typer.Argument(None, help="Token JTI to revoke (or --all)"),
    all_tokens: bool = typer.Option(False, "--all", help="Revoke all tokens"),
) -> None:
    """Revoke a readonly relay token.

    Revoked tokens are rejected by the relay addon. Use --all to revoke
    all tokens at once.

    Examples:

        safeyolo token revoke abc123        # Revoke specific token
        safeyolo token revoke --all         # Revoke all tokens
    """
    if not jti and not all_tokens:
        console.print("[red]Error:[/red] Specify a JTI or use --all")
        raise typer.Exit(1)

    tokens = _load_tokens()
    if not tokens:
        console.print("[dim]No tokens to revoke.[/dim]")
        return

    revoked_count = 0
    for token_entry in tokens:
        if all_tokens or token_entry.get("jti") == jti:
            if token_entry.get("status") != "revoked":
                token_entry["status"] = "revoked"
                revoked_count += 1

    if revoked_count == 0:
        if jti:
            console.print(f"[yellow]Token {jti} not found or already revoked.[/yellow]")
        else:
            console.print("[dim]No active tokens to revoke.[/dim]")
        return

    _save_tokens(tokens)

    # Clear the active token file
    active_path = _get_active_token_path()
    if active_path.exists():
        active_path.unlink()

    console.print(f"[green]Revoked {revoked_count} token(s).[/green]")
    console.print("[dim]Agents will lose relay access on next request.[/dim]")
