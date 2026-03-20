"""Vault management commands for the service gateway credential store.

Vault encryption key is auto-generated and stored at ~/.safeyolo/data/vault.key
with 0600 permissions. No passphrase to remember — same model as admin_token.
"""

import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

console = Console()

vault_app = typer.Typer(
    name="vault",
    help="Manage encrypted credential vault for service gateway.",
    no_args_is_help=True,
)


def _get_data_dir() -> Path:
    from ..config import get_data_dir
    return get_data_dir()


def _get_vault_path() -> Path:
    """Get vault file path."""
    return _get_data_dir() / "vault.yaml.enc"


def _get_key_path() -> Path:
    """Get vault key file path."""
    return _get_data_dir() / "vault.key"


def _get_or_create_key() -> str:
    """Read vault key from file, or generate one if first use."""
    key_path = _get_key_path()

    if key_path.exists():
        return key_path.read_text().strip()

    # First use — generate key
    key = secrets.token_urlsafe(32)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(key)
    key_path.chmod(0o600)
    console.print(f"[bold]Generated vault key:[/bold] {key_path}")
    return key


def _load_vault():
    """Import Vault class and return an unlocked vault instance.

    Returns (Vault, VaultCredential) tuple.
    """
    import sys
    addons_dir = Path(__file__).parent.parent.parent.parent.parent / "addons"
    sys.path.insert(0, str(addons_dir))
    from vault import Vault, VaultCredential

    key = _get_or_create_key()
    vault_path = _get_vault_path()
    vault = Vault(vault_path)
    vault.unlock(key)
    return vault, VaultCredential


@vault_app.command()
def add(
    name: str = typer.Argument(..., help="Credential name (e.g., gmail-oauth2)"),
    credential_type: str = typer.Option(
        "bearer", "--type", "-t",
        help="Credential type: oauth2, api_key, or bearer",
    ),
) -> None:
    """Store a credential in the vault.

    Prompts for the credential value securely (not echoed).

    Examples:

        safeyolo vault add gmail-oauth2 --type oauth2
        safeyolo vault add minifuse-key --type api_key
    """
    if credential_type not in ("oauth2", "api_key", "bearer"):
        console.print(f"[red]Error:[/red] Invalid type '{credential_type}'. Use: oauth2, api_key, bearer")
        raise typer.Exit(1)

    import getpass
    value = getpass.getpass("Credential value: ")
    if not value:
        console.print("[red]Error:[/red] Empty credential value")
        raise typer.Exit(1)

    try:
        vault, VaultCredential = _load_vault()
        cred = VaultCredential(name=name, type=credential_type, value=value)
        vault.store(cred)
        console.print(f"[green]Stored:[/green] {name} (type={credential_type})")
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {type(e).__name__}: {e}")
        raise typer.Exit(1)


@vault_app.command(name="list")
def list_creds() -> None:
    """List credential names in the vault (never shows values).

    Examples:

        safeyolo vault list
    """
    if not _get_vault_path().exists():
        console.print("[dim]No vault found.[/dim] Create one with: safeyolo vault add <name>")
        return

    try:
        vault, _ = _load_vault()
        names = vault.list_names()

        if not names:
            console.print("[dim]Vault is empty.[/dim]")
            return

        table = Table(title="Vault Credentials")
        table.add_column("Name", style="cyan")
        table.add_column("Type", style="green")
        for name in names:
            cred = vault.get(name)
            table.add_row(name, cred.type if cred else "?")
        console.print(table)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@vault_app.command()
def remove(
    name: str = typer.Argument(..., help="Credential name to remove"),
) -> None:
    """Remove a credential from the vault.

    Examples:

        safeyolo vault remove gmail-oauth2
    """
    if not _get_vault_path().exists():
        console.print("[red]Error:[/red] No vault found")
        raise typer.Exit(1)

    try:
        vault, _ = _load_vault()
        if vault.remove(name):
            console.print(f"[green]Removed:[/green] {name}")
        else:
            console.print(f"[yellow]Not found:[/yellow] {name}")
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


# Google scope shortcuts — expand bare names to full URLs
_GOOGLE_SCOPE_SHORTCUTS = {
    "gmail.readonly": "https://www.googleapis.com/auth/gmail.readonly",
    "gmail.send": "https://www.googleapis.com/auth/gmail.send",
    "gmail.modify": "https://www.googleapis.com/auth/gmail.modify",
    "gmail.labels": "https://www.googleapis.com/auth/gmail.labels",
    "calendar.readonly": "https://www.googleapis.com/auth/calendar.readonly",
    "calendar.events": "https://www.googleapis.com/auth/calendar.events",
    "drive.readonly": "https://www.googleapis.com/auth/drive.readonly",
}


def _expand_scopes(scopes: list[str], provider: str | None) -> list[str]:
    """Expand scope shortcuts for known providers."""
    if provider != "google":
        return scopes
    return [_GOOGLE_SCOPE_SHORTCUTS.get(s, s) for s in scopes]


@vault_app.command()
def oauth2(
    name: str = typer.Argument(..., help="Credential name (e.g., gmail-oauth2)"),
    client_id: str = typer.Option(..., "--client-id", help="OAuth2 client ID"),
    client_secret: str = typer.Option(..., "--client-secret", help="OAuth2 client secret"),
    scopes: list[str] = typer.Option(..., "--scope", "-s", help="OAuth2 scopes (repeatable)"),
    provider: str = typer.Option(
        None, "--provider", "-p",
        help="Provider preset (google) — sets auth/token URLs automatically",
    ),
    auth_url: str = typer.Option(
        None, "--auth-url",
        help="Authorization endpoint URL (auto-set by --provider)",
    ),
    token_url: str = typer.Option(
        None, "--token-url",
        help="Token endpoint URL (auto-set by --provider)",
    ),
    port: int = typer.Option(0, "--port", help="Localhost callback port (0 = auto)"),
    no_browser: bool = typer.Option(
        False, "--no-browser",
        help="Manual mode: print URL, paste back the code (for headless servers)",
    ),
) -> None:
    """Authorize an OAuth2 credential via browser consent flow.

    Opens your browser, you log in and authorize, and the tokens are
    stored in the vault — ready for the service gateway to inject.

    Use --no-browser on headless servers: prints the auth URL for you
    to open on any machine, then paste back the redirect URL.

    Examples:

        safeyolo vault oauth2 gmail-oauth2 \\
            --provider google \\
            --client-id 12345.apps.googleusercontent.com \\
            --client-secret GOCSPX-xxx \\
            --scope gmail.readonly

        safeyolo vault oauth2 gmail-oauth2 \\
            --provider google \\
            --client-id 12345.apps.googleusercontent.com \\
            --client-secret GOCSPX-xxx \\
            --scope gmail.readonly \\
            --no-browser
    """
    from ._oauth2_flow import PROVIDERS, OAuth2Error, run_oauth2_flow, run_oauth2_flow_manual

    # Resolve provider preset
    extra_params = None
    if provider:
        preset = PROVIDERS.get(provider)
        if not preset:
            console.print(f"[red]Error:[/red] Unknown provider '{provider}'")
            console.print(f"Available: {', '.join(PROVIDERS.keys())}")
            raise typer.Exit(1)
        if not auth_url:
            auth_url = preset["auth_url"]
        if not token_url:
            token_url = preset["token_url"]
        extra_params = preset.get("extra_auth_params")

    if not auth_url or not token_url:
        console.print("[red]Error:[/red] --auth-url and --token-url required (or use --provider)")
        raise typer.Exit(1)

    # Expand scope shortcuts
    expanded_scopes = _expand_scopes(scopes, provider)

    console.print(f"Credential: [cyan]{name}[/cyan]")
    console.print(f"Provider:   {provider or 'custom'}")
    console.print(f"Scopes:     {', '.join(expanded_scopes)}")

    try:
        if no_browser:
            console.print(f"Mode:       manual (no browser)")
            token_data = run_oauth2_flow_manual(
                client_id=client_id,
                client_secret=client_secret,
                auth_url=auth_url,
                token_url=token_url,
                scopes=expanded_scopes,
                extra_auth_params=extra_params,
            )
        else:
            console.print()
            console.print("Opening browser for authorization...")
            console.print("[dim]Waiting for callback (Ctrl+C to cancel)...[/dim]")
            token_data = run_oauth2_flow(
                client_id=client_id,
                client_secret=client_secret,
                auth_url=auth_url,
                token_url=token_url,
                scopes=expanded_scopes,
                extra_auth_params=extra_params,
                port=port,
            )
    except OAuth2Error as e:
        console.print(f"\n[red]Error:[/red] {e}")
        raise typer.Exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled.[/yellow]")
        raise typer.Exit(1)

    # Extract token fields
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    expires_in = token_data.get("expires_in")

    if not access_token:
        console.print("[red]Error:[/red] No access_token in response")
        raise typer.Exit(1)

    console.print()
    console.print("[green]Authorization successful![/green]")
    if refresh_token:
        console.print("  Refresh token: received (auto-refresh enabled)")
    else:
        console.print("  [yellow]No refresh token[/yellow] — token will expire and need re-auth")
    if expires_in:
        console.print(f"  Expires in: {expires_in}s")

    # Store in vault
    try:
        vault, VaultCredential = _load_vault()

        expires_at = None
        if expires_in:
            expires_at = (datetime.now(UTC) + timedelta(seconds=expires_in)).isoformat()

        cred = VaultCredential(
            name=name,
            type="oauth2",
            value=access_token,
            refresh_token=refresh_token,
            token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            expires_at=expires_at,
        )
        vault.store(cred)
        console.print(f"\n[green]Stored:[/green] {name} (type=oauth2)")
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
