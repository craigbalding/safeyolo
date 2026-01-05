"""Certificate management commands."""

from pathlib import Path

import typer
from rich.console import Console

from ..config import find_config_dir, get_certs_dir, load_config

console = Console()


def get_ca_cert_path() -> Path | None:
    """Find the CA certificate file."""
    certs_dir = get_certs_dir()

    # mitmproxy generates this file name
    ca_cert = certs_dir / "mitmproxy-ca-cert.pem"
    if ca_cert.exists():
        return ca_cert

    return None


def env() -> None:
    """Print environment variables for CA trust and proxy.

    These variables configure per-process CA trust and proxy settings.
    No system-wide trust store modification required.

    Usage:

        eval $(safeyolo cert env)

    Or copy specific exports for your runtime:

        safeyolo cert env
    """
    config_dir = find_config_dir()
    if not config_dir:
        console.print("[red]No SafeYolo configuration found.[/red]")
        console.print("Run [bold]safeyolo start[/bold] first.")
        raise typer.Exit(1)

    ca_cert = get_ca_cert_path()
    if not ca_cert:
        console.print("[red]CA certificate not found.[/red]")
        console.print("The certificate is generated when SafeYolo starts.")
        console.print("Run [bold]safeyolo start[/bold] first.")
        raise typer.Exit(1)

    config = load_config()
    proxy_port = config.get("proxy", {}).get("port", 8080)

    # Output exports for eval
    print("# SafeYolo CA trust (per-process, not system-wide)")
    print(f"export NODE_EXTRA_CA_CERTS={ca_cert}")
    print(f"export REQUESTS_CA_BUNDLE={ca_cert}")
    print(f"export SSL_CERT_FILE={ca_cert}")
    print(f"export GIT_SSL_CAINFO={ca_cert}")
    print(f"export HTTP_PROXY=http://localhost:{proxy_port}")
    print(f"export HTTPS_PROXY=http://localhost:{proxy_port}")


def show() -> None:
    """Show CA certificate location and status.

    Examples:

        safeyolo cert show
    """
    config_dir = find_config_dir()
    if not config_dir:
        console.print("[yellow]No SafeYolo configuration found.[/yellow]")
        console.print("Run [bold]safeyolo start[/bold] first.")
        raise typer.Exit(1)

    ca_cert = get_ca_cert_path()

    console.print("[bold]CA Certificate Status[/bold]\n")
    console.print(f"  Config directory: {config_dir}")
    console.print(f"  Certs directory:  {get_certs_dir()}")

    if ca_cert:
        console.print(f"  CA certificate:   [green]{ca_cert}[/green]")
        console.print(f"\n  File size: {ca_cert.stat().st_size} bytes")

        # Show fingerprint
        try:
            import hashlib
            content = ca_cert.read_bytes()
            sha256 = hashlib.sha256(content).hexdigest()[:16]
            console.print(f"  SHA256:    {sha256}...")
        except Exception:
            pass

        console.print("\nTo use: [bold]eval $(safeyolo cert env)[/bold]")
    else:
        console.print("  CA certificate:   [yellow]Not generated yet[/yellow]")
        console.print("\nThe certificate is created when SafeYolo first starts.")
        console.print("Run [bold]safeyolo start[/bold] to generate it.")


# Create subcommand group
cert_app = typer.Typer(
    name="cert",
    help="Manage CA certificate for HTTPS inspection.",
    no_args_is_help=True,
)

cert_app.command()(env)
cert_app.command()(show)
