"""Certificate management commands."""

import platform
import subprocess
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from ..config import find_config_dir, get_certs_dir

console = Console()


def get_ca_cert_path() -> Path | None:
    """Find the CA certificate file."""
    certs_dir = get_certs_dir()

    # mitmproxy generates this file name
    ca_cert = certs_dir / "mitmproxy-ca-cert.pem"
    if ca_cert.exists():
        return ca_cert

    return None


def install(
    cert_path: Path = typer.Argument(
        None,
        help="Path to CA certificate (default: auto-detect from config)",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run", "-n",
        help="Show commands without executing",
    ),
) -> None:
    """Install SafeYolo CA certificate into system trust store.

    This is required for HTTPS inspection to work. The certificate
    is generated automatically when SafeYolo first starts.

    Examples:

        safeyolo cert install           # Auto-detect and install
        safeyolo cert install -n        # Show what would be done
        safeyolo cert install /path/to/cert.pem  # Install specific cert
    """
    # Find the certificate
    if cert_path:
        ca_cert = cert_path
        if not ca_cert.exists():
            console.print(f"[red]Certificate not found:[/red] {ca_cert}")
            raise typer.Exit(1)
    else:
        config_dir = find_config_dir()
        if not config_dir:
            console.print(
                "[red]No SafeYolo configuration found.[/red]\n"
                "Run [bold]safeyolo init[/bold] and [bold]safeyolo start[/bold] first.\n"
                "The CA certificate is generated on first proxy start."
            )
            raise typer.Exit(1)

        ca_cert = get_ca_cert_path()
        if not ca_cert:
            console.print(
                "[red]CA certificate not found.[/red]\n\n"
                "The certificate is generated when SafeYolo starts.\n"
                "Run [bold]safeyolo start[/bold] first, then retry."
            )
            raise typer.Exit(1)

    console.print(f"[bold]Installing CA certificate[/bold]\n")
    console.print(f"  Certificate: {ca_cert}")

    system = platform.system()

    if system == "Darwin":
        _install_macos(ca_cert, dry_run)
    elif system == "Linux":
        _install_linux(ca_cert, dry_run)
    elif system == "Windows":
        _install_windows(ca_cert, dry_run)
    else:
        console.print(f"[red]Unsupported OS:[/red] {system}")
        console.print("\nManually add the certificate to your system trust store:")
        console.print(f"  {ca_cert}")
        raise typer.Exit(1)


def _install_macos(ca_cert: Path, dry_run: bool) -> None:
    """Install certificate on macOS."""
    cmd = [
        "sudo", "security", "add-trusted-cert",
        "-d",  # Add to admin cert store
        "-r", "trustRoot",  # Trust as root CA
        "-k", "/Library/Keychains/System.keychain",
        str(ca_cert),
    ]

    console.print(f"  OS: macOS\n")
    console.print(f"[dim]Command: {' '.join(cmd)}[/dim]\n")

    if dry_run:
        console.print("[yellow]Dry run - no changes made[/yellow]")
        return

    console.print("This requires administrator privileges (sudo).\n")

    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        console.print("[green]Certificate installed successfully![/green]")
        console.print("\nVerify with: [bold]safeyolo check[/bold]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Installation failed:[/red] {e.stderr or e}")
        console.print("\nYou can try manually:")
        console.print(f"  {' '.join(cmd)}")
        raise typer.Exit(1)


def _install_linux(ca_cert: Path, dry_run: bool) -> None:
    """Install certificate on Linux."""
    # Detect distro
    dest_dir = Path("/usr/local/share/ca-certificates")
    update_cmd = "update-ca-certificates"

    # Check for RHEL/CentOS/Fedora
    if Path("/etc/pki/ca-trust").exists():
        dest_dir = Path("/etc/pki/ca-trust/source/anchors")
        update_cmd = "update-ca-trust"

    dest_path = dest_dir / "safeyolo.crt"

    console.print(f"  OS: Linux")
    console.print(f"  Destination: {dest_path}\n")

    copy_cmd = ["sudo", "cp", str(ca_cert), str(dest_path)]
    update_cmd_full = ["sudo", update_cmd]

    console.print(f"[dim]Commands:[/dim]")
    console.print(f"[dim]  {' '.join(copy_cmd)}[/dim]")
    console.print(f"[dim]  {' '.join(update_cmd_full)}[/dim]\n")

    if dry_run:
        console.print("[yellow]Dry run - no changes made[/yellow]")
        return

    console.print("This requires administrator privileges (sudo).\n")

    try:
        # Copy cert
        subprocess.run(copy_cmd, check=True, capture_output=True, text=True)
        # Update trust store
        subprocess.run(update_cmd_full, check=True, capture_output=True, text=True)

        console.print("[green]Certificate installed successfully![/green]")
        console.print("\nVerify with: [bold]safeyolo check[/bold]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Installation failed:[/red] {e.stderr or e}")
        console.print("\nYou can try manually:")
        console.print(f"  {' '.join(copy_cmd)}")
        console.print(f"  {' '.join(update_cmd_full)}")
        raise typer.Exit(1)


def _install_windows(ca_cert: Path, dry_run: bool) -> None:
    """Install certificate on Windows."""
    cmd = [
        "certutil", "-addstore", "-f", "ROOT", str(ca_cert)
    ]

    console.print(f"  OS: Windows\n")
    console.print(f"[dim]Command: {' '.join(cmd)}[/dim]\n")

    if dry_run:
        console.print("[yellow]Dry run - no changes made[/yellow]")
        return

    console.print("This requires administrator privileges.\n")
    console.print("[yellow]Run this in an Administrator command prompt:[/yellow]")
    console.print(f"  {' '.join(cmd)}")

    # Don't auto-run on Windows - too risky without proper UAC handling
    raise typer.Exit(0)


def show() -> None:
    """Show CA certificate location and status.

    Examples:

        safeyolo cert show
    """
    config_dir = find_config_dir()
    if not config_dir:
        console.print("[yellow]No SafeYolo configuration found.[/yellow]")
        console.print("Run [bold]safeyolo init[/bold] first.")
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

        console.print(f"\nTo install: [bold]safeyolo cert install[/bold]")
    else:
        console.print(f"  CA certificate:   [yellow]Not generated yet[/yellow]")
        console.print(f"\nThe certificate is created when SafeYolo first starts.")
        console.print("Run [bold]safeyolo start[/bold] to generate it.")


# Create subcommand group
cert_app = typer.Typer(
    name="cert",
    help="Manage CA certificate for HTTPS inspection.",
    no_args_is_help=True,
)

cert_app.command()(install)
cert_app.command()(show)
