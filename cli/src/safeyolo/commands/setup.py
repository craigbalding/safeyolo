"""Setup commands for SafeYolo system integration."""

import grp
import os
import subprocess
from pathlib import Path

import typer
from rich.console import Console

from ..vm import check_guest_images, guest_image_status

console = Console()

setup_app = typer.Typer(
    name="setup",
    help="Check system prerequisites for SafeYolo microVM agents.",
    no_args_is_help=False,
    invoke_without_command=True,
)


def check_bpf_access() -> tuple[bool, str]:
    """Check if the user can access BPF devices (needed for feth-bridge)."""
    try:
        bpf_gid = grp.getgrnam("access_bpf").gr_gid
    except KeyError:
        return False, "access_bpf group does not exist (run: safeyolo setup bpf)"

    user_groups = os.getgroups()
    if bpf_gid in user_groups:
        return True, "User is in access_bpf group"
    return False, f"Not in access_bpf group (run: safeyolo setup bpf)"


@setup_app.callback(invoke_without_command=True)
def setup() -> None:
    """Check system prerequisites for SafeYolo microVM agents.

    Verifies guest images, BPF access, and other requirements.

    Examples:

        safeyolo setup
    """
    console.print("[bold]Checking prerequisites...[/bold]\n")

    all_ok = True

    # Guest images
    if check_guest_images():
        console.print("  [green]OK[/green]  Guest images available")
    else:
        status = guest_image_status()
        missing = [k for k, v in status.items() if not v]
        console.print(f"  [red]MISSING[/red]  Guest images: {', '.join(missing)}")
        console.print("    Build with: cd guest && ./build-all.sh")
        console.print("    Install:    cp guest/out/* ~/.safeyolo/share/")
        all_ok = False

    # BPF access
    has_bpf, reason = check_bpf_access()
    if has_bpf:
        console.print(f"  [green]OK[/green]  BPF access ({reason})")
    else:
        console.print(f"  [yellow]WARN[/yellow]  BPF access: {reason}")
        console.print("    Run [bold]safeyolo setup bpf[/bold] to fix")

    # VM helper
    from ..vm import find_vm_helper, VMError
    try:
        helper = find_vm_helper()
        console.print(f"  [green]OK[/green]  safeyolo-vm at {helper}")
    except VMError:
        console.print("  [red]MISSING[/red]  safeyolo-vm binary")
        console.print("    Build with: cd vm && make install")
        all_ok = False

    if all_ok:
        console.print("\n[green]All prerequisites met.[/green]")
    else:
        console.print("\n[yellow]Some prerequisites missing — see above.[/yellow]")


@setup_app.command()
def bpf() -> None:
    """Set up BPF access for feth-bridge (requires sudo).

    Creates the access_bpf group if it doesn't exist, adds the current
    user to it, and sets permissions on /dev/bpf* devices. This is the
    same setup that Wireshark's ChmodBPF installer performs.

    You must log out and back in after running this for group membership
    to take effect.

    Examples:

        safeyolo setup bpf
    """
    import platform
    import sys

    if platform.system() != "Darwin":
        console.print("[yellow]BPF setup is macOS-only.[/yellow]")
        console.print("On Linux, use tap/veth networking instead (no BPF needed).")
        raise typer.Exit(0)

    # Check if already set up
    has_bpf, reason = check_bpf_access()
    if has_bpf:
        console.print(f"[green]Already configured:[/green] {reason}")
        raise typer.Exit(0)

    username = os.environ.get("USER", os.environ.get("LOGNAME", ""))
    if not username:
        console.print("[red]Cannot determine username[/red]")
        raise typer.Exit(1)

    console.print("[bold]Setting up BPF access for feth-bridge...[/bold]\n")
    console.print("This requires sudo to:")
    console.print("  1. Create the access_bpf group (if needed)")
    console.print(f"  2. Add {username} to the group")
    console.print("  3. Set /dev/bpf* permissions\n")

    try:
        # Create group if it doesn't exist
        try:
            grp.getgrnam("access_bpf")
            console.print("  access_bpf group already exists")
        except KeyError:
            console.print("  Creating access_bpf group...")
            subprocess.run(
                ["sudo", "dseditgroup", "-o", "create", "access_bpf"],
                check=True,
            )

        # Add user to group
        console.print(f"  Adding {username} to access_bpf...")
        subprocess.run(
            ["sudo", "dseditgroup", "-o", "edit", "-a", username, "-t", "user", "access_bpf"],
            check=True,
        )

        # Set BPF device permissions
        console.print("  Setting /dev/bpf* permissions...")
        subprocess.run(
            ["sudo", "sh", "-c", "chgrp access_bpf /dev/bpf* && chmod g+rw /dev/bpf*"],
            check=True,
        )

    except subprocess.CalledProcessError as err:
        console.print(f"\n[red]Failed:[/red] {err}")
        raise typer.Exit(1)

    console.print("\n[green]BPF access configured.[/green]")
    console.print("[yellow]Log out and back in[/yellow] for group membership to take effect.")
    console.print(f"Verify: [dim]groups | grep access_bpf[/dim]")


@setup_app.command()
def sudoers() -> None:
    """Install sudoers rules for passwordless pf/feth management.

    Copies the SafeYolo sudoers template to /etc/sudoers.d/safeyolo,
    granting passwordless sudo for only the specific commands SafeYolo
    needs: pfctl, ifconfig feth*, sysctl, and pf.conf management.

    Review the template before installing:

        safeyolo setup sudoers --show

    Examples:

        safeyolo setup sudoers
    """
    import platform
    import shutil

    if platform.system() != "Darwin":
        console.print("[yellow]sudoers setup is macOS-only.[/yellow]")
        console.print("On Linux, pf/feth are not used — different firewall rules apply.")
        raise typer.Exit(0)

    template = Path(__file__).parent.parent / "templates" / "safeyolo.sudoers"
    if not template.exists():
        console.print(f"[red]Template not found:[/red] {template}")
        raise typer.Exit(1)

    dest = Path("/etc/sudoers.d/safeyolo")

    # Show the template so the user knows what they're installing
    console.print("[bold]SafeYolo sudoers template:[/bold]\n")
    console.print(template.read_text())

    if dest.exists():
        console.print(f"[yellow]{dest} already exists.[/yellow]")
        console.print("Remove it first if you want to reinstall: sudo rm /etc/sudoers.d/safeyolo")
        raise typer.Exit(0)

    console.print(f"Installing to [bold]{dest}[/bold] (requires sudo)...\n")

    try:
        # Write via sudo tee (can't write directly to /etc/sudoers.d/)
        content = template.read_text()
        proc = subprocess.run(
            ["sudo", "tee", str(dest)],
            input=content.encode(),
            capture_output=True,
            check=True,
        )

        # Set required permissions (sudoers files must be 0440)
        subprocess.run(["sudo", "chmod", "0440", str(dest)], check=True)

        # Validate syntax
        result = subprocess.run(
            ["sudo", "visudo", "-c", "-f", str(dest)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            console.print(f"[red]Syntax validation failed:[/red] {result.stderr}")
            console.print("Removing invalid file...")
            subprocess.run(["sudo", "rm", str(dest)], check=True)
            raise typer.Exit(1)

    except subprocess.CalledProcessError as err:
        console.print(f"\n[red]Failed:[/red] {err}")
        raise typer.Exit(1)

    console.print("[green]Sudoers rules installed.[/green]")
    console.print("SafeYolo commands (pfctl, ifconfig feth, sysctl) no longer require a password.")
