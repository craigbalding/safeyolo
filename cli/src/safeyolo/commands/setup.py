"""Setup commands for SafeYolo system integration."""

import grp
import os
import subprocess

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
        return False, "access_bpf group does not exist"

    user_groups = os.getgroups()
    if bpf_gid in user_groups:
        return True, "User is in access_bpf group"
    return False, "Not in access_bpf group (install Wireshark or OrbStack to add it)"


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
        console.print("    feth-bridge needs BPF to forward VM network traffic")

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
