"""Setup commands for SafeYolo system integration."""

import os
import platform as _platform
import re as _re
import subprocess
from pathlib import Path

import typer
from rich.console import Console

from ..vm import check_guest_images, guest_image_status

console = Console()

_VALID_USERNAME = _re.compile(r"^[a-z_][a-z0-9_-]*$")

setup_app = typer.Typer(
    name="setup",
    help="Check system prerequisites for SafeYolo microVM agents.",
    no_args_is_help=False,
    invoke_without_command=True,
)


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

    # Platform-specific checks. macOS uses a Swift VM helper (vsock-based
    # egress, structural isolation); Linux uses runsc (gVisor) with a
    # loopback-only netns.
    system = _platform.system()
    if system == "Darwin":
        # VM helper (Swift-built safeyolo-vm binary)
        from ..vm import VMError, find_vm_helper
        try:
            helper = find_vm_helper()
            console.print(f"  [green]OK[/green]  safeyolo-vm at {helper}")
        except VMError:
            console.print("  [red]MISSING[/red]  safeyolo-vm binary")
            console.print("    Build with: cd vm && make install")
            all_ok = False
    elif system == "Linux":
        from ..platform.linux import (
            check_userns_prerequisites,
            detect_runsc_platform,
            find_runsc,
        )

        # runsc (gVisor) — the Linux VM runtime
        runsc_path = find_runsc()
        if runsc_path:
            console.print(f"  [green]OK[/green]  runsc (found at {runsc_path})")
        else:
            console.print("  [red]MISSING[/red]  runsc: not found on PATH or in /usr/local/bin, /usr/bin")
            console.print("    Install gVisor — see README 'Linux' section for apt commands.")
            all_ok = False

        # User namespace prerequisites
        userns = check_userns_prerequisites()
        if userns["apparmor_restricts"]:
            if userns["apparmor_profile_loaded"]:
                console.print("  [green]OK[/green]  AppArmor profile (safeyolo-runsc)")
            else:
                console.print("  [yellow]SETUP[/yellow]  AppArmor profile needed (user namespace creation)")
                console.print("    [bold]sudo apparmor_parser -r /etc/apparmor.d/safeyolo-runsc[/bold]")
                all_ok = False

        # KVM platform detection
        kvm = detect_runsc_platform()
        if kvm["platform"] == "kvm":
            console.print("  [green]OK[/green]  KVM platform (hardware isolation)")
        elif not kvm["kvm_exists"]:
            console.print("  [dim]INFO[/dim]  /dev/kvm not available — using systrap (software isolation)")
            console.print("    Coding agent performance is equivalent. Hardware isolation")
            console.print("    (KVM) is available on hosts with virtualization enabled.")
        elif kvm["kvm_operator_access"] and not kvm["kvm_subordinate_access"]:
            console.print("  [yellow]SETUP[/yellow]  KVM available — grant access for hardware isolation")
            console.print("    KVM provides hardware-enforced isolation (recommended).")
            console.print("    Without it, SafeYolo uses systrap (software isolation,")
            console.print("    equivalent performance for coding agents).")
            console.print("    [bold]sudo setfacl -m u:100000:rw /dev/kvm[/bold]")
        else:
            console.print("  [dim]INFO[/dim]  /dev/kvm exists but not accessible — using systrap")
    else:
        console.print(f"  [yellow]WARN[/yellow]  unsupported platform {system!r}: skipping runtime checks")

    if all_ok:
        console.print("\n[green]All prerequisites met.[/green]")
    else:
        console.print("\n[yellow]Some prerequisites missing — see above.[/yellow]")


def _sudoers_template_and_summary() -> tuple[Path, str, str]:
    """Return (template_path, post-install-summary, missing-template-error)
    for the current platform.

    Darwin: safeyolo.sudoers — ifconfig lo0 alias for attribution IPs.
    Linux:  safeyolo-linux.sudoers — ip/iptables/mount/umount/runsc/cp rules.
    """
    templates_dir = Path(__file__).parent.parent / "templates"
    system = _platform.system()
    if system == "Darwin":
        return (
            templates_dir / "safeyolo.sudoers",
            "ifconfig lo0 alias",
            "Darwin sudoers template missing",
        )
    if system == "Linux":
        return (
            templates_dir / "safeyolo-linux.sudoers",
            "ip/iptables/mount/umount/runsc/cp",
            "Linux sudoers template missing",
        )
    raise RuntimeError(f"Unsupported platform for sudoers setup: {system}")


def _resolve_sudoers_body(template_path: Path) -> str:
    """Read the template and apply platform-specific substitutions.

    Both platforms substitute the invoking user's username into the
    template so that rules are scoped to a single operator, not a
    broad group like macOS %staff (which includes ALL local users).

    Linux additionally substitutes rootfs paths and chown targets to
    pin the extraction rules to literal destinations.
    """
    content = template_path.read_text()

    username = os.environ.get("SUDO_USER") or os.environ.get("USER") or ""
    if not username:
        raise RuntimeError(
            "Cannot determine invoking user (neither $SUDO_USER nor $USER is set)."
        )
    if not _VALID_USERNAME.match(username):
        raise RuntimeError(
            f"Username {username!r} contains characters unsafe for sudoers. "
            f"Expected pattern: {_VALID_USERNAME.pattern}"
        )

    system = _platform.system()
    if system == "Darwin":
        content = content.replace("%safeyolo_user", username)
    elif system == "Linux":
        # `%safeyolo` → bare username (drops the `%` group prefix).
        content = content.replace("%safeyolo", username)

        from ..config import get_share_dir
        share_dir = get_share_dir()

        # Pin the base rootfs destination path.
        base_rootfs_dest = str(share_dir / "rootfs-base")
        content = content.replace("%SAFEYOLO_BASE_ROOTFS_DEST%", base_rootfs_dest)

        # Pin the ext4 image path for the one-time loop mount.
        base_ext4 = str(share_dir / "rootfs-base.ext4")
        content = content.replace("%SAFEYOLO_BASE_EXT4%", base_ext4)

        # Pin the chown target (uid:gid) for base rootfs extraction.
        # The colon must be escaped as \: in sudoers (: is a parser delimiter).
        import pwd
        try:
            pw = pwd.getpwnam(username)
            chown_target = f"{pw.pw_uid}\\:{pw.pw_gid}"
        except KeyError:
            chown_target = f"{username}\\:{username}"
        content = content.replace("%SAFEYOLO_CHOWN_TARGET%", chown_target)

    return content


@setup_app.command()
def sudoers() -> None:
    """Install sudoers rules for passwordless SafeYolo privileged operations.

    Copies a platform-specific SafeYolo sudoers template to
    /etc/sudoers.d/safeyolo, granting passwordless sudo for ONLY the
    specific commands SafeYolo needs at runtime:

      macOS: ifconfig lo0 alias/-alias for the per-agent attribution IP
        (a synthetic 127.0.0.X bound by the proxy bridge). The rules are
        scoped to the invoking user via the %safeyolo_user placeholder.

      Linux: ip netns/link/addr for veth and namespace lifecycle,
        iptables for per-agent egress rules, mount/umount for overlayfs,
        runsc for gVisor container lifecycle, sysctl for IP forwarding,
        mkdir/cp for base-rootfs extraction. The Linux template's
        `%safeyolo` placeholder is replaced with the invoking user's
        username at install time.

    Examples:

        safeyolo setup sudoers
    """
    try:
        template, post_install_summary, missing_msg = _sudoers_template_and_summary()
    except RuntimeError as err:
        console.print(f"[yellow]{err}[/yellow]")
        raise typer.Exit(0)

    if not template.exists():
        console.print(f"[red]{missing_msg}:[/red] {template}")
        raise typer.Exit(1)

    dest = Path("/etc/sudoers.d/safeyolo")

    # Resolve substitutions (Linux: %safeyolo → username) before showing +
    # writing so what the user sees is what lands on disk.
    try:
        content = _resolve_sudoers_body(template)
    except RuntimeError as err:
        console.print(f"[red]{err}[/red]")
        raise typer.Exit(1)

    # Show the template so the user knows what they're installing
    console.print("[bold]SafeYolo sudoers rules to install:[/bold]\n")
    console.print(content)

    if dest.exists():
        console.print(f"[yellow]{dest} already exists.[/yellow]")
        console.print("Remove it first if you want to reinstall: sudo rm /etc/sudoers.d/safeyolo")
        raise typer.Exit(0)

    console.print(f"Installing to [bold]{dest}[/bold] (requires sudo)...\n")

    try:
        # Write via sudo tee (can't write directly to /etc/sudoers.d/)
        subprocess.run(
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
    console.print(f"SafeYolo commands ({post_install_summary}) no longer require a password.")
