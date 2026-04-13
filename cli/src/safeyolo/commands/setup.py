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
    return False, "Not in access_bpf group (run: safeyolo setup bpf)"


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
    from ..vm import VMError, find_vm_helper
    try:
        helper = find_vm_helper()
        console.print(f"  [green]OK[/green]  safeyolo-vm at {helper}")
    except VMError:
        console.print("  [red]MISSING[/red]  safeyolo-vm binary")
        console.print("    Build with: cd vm && make install")
        all_ok = False

    # pf anchor hook (macOS only). Runtime no longer installs this — must be
    # present in /etc/pf.conf before the first VM starts.
    import platform as _platform
    if _platform.system() == "Darwin":
        state = _pf_conf_state("com.safeyolo")
        if state == "present":
            console.print(f"  [green]OK[/green]  pf anchor hook installed in {_PF_CONF_PATH}")
        elif state == "absent":
            console.print(f"  [yellow]WARN[/yellow]  pf anchor hook not installed in {_PF_CONF_PATH}")
            console.print("    Run [bold]safeyolo setup pf[/bold] to install")
            all_ok = False
        else:
            console.print(f"  [red]MISSING[/red]  pf anchor hook: {state}")
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
    console.print("Verify: [dim]groups | grep access_bpf[/dim]")


@setup_app.command()
def sudoers() -> None:
    """Install sudoers rules for passwordless pf/feth management.

    Copies the SafeYolo sudoers template to /etc/sudoers.d/safeyolo,
    granting passwordless sudo for only the specific commands SafeYolo
    needs at runtime: pfctl on the fixed com.safeyolo anchor, ifconfig
    feth*, sysctl IP forwarding, and writes to the fixed anchor file
    /etc/pf.anchors/com.safeyolo. The sudoers rules do NOT grant write
    access to /etc/pf.conf — install the static anchor hook once with
    `safeyolo setup pf` instead.

    Review the template before installing:

        safeyolo setup sudoers --show

    Examples:

        safeyolo setup sudoers
    """
    import platform

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
    console.print("SafeYolo commands (pfctl, ifconfig feth, sysctl) no longer require a password.")


# ---------------------------------------------------------------------------
# pf anchor hook install
# ---------------------------------------------------------------------------

# The exact two lines SafeYolo expects in /etc/pf.conf for each anchor.
# Anything else (missing, partial, or with a different load path) is treated
# as an unexpected state and we refuse to modify pf.conf automatically.
_PF_CONF_PATH = Path("/etc/pf.conf")
_PF_ANCHORS_DIR = Path("/etc/pf.anchors")


def _pf_hook_lines(anchor: str) -> tuple[str, str]:
    """Return the (anchor, load) lines for the given anchor name."""
    anchor_file = _PF_ANCHORS_DIR / anchor
    return (
        f'anchor "{anchor}"',
        f'load anchor "{anchor}" from "{anchor_file}"',
    )


def _pf_conf_state(anchor: str) -> str:
    """Return 'present', 'absent', or a description of an unexpected state.

    Matches lines exactly (after stripping whitespace and skipping comments).
    This matters because `anchor "com.safeyolo"` is a substring of
    `load anchor "com.safeyolo" from "..."`, so substring matching would
    misreport a pf.conf that has only the load line as "present".
    """
    anchor_line, load_line = _pf_hook_lines(anchor)
    try:
        content = _PF_CONF_PATH.read_text()
    except FileNotFoundError:
        return f"missing: {_PF_CONF_PATH} does not exist"
    except PermissionError as err:
        return f"unreadable: {err}"

    has_anchor = False
    has_load = False
    has_conflicting_load = False
    load_prefix = f'load anchor "{anchor}" from '
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == anchor_line:
            has_anchor = True
        elif line == load_line:
            has_load = True
        elif line.startswith(load_prefix):
            has_conflicting_load = True

    if has_anchor and has_load:
        return "present"
    if not has_anchor and not has_load:
        if has_conflicting_load:
            return (
                f"conflict: {_PF_CONF_PATH} already loads anchor "
                f"{anchor!r} from a different path"
            )
        return "absent"
    # Partial: one line present, the other missing — don't guess, fail loudly.
    missing = "anchor" if not has_anchor else "load anchor"
    return (
        f"partial: {_PF_CONF_PATH} contains one of the two expected hook "
        f"lines for {anchor!r} but not the other (missing {missing!r} line)"
    )


def _install_pf_hook(anchor: str) -> tuple[bool, str]:
    """Install the static pf.conf hook for an anchor if not already present.

    Returns (changed, message). Raises RuntimeError on unexpected pf.conf state
    so the caller can surface a clear error without leaving things half-done.
    """
    state = _pf_conf_state(anchor)
    if state == "present":
        return False, f"already installed in {_PF_CONF_PATH}"
    if state != "absent":
        raise RuntimeError(f"Refusing to modify {_PF_CONF_PATH}: {state}")

    anchor_line, load_line = _pf_hook_lines(anchor)
    block = (
        f"\n# SafeYolo VM isolation — managed by `safeyolo setup pf`\n"
        f"{anchor_line}\n"
        f"{load_line}\n"
    )

    # Read current content and produce a new version; write the full file via
    # a single `tee` (not `tee -a`) so sudoers can narrowly allow writes only
    # to /etc/pf.conf. Callers may assume this is idempotent: if the lines are
    # already present we never get here.
    try:
        current = _PF_CONF_PATH.read_text()
    except FileNotFoundError:
        raise RuntimeError(f"{_PF_CONF_PATH} does not exist")

    if not current.endswith("\n"):
        current += "\n"
    new_content = current + block

    proc = subprocess.run(
        ["sudo", "tee", str(_PF_CONF_PATH)],
        input=new_content, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to write {_PF_CONF_PATH}: {proc.stderr}")
    return True, f"added anchor hook for {anchor!r} to {_PF_CONF_PATH}"


def _ensure_empty_anchor_file(anchor: str) -> tuple[bool, str]:
    """Ensure /etc/pf.anchors/<anchor> exists. Create empty if missing."""
    anchor_file = _PF_ANCHORS_DIR / anchor
    if anchor_file.exists():
        return False, f"{anchor_file} already exists"
    placeholder = f"# SafeYolo anchor {anchor} — populated at runtime\n"
    proc = subprocess.run(
        ["sudo", "tee", str(anchor_file)],
        input=placeholder, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to create {anchor_file}: {proc.stderr}")
    return True, f"created empty {anchor_file}"


@setup_app.command()
def pf(
    test: bool = typer.Option(
        False,
        "--test",
        help="Install the com.safeyolo-test anchor hook (blackbox test harness).",
    ),
) -> None:
    """Install the static SafeYolo pf anchor hook in /etc/pf.conf.

    Idempotent: re-running this command is a no-op if the anchor hook is
    already present. If /etc/pf.conf is in an unexpected state (partial or
    conflicting hook) the command refuses to modify it and prints the
    remediation.

    After this runs once, SafeYolo only manages the anchor file at
    /etc/pf.anchors/com.safeyolo and never touches /etc/pf.conf again.

    Examples:

        safeyolo setup pf
        safeyolo setup pf --test   # for the blackbox test harness
    """
    import platform as _platform

    if _platform.system() != "Darwin":
        console.print("[yellow]pf setup is macOS-only.[/yellow]")
        raise typer.Exit(0)

    anchor = "com.safeyolo-test" if test else "com.safeyolo"
    console.print(f"[bold]Installing pf anchor hook for {anchor!r}[/bold]\n")

    try:
        changed_conf, msg_conf = _install_pf_hook(anchor)
        if changed_conf:
            console.print(f"  [green]OK[/green]  {msg_conf}")
        else:
            console.print(f"  [dim]skip[/dim]  {msg_conf}")

        changed_anchor, msg_anchor = _ensure_empty_anchor_file(anchor)
        if changed_anchor:
            console.print(f"  [green]OK[/green]  {msg_anchor}")
        else:
            console.print(f"  [dim]skip[/dim]  {msg_anchor}")

    except RuntimeError as err:
        console.print(f"\n[red]Failed:[/red] {err}")
        console.print(
            "\nFix /etc/pf.conf manually (e.g. remove stale SafeYolo lines) "
            "and re-run `safeyolo setup pf`."
        )
        raise typer.Exit(1)

    console.print(
        f"\n[green]pf anchor hook installed.[/green] "
        f"SafeYolo will manage {_PF_ANCHORS_DIR / anchor} only."
    )
