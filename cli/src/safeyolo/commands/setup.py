"""Setup commands for SafeYolo system integration."""

import grp
import os
import platform as _platform
import shutil
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


def check_runsc() -> tuple[bool, str]:
    """Check if runsc (gVisor) is installed. Linux VM runtime."""
    path = shutil.which("runsc")
    if not path:
        for p in ("/usr/local/bin/runsc", "/usr/bin/runsc"):
            if os.path.exists(p) and os.access(p, os.X_OK):
                path = p
                break
    if path:
        return True, f"found at {path}"
    return False, "not found on PATH or in /usr/local/bin, /usr/bin"


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

    # Platform-specific checks. macOS uses a Swift VM helper + feth-bridge (BPF)
    # + pf; Linux uses runsc (gVisor) and has none of those.
    system = _platform.system()
    if system == "Darwin":
        # BPF access (needed by feth-bridge)
        has_bpf, reason = check_bpf_access()
        if has_bpf:
            console.print(f"  [green]OK[/green]  BPF access ({reason})")
        else:
            console.print(f"  [yellow]WARN[/yellow]  BPF access: {reason}")
            console.print("    Run [bold]safeyolo setup bpf[/bold] to fix")

        # VM helper (Swift-built safeyolo-vm binary)
        from ..vm import VMError, find_vm_helper
        try:
            helper = find_vm_helper()
            console.print(f"  [green]OK[/green]  safeyolo-vm at {helper}")
        except VMError:
            console.print("  [red]MISSING[/red]  safeyolo-vm binary")
            console.print("    Build with: cd vm && make install")
            all_ok = False

        # pf anchor hook — must be present in /etc/pf.conf before the first
        # VM starts. Runtime no longer installs this.
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
    elif system == "Linux":
        # runsc (gVisor) — the Linux VM runtime
        has_runsc, reason = check_runsc()
        if has_runsc:
            console.print(f"  [green]OK[/green]  runsc ({reason})")
        else:
            console.print(f"  [red]MISSING[/red]  runsc: {reason}")
            console.print("    Install gVisor — see README 'Linux' section for apt commands.")
            all_ok = False

        # sudoers rules — present means no sudo prompts during agent lifecycle.
        # /etc/sudoers.d/ is typically 0750 (unreadable without sudo), so
        # .exists() can raise PermissionError; treat that as "unknown" and
        # surface the pointer anyway.
        sudoers_path = Path("/etc/sudoers.d/safeyolo")
        try:
            sudoers_installed = sudoers_path.exists()
        except PermissionError:
            sudoers_installed = None

        if sudoers_installed is True:
            console.print(f"  [green]OK[/green]  sudoers rules installed ({sudoers_path})")
        elif sudoers_installed is False:
            console.print(f"  [yellow]WARN[/yellow]  sudoers rules not installed ({sudoers_path})")
            console.print("    Without them, every agent start/stop/remove prompts for sudo.")
            console.print("    Run [bold]safeyolo setup sudoers[/bold] to install.")
        else:
            console.print(f"  [dim]?[/dim]  sudoers rules: cannot read {sudoers_path.parent}")
            console.print("    If not already installed, run [bold]safeyolo setup sudoers[/bold].")
    else:
        console.print(f"  [yellow]WARN[/yellow]  unsupported platform {system!r}: skipping runtime checks")

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


def _sudoers_template_and_summary() -> tuple[Path, str, str]:
    """Return (template_path, post-install-summary, missing-template-error)
    for the current platform.

    Darwin: safeyolo.sudoers — pfctl/feth/sysctl/anchor-file write rules.
    Linux:  safeyolo-linux.sudoers — ip/iptables/mount/umount/runsc/cp rules.
    """
    templates_dir = Path(__file__).parent.parent / "templates"
    system = _platform.system()
    if system == "Darwin":
        return (
            templates_dir / "safeyolo.sudoers",
            "pfctl, ifconfig feth, sysctl",
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

    Linux substitutions:
      - `%safeyolo` → invoking user's username. The placeholder group
        doesn't exist on default distros, so without this substitution
        the rules would never match any user.
      - `%SAFEYOLO_BASE_ROOTFS_DEST%` → the resolved base rootfs path
        (e.g. `/home/alice/.safeyolo/share/rootfs-base`). Pinning the
        destination literal kills the wildcard in the `cp -a` rule, so
        it can't be used as a generic `sudo cp` primitive.

    Darwin uses `%staff` (a default macOS group) and is left untouched.
    """
    content = template_path.read_text()
    if _platform.system() == "Linux":
        username = os.environ.get("SUDO_USER") or os.environ.get("USER") or ""
        if not username:
            raise RuntimeError(
                "Cannot determine invoking user (neither $SUDO_USER nor $USER is set)."
            )
        # `%safeyolo` → bare username (drops the `%` group prefix).
        content = content.replace("%safeyolo", username)

        # Resolve the base-rootfs destination that the Linux platform's
        # `prepare_rootfs` will `sudo cp -a /tmp/safeyolo-rootfs-mnt/. …`
        # into. Pinning the literal path kills the wildcard in the rule.
        from ..config import get_agents_dir, get_share_dir
        base_rootfs_dest = str(get_share_dir() / "rootfs-base")
        content = content.replace("%SAFEYOLO_BASE_ROOTFS_DEST%", base_rootfs_dest)

        # Pin the rm -rf rule to this instance's agents dir; sudoers `*`
        # does not match `/`, so path traversal outside the dir is blocked.
        agents_dir = str(get_agents_dir())
        content = content.replace("%SAFEYOLO_AGENTS_DIR%", agents_dir)

    return content


@setup_app.command()
def sudoers() -> None:
    """Install sudoers rules for passwordless SafeYolo privileged operations.

    Copies a platform-specific SafeYolo sudoers template to
    /etc/sudoers.d/safeyolo, granting passwordless sudo for ONLY the
    specific commands SafeYolo needs at runtime:

      macOS: pfctl on the fixed com.safeyolo anchor, ifconfig feth*,
        sysctl IP forwarding, writes to /etc/pf.anchors/com.safeyolo.
        The rules do NOT grant write access to /etc/pf.conf — install
        the static anchor hook once with `safeyolo setup pf` instead.

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

    # Reload main pf.conf so the anchor hook takes effect in the running pf
    # state now, not on the next reboot. macOS loads pf.conf once at boot;
    # edits to the file afterwards are inert until an explicit reload.
    # Without this step the hook sits on disk and every packet sails past it
    # — which silently defeats SafeYolo's default-deny egress posture until
    # the Mac next reboots. We refuse to start without it; abort on failure.
    #
    # Side effect: `pfctl -f` replaces the main ruleset, which flushes
    # anchors that were added dynamically at runtime (notably Apple's
    # `com.apple.internet-sharing` when Internet Sharing is on). The
    # owning service normally re-registers; if it doesn't, toggle
    # Sharing off/on. We surface the warning so the user isn't surprised.
    console.print(
        f"\n  [yellow]Reloading {_PF_CONF_PATH}[/yellow] — may flush "
        f"dynamic anchors like Apple's Internet Sharing; toggle them "
        f"off/on afterwards if they don't re-attach on their own."
    )
    reload_proc = subprocess.run(
        ["sudo", "pfctl", "-f", str(_PF_CONF_PATH)],
        capture_output=True, text=True,
    )
    if reload_proc.returncode != 0:
        err_text = (reload_proc.stderr or reload_proc.stdout or "").strip()
        console.print(
            f"[red]Failed to reload pf:[/red] {err_text or 'pfctl -f returned non-zero'}"
        )
        console.print(
            "\nThe hook lines are written to /etc/pf.conf but won't take "
            "effect until pf is reloaded. Re-run `safeyolo setup pf` once "
            "the issue is resolved, or reboot."
        )
        raise typer.Exit(1)
    console.print("  [green]OK[/green]  pf reloaded — anchor hook is now active")

    console.print(
        f"\n[green]pf anchor hook installed.[/green] "
        f"SafeYolo will manage {_PF_ANCHORS_DIR / anchor} only."
    )
