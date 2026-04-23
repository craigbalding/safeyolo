"""Setup commands for SafeYolo system integration."""

import os
import platform as _platform
import re as _re
import subprocess
from pathlib import Path

import typer
from rich.console import Console

from ..vm import check_guest_images, missing_guest_images

console = Console()

_VALID_USERNAME = _re.compile(r"^[a-z_][a-z0-9_-]*$")

# AppArmor profile paths. The template ships with the installed CLI package;
# `safeyolo setup apparmor` copies it to /etc/apparmor.d/ and asks the
# kernel to load it via apparmor_parser -r. Ubuntu 24.04+ ships with
# kernel.apparmor_restrict_unprivileged_userns=1, which blocks the
# unprivileged user namespace runsc needs unless this profile is present.
_APPARMOR_TEMPLATE = Path(__file__).parent.parent / "templates" / "apparmor-safeyolo-runsc"
_APPARMOR_DEST = Path("/etc/apparmor.d/safeyolo-runsc")

setup_app = typer.Typer(
    name="setup",
    help="Apply system prerequisites for SafeYolo agent sandboxes.",
    no_args_is_help=False,
    invoke_without_command=True,
)


def _install_apparmor_profile() -> bool:
    """Stage the AppArmor profile and load it via apparmor_parser -r.

    Returns True on success (profile loaded, functional probe passes),
    False on any failure. Idempotent: re-running when the profile is
    already loaded still succeeds (apparmor_parser -r replaces in place).

    Writes /etc/apparmor.d/safeyolo-runsc via `sudo tee`. Callers SHOULD
    surface intent (the file path + the reason sudo is needed) before
    calling this so the sudo prompt isn't surprising.
    """
    if not _APPARMOR_TEMPLATE.exists():
        console.print(f"  [red]FAIL[/red]  AppArmor template missing: {_APPARMOR_TEMPLATE}")
        return False

    content = _APPARMOR_TEMPLATE.read_text()
    try:
        subprocess.run(
            ["sudo", "tee", str(_APPARMOR_DEST)],
            input=content.encode(),
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["sudo", "chmod", "0644", str(_APPARMOR_DEST)],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["sudo", "apparmor_parser", "-r", str(_APPARMOR_DEST)],
            check=True, capture_output=True,
        )
    except FileNotFoundError as err:
        console.print(f"  [red]FAIL[/red]  Required tool missing: {err}")
        console.print("    Debian/Ubuntu: [bold]sudo apt-get install sudo apparmor apparmor-utils[/bold]")
        return False
    except subprocess.CalledProcessError as err:
        stderr = (err.stderr.decode(errors="replace").strip()
                  if err.stderr else "")
        console.print(f"  [red]FAIL[/red]  AppArmor install failed: {stderr or err}")
        return False

    # Probe: profile actually loaded and usable?
    from ..platform.linux import has_apparmor_profile
    if not has_apparmor_profile():
        console.print("  [red]FAIL[/red]  Profile installed but aa-exec probe failed.")
        return False
    return True


def _apply_kvm_udev_rule(udev_path: Path, udev_rule: str) -> bool:
    """Install the /dev/kvm udev rule and apply the ACL immediately.

    Idempotent: re-running when the rule file already exists re-applies
    the setfacl so the ACL takes effect without requiring a reboot.
    """
    try:
        subprocess.run(
            ["sudo", "tee", str(udev_path)],
            input=udev_rule.encode(),
            capture_output=True, check=True,
        )
        subprocess.run(
            ["sudo", "setfacl", "-m", "u:100000:rw", "/dev/kvm"],
            capture_output=True, check=True,
        )
        return True
    except FileNotFoundError as err:
        console.print(f"  [red]FAIL[/red]  Required tool missing: {err}")
        return False
    except subprocess.CalledProcessError as err:
        stderr = (err.stderr.decode(errors="replace").strip()
                  if err.stderr else "")
        console.print(f"  [red]FAIL[/red]  KVM udev install failed: {stderr or err}")
        return False


def _announce_linux_sudo_changes(need_apparmor: bool, need_kvm: bool,
                                 udev_path: Path) -> None:
    """Tell the user exactly what `sudo` will touch on Linux, before we ask
    them for their password. Only items actually required are listed."""
    if not (need_apparmor or need_kvm):
        return

    console.print("\n[bold]`safeyolo setup` needs sudo to apply the following:[/bold]")
    if need_apparmor:
        console.print(
            f"  • [bold]AppArmor profile[/bold]\n"
            f"      write   {_APPARMOR_DEST}\n"
            f"      reload  apparmor_parser -r {_APPARMOR_DEST}\n"
            f"      Why: Ubuntu 24.04+ blocks unprivileged user namespaces by\n"
            f"      default, which breaks rootless gVisor; this profile allows them\n"
            f"      only for /usr/local/bin/runsc."
        )
    if need_kvm:
        console.print(
            f"  • [bold]KVM access[/bold]\n"
            f"      write   {udev_path}\n"
            f"      apply   setfacl -m u:100000:rw /dev/kvm\n"
            f"      Why: gVisor's sandbox uid 100000 needs /dev/kvm to use the KVM\n"
            f"      platform (hardware isolation). Falls back to systrap without it."
        )
    console.print()


@setup_app.callback(invoke_without_command=True)
def setup() -> None:
    """Apply system prerequisites for SafeYolo agent sandboxes.

    Checks what's needed, announces which sudo-privileged changes are
    about to be made and why, then applies them idempotently. Safe to
    re-run.

    Linux installs (only when missing):

      - AppArmor profile at /etc/apparmor.d/safeyolo-runsc, loaded via
        `apparmor_parser -r`.
      - udev rule at /etc/udev/rules.d/99-safeyolo-kvm.rules + immediate
        setfacl on /dev/kvm (for KVM hardware isolation).

    macOS verifies the Swift VM helper only; no sudo-level changes.

    Examples:

        safeyolo setup
    """
    console.print("[bold]Checking prerequisites...[/bold]\n")

    all_ok = True

    # Guest images (platform-aware: Linux needs EROFS, macOS needs ext4+kernel+initramfs).
    if check_guest_images():
        console.print("  [green]OK[/green]  Guest images available")
    else:
        missing = missing_guest_images()
        console.print(f"  [red]MISSING[/red]  Guest images: {', '.join(missing)}")
        console.print("    Build with: cd guest && ./build-all.sh")
        console.print("    Install:    cp guest/out/* ~/.safeyolo/share/")
        if "rootfs-erofs" in missing:
            console.print("    [dim](erofs-utils is required on the build host: sudo apt-get install erofs-utils)[/dim]")
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

        # User namespace prerequisites (purely diagnostic)
        userns = check_userns_prerequisites()
        if not userns["setfacl"]:
            console.print("  [red]MISSING[/red]  setfacl (required for rootless rootfs ACL)")
            console.print("    Debian/Ubuntu: [bold]sudo apt-get install acl[/bold]")
            all_ok = False

        # --- Decide what needs applying before touching sudo ---
        kvm = detect_runsc_platform()
        kvm_udev_rule = 'KERNEL=="kvm", RUN+="/usr/bin/setfacl -m u:100000:rw /dev/kvm"'
        kvm_udev_path = Path("/etc/udev/rules.d/99-safeyolo-kvm.rules")

        need_apparmor = (
            userns["apparmor_restricts"]
            and not userns["apparmor_profile_loaded"]
        )
        # Install the KVM rule if /dev/kvm is usable by the operator but not
        # yet by the sandbox subordinate uid.
        need_kvm = (
            kvm["kvm_exists"]
            and kvm["kvm_operator_access"]
            and not kvm["kvm_subordinate_access"]
        )

        # AppArmor: report current state before/after
        if userns["apparmor_restricts"]:
            if userns["apparmor_profile_loaded"]:
                console.print("  [green]OK[/green]  AppArmor profile (safeyolo-runsc)")
            else:
                console.print("  [yellow]SETUP[/yellow]  AppArmor profile needs installation")
        else:
            console.print("  [dim]INFO[/dim]  AppArmor does not restrict userns here — profile not required")

        # KVM: report current state before/after
        if kvm["platform"] == "kvm":
            console.print("  [green]OK[/green]  KVM platform (hardware isolation)")
        elif not kvm["kvm_exists"]:
            console.print("  [dim]INFO[/dim]  /dev/kvm not available — using systrap (software isolation)")
            console.print("    Coding agent performance is equivalent. Hardware isolation")
            console.print("    (KVM) is available on hosts with virtualization enabled.")
        elif kvm["kvm_operator_access"] and not kvm["kvm_subordinate_access"]:
            console.print("  [yellow]SETUP[/yellow]  KVM available — installing udev rule for sandbox access")
        else:
            console.print("  [dim]INFO[/dim]  /dev/kvm exists but not accessible — using systrap")

        # --- Announce + apply ---
        _announce_linux_sudo_changes(need_apparmor, need_kvm, kvm_udev_path)

        if need_apparmor:
            if _install_apparmor_profile():
                console.print("  [green]OK[/green]  AppArmor profile (safeyolo-runsc) installed and loaded")
            else:
                all_ok = False

        if need_kvm:
            if _apply_kvm_udev_rule(kvm_udev_path, kvm_udev_rule):
                console.print("  [green]OK[/green]  KVM udev rule installed and ACL applied")
            else:
                console.print("    Manual fix:")
                console.print(f'    [bold]echo \'{kvm_udev_rule}\' | sudo tee {kvm_udev_path}[/bold]')
                console.print("    [bold]sudo setfacl -m u:100000:rw /dev/kvm[/bold]")
                all_ok = False
    else:
        console.print(f"  [yellow]WARN[/yellow]  unsupported platform {system!r}: skipping runtime checks")

    if all_ok:
        console.print("\n[green]All prerequisites met.[/green]")
    else:
        console.print("\n[yellow]Some prerequisites missing — see above.[/yellow]")


@setup_app.command()
def apparmor() -> None:
    """Install the SafeYolo AppArmor profile for runsc.

    Copies the bundled profile to /etc/apparmor.d/safeyolo-runsc and asks
    the kernel to load it via `apparmor_parser -r`. Idempotent. Announces
    the exact changes + reason for sudo before prompting.

    This runs as part of `safeyolo setup`; run this subcommand directly if
    you only want to (re)apply the AppArmor piece.
    """
    if _platform.system() != "Linux":
        console.print("[yellow]AppArmor setup is Linux-only. Skipping.[/yellow]")
        raise typer.Exit(0)

    console.print(
        "\n[bold]Installing SafeYolo AppArmor profile (requires sudo).[/bold]\n"
        f"  write   {_APPARMOR_DEST}\n"
        f"  reload  apparmor_parser -r {_APPARMOR_DEST}\n"
        "  Why: Ubuntu 24.04+ blocks unprivileged user namespaces by default,\n"
        "  which breaks rootless gVisor; this profile allows them only for\n"
        "  /usr/local/bin/runsc.\n"
    )
    if not _install_apparmor_profile():
        raise typer.Exit(1)
    console.print("[green]AppArmor profile (safeyolo-runsc) installed and loaded.[/green]")


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
