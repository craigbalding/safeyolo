"""safeyolo bootstrap - one-command first-run setup.

Runs the sequence a new user needs after `./install.sh`: preflight OS
package check, then init -> build -> setup, skipping steps whose end-state
is already present.

Design rules:

- Idempotent. Safe to re-run at any time; skips work whose end-state is
  already in place (see `_needs_*` helpers).
- Never auto-installs OS packages. Preflight names the missing set as a
  single ready-to-paste `sudo apt install ...` line and exits non-zero.
  Respect operator privilege boundary; the human decides when to sudo.
- Machine-parseable output via ``--json`` so acceptance harnesses can
  assert on structured state instead of grepping rich console output.
- Progress lines are strictly informational; step outcomes go through
  ``console.print`` so an operator watching sees what happened.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import platform as _platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import typer
from rich.console import Console

from ..config import get_config_dir
from ..vm import check_guest_images

console = Console()


@contextlib.contextmanager
def _stdout_to_stderr():
    """Redirect fd 1 to fd 2 for the duration of the block.

    Used by --json mode so that inner sub-commands (init/build/setup) which
    write to stdout via their own rich Consoles don't leak human text into
    the JSON output stream. Operates at the file-descriptor level so it
    catches subprocess output and rich Consoles whose file handle was
    captured at import time.
    """
    stdout_fd = 1
    saved = os.dup(stdout_fd)
    try:
        os.dup2(2, stdout_fd)
        yield
    finally:
        # Ensure Python's buffered writes to stdout land in stderr, then restore.
        sys.stdout.flush()
        os.dup2(saved, stdout_fd)
        os.close(saved)


# Guest-build prerequisites, per Linux package manager (#353).
#
# apt (Ubuntu / Debian):
#   skopeo + umoci: pull + unpack the debian OCI image used for the guest rootfs.
#   mmdebstrap + debootstrap: fallback rootfs build path.
#   acl: setfacl on /dev/kvm for the subordinate uid (gVisor KVM platform).
#   jq: used by helper scripts and by this bootstrap for JSON emission.
#   rsync: `safeyolo build` invokes `sudo rsync -aHAX --numeric-ids --delete ...`
#     to install the rootfs tree into ~/.safeyolo/share/ preserving ownership.
#   tmux: `safeyolo start` runs the mitmproxy master inside a private tmux
#     session (see traffic_session.py).
#
# dnf (Fedora / RHEL): no mmdebstrap (Debian-only); everything else in
# standard Fedora repos. debootstrap is available for Debian rootfs builds.
#
# apk (Alpine): no mmdebstrap; umoci lives in the community repository.
#
# pacman (Arch): no mmdebstrap; umoci and debootstrap are in AUR (the
# operator will need an AUR helper — flagged in the install hint).
LINUX_BUILD_APT_DEPS = (
    "skopeo", "umoci", "mmdebstrap", "debootstrap", "acl", "jq", "rsync", "tmux",
)

# umoci is intentionally NOT in dnf / apk / pacman: it doesn't ship in the
# default Fedora / RHEL / Alpine main / Arch core repos. `_ensure_umoci()`
# handles it explicitly (PATH → SafeYolo bin dir → pinned upstream download)
# so operators on those distros aren't forced into COPR / testing repo /
# AUR to make `safeyolo build` work.
LINUX_BUILD_DEPS = {
    "apt":    LINUX_BUILD_APT_DEPS,
    "dnf":    ("skopeo", "debootstrap", "acl", "jq", "rsync", "tmux"),
    "apk":    ("skopeo", "debootstrap", "acl", "jq", "rsync", "tmux"),
    "pacman": ("skopeo", "debootstrap", "acl", "jq", "rsync", "tmux"),
}

# Pinned upstream umoci for hosts whose package manager doesn't have it.
# Update by fetching the latest release + sha256sum file from
# https://github.com/opencontainers/umoci/releases (both amd64 and arm64
# rows). Never install without verifying the sha256.
_UMOCI_VERSION = "v0.6.0"
_UMOCI_SHA256 = {
    "amd64": "b51c267ec394499e42c6fde47f240b7b7dba57ea49df0b5acd304378b82a3b71",
    "arm64": "5cfd17f2e7a4bcf9ed67ea1b955ca893d200349b9ce6a3d3707dba415f458a1f",
}
# Package managers whose native repos ship a usable umoci. Anywhere else
# falls through to the pinned-binary download.
_UMOCI_NATIVE_PACKAGE_MANAGERS = frozenset({"apt"})


def _safeyolo_bin_dir() -> Path:
    """SafeYolo-managed bin dir: ~/.safeyolo/bin/ (init/lifecycle already
    ensure it exists)."""
    return get_config_dir() / "bin"


def _prepend_safeyolo_bin_to_path() -> None:
    """Make ``~/.safeyolo/bin/`` the first PATH entry for this process and
    any child subprocesses (``safeyolo build``, rootfs scripts, …). Cheap
    and idempotent — if the dir is already the first entry, no-op."""
    sy_bin = str(_safeyolo_bin_dir())
    current = os.environ.get("PATH", "")
    parts = current.split(os.pathsep) if current else []
    if parts and parts[0] == sy_bin:
        return
    parts = [sy_bin] + [p for p in parts if p != sy_bin]
    os.environ["PATH"] = os.pathsep.join(parts)


def _umoci_host_arch() -> str | None:
    """Map the current `platform.machine()` to an umoci asset arch key, or
    None if we don't ship a pinned binary for it."""
    m = _platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "amd64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    return None


def _ensure_umoci(pm: str | None) -> dict:
    """Resolve umoci for `safeyolo build` per the algorithm:

    1. If ``umoci`` is on PATH → use it (nothing to do).
    2. Elif ``~/.safeyolo/bin/umoci`` exists+executable → use it (add the
       dir to PATH for child processes; nothing to install).
    3. Elif the distro's package manager ships a usable umoci
       (``_UMOCI_NATIVE_PACKAGE_MANAGERS``) → return ``needs_native``;
       ``_missing_deps()`` will surface it as a normal dep and the
       operator installs via their package manager.
    4. Else → download the pinned upstream binary, verify sha256, install
       to ``~/.safeyolo/bin/umoci``.

    Returns a small dict for the JSON payload:
      ``{"state": "on_path"|"safeyolo_bin"|"needs_native"|"installed"|"unsupported_arch",
         "path": "<resolved path or empty>",
         "version": "<pinned or empty>",
         "reason": "<optional detail>"}``

    Never invoked on non-Linux hosts.
    """
    # (1) already on PATH — do nothing
    on_path = shutil.which("umoci")
    if on_path:
        return {"state": "on_path", "path": on_path, "version": ""}

    # (2) SafeYolo-managed bin dir
    safeyolo_umoci = _safeyolo_bin_dir() / "umoci"
    if safeyolo_umoci.exists() and os.access(safeyolo_umoci, os.X_OK):
        return {"state": "safeyolo_bin", "path": str(safeyolo_umoci), "version": _UMOCI_VERSION}

    # (3) apt ships a native umoci — let the operator install via package manager
    if pm in _UMOCI_NATIVE_PACKAGE_MANAGERS:
        return {"state": "needs_native", "path": "", "version": ""}

    # (4) download pinned upstream binary
    arch = _umoci_host_arch()
    if arch is None:
        return {
            "state": "unsupported_arch",
            "path": "",
            "version": _UMOCI_VERSION,
            "reason": f"no pinned umoci for {_platform.machine()!r}",
        }

    url = (
        "https://github.com/opencontainers/umoci/releases/download/"
        f"{_UMOCI_VERSION}/umoci.linux.{arch}"
    )
    expected_sha = _UMOCI_SHA256[arch]

    dest_dir = _safeyolo_bin_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        # NOTE: not piping curl-to-shell — we download to a temp file, verify
        # sha256, then os.replace() into place. That's the only safe pattern
        # for pinned binaries.
        with tempfile.NamedTemporaryFile(
            "wb", dir=dest_dir, prefix=".umoci.", suffix=".partial", delete=False,
        ) as tmp:
            with urlopen(url) as resp:  # noqa: S310 (trusted-vendor URL, pinned checksum)
                shutil.copyfileobj(resp, tmp)
            tmp_path = Path(tmp.name)
    except URLError as e:
        return {
            "state": "download_failed",
            "path": "",
            "version": _UMOCI_VERSION,
            "reason": f"could not fetch {url}: {e}",
        }

    got_sha = hashlib.sha256(tmp_path.read_bytes()).hexdigest()
    if got_sha != expected_sha:
        tmp_path.unlink(missing_ok=True)
        return {
            "state": "sha_mismatch",
            "path": "",
            "version": _UMOCI_VERSION,
            "reason": f"expected {expected_sha}, got {got_sha}",
        }

    tmp_path.chmod(0o755)
    os.replace(tmp_path, safeyolo_umoci)
    return {"state": "installed", "path": str(safeyolo_umoci), "version": _UMOCI_VERSION}


def _detect_package_manager() -> str | None:
    """Return "apt" | "dnf" | "apk" | "pacman" for the current Linux host,
    or None if none detected (unknown distro or non-Linux).

    We key on ``/etc/os-release``'s ``ID`` / ``ID_LIKE`` first so we pick
    the *native* package manager for the distro, not whichever query tool
    happens to be on PATH. That matters after `bootstrap` installs
    `debootstrap` on Fedora / Alpine / Arch — debootstrap pulls `dpkg`
    (needed to bootstrap Debian rootfs), which puts `dpkg-query` on PATH
    of a non-apt host. Without the os-release check we'd start
    reporting `package_manager=apt` on a Fedora box that just installed
    debootstrap, and the next bootstrap run would produce a bogus
    ``sudo apt-get install …`` line. Falls back to tool detection when
    os-release is missing or has no recognised ID.
    """
    if _platform.system() != "Linux":
        return None

    ids: set[str] = set()
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                key, _, value = line.strip().partition("=")
                if key in ("ID", "ID_LIKE"):
                    ids.update(v.strip().strip('"') for v in value.strip('"').split())
    except OSError:
        pass

    # Debian family
    if {"debian", "ubuntu"} & ids and shutil.which("dpkg-query"):
        return "apt"
    # RHEL family (fedora, rhel, centos, rocky, almalinux, ...)
    if {"fedora", "rhel", "centos"} & ids and shutil.which("rpm"):
        return "dnf"
    # Alpine
    if "alpine" in ids and shutil.which("apk"):
        return "apk"
    # Arch family
    if {"arch"} & ids and shutil.which("pacman"):
        return "pacman"

    # Fallback for hosts without a recognised /etc/os-release ID: probe
    # the query tools in the historical order.
    for tool, name in (
        ("dpkg-query", "apt"),
        ("rpm",        "dnf"),
        ("apk",        "apk"),
        ("pacman",     "pacman"),
    ):
        if shutil.which(tool):
            return name
    return None


def _package_installed(pm: str, pkg: str) -> bool:
    """True if `pkg` is installed under package manager `pm`."""
    if pm == "apt":
        r = subprocess.run(
            ["dpkg-query", "-W", "-f=${Status}", pkg],
            capture_output=True, text=True,
        )
        return r.returncode == 0 and "install ok installed" in r.stdout
    if pm == "dnf":
        return subprocess.run(
            ["rpm", "-q", pkg], capture_output=True, text=True,
        ).returncode == 0
    if pm == "apk":
        return subprocess.run(
            ["apk", "info", "-e", pkg], capture_output=True, text=True,
        ).returncode == 0
    if pm == "pacman":
        return subprocess.run(
            ["pacman", "-Q", pkg], capture_output=True, text=True,
        ).returncode == 0
    return True  # unknown pm: no way to tell → assume present so we don't block


def _install_command(pm: str, missing: list[str]) -> str:
    """Render the operator-ready install command for the detected manager."""
    pkgs = " ".join(missing)
    if pm == "apt":
        return f"sudo apt-get install -y {pkgs}"
    if pm == "dnf":
        return f"sudo dnf install -y {pkgs}"
    if pm == "apk":
        return f"sudo apk add {pkgs}"
    if pm == "pacman":
        # debootstrap is in AUR on Arch; flag it so the operator knows
        # why a plain `pacman -S` won't cover it. (umoci is not in this
        # list at all — `_ensure_umoci()` handles it via the pinned
        # upstream binary.)
        return (
            f"sudo pacman -S --needed {pkgs}"
            "   # NOTE: debootstrap is AUR — install via your AUR helper"
        )
    return f"# unknown package manager; install: {pkgs}"


def _missing_deps() -> tuple[list[str], str | None]:
    """Return (missing packages, detected package manager).

    Empty list on non-Linux hosts and on unknown package managers (in the
    latter case bootstrap won't refuse — but the operator sees the
    detected manager as None in the JSON output).
    """
    pm = _detect_package_manager()
    if pm is None:
        return [], None
    deps = LINUX_BUILD_DEPS.get(pm, ())
    missing = [pkg for pkg in deps if not _package_installed(pm, pkg)]
    return missing, pm


def _missing_apt_deps() -> list[str]:
    """Back-compat wrapper: return the apt-side missing list only.

    Kept because some tests import it by name; prefer `_missing_deps()`
    in new code.
    """
    missing, pm = _missing_deps()
    return missing if pm == "apt" else []


def _needs_init() -> bool:
    """True when the config dir hasn't been initialised yet."""
    cfg = get_config_dir()
    return not (cfg / "policy.toml").exists()


def _needs_build() -> bool:
    """True when the guest rootfs tree is missing."""
    return not check_guest_images()


def _needs_setup() -> bool:
    """True when the Linux host needs `safeyolo setup` to run.

    On macOS: always False (no runsc / no AppArmor).

    On Linux, setup is needed when any of these hold:
      * runsc isn't installed
      * newuidmap / newgidmap / setfacl aren't available
      * AppArmor is restricting unprivileged userns AND the
        SafeYolo profile isn't loaded (distros without AppArmor —
        Fedora, Arch, Alpine, etc. — never trigger this)
      * KVM is present and usable by the operator but the /dev/kvm ACL
        for the subordinate uid is missing.

    Historically the AppArmor check was "does
    /etc/apparmor.d/safeyolo-runsc exist" — always False on Fedora /
    Arch / Alpine, wrongly forcing setup to run every time on those
    hosts. Ask whether AppArmor actually restricts userns instead
    (`check_userns_prerequisites` handles the introspection).
    """
    if _platform.system() != "Linux":
        return False

    # Deferred import — platform.linux imports safeyolo config which
    # imports commands, so bringing it in at module load creates a cycle
    # on some import orderings.
    from ..platform.linux import (
        check_userns_prerequisites,
        detect_runsc_platform,
        find_runsc,
    )

    if find_runsc() is None:
        return True

    userns = check_userns_prerequisites()
    if not (
        userns["newuidmap"]
        and userns["newgidmap"]
        and userns["subuid"]
        and userns["subgid"]
        and userns["setfacl"]
    ):
        return True
    if userns["apparmor_restricts"] and not userns["apparmor_profile_loaded"]:
        return True

    kvm = detect_runsc_platform()
    if (
        not kvm.get("forced")
        and kvm.get("kvm_exists")
        and kvm.get("kvm_operator_access")
        and not kvm.get("kvm_subordinate_access")
    ):
        return True

    return False


def _print_missing_deps_hint(missing: list[str], pm: str | None) -> None:
    console.print("[red]Missing build prerequisites:[/red] " + ", ".join(missing))
    console.print()
    console.print("Install with:")
    console.print(f"  [bold]{_install_command(pm or 'unknown', missing)}[/bold]")
    console.print()
    console.print("Then re-run: [bold]safeyolo bootstrap[/bold]")


def _emit_json(payload: dict) -> None:
    print(json.dumps(payload))


def bootstrap(  # DOC: README.md
    json_out: bool = typer.Option(
        False,
        "--json",
        help="Emit a single JSON object on stdout; suppress rich console.",
    ),
    check: bool = typer.Option(
        False,
        "--check",
        help="Report what would run without doing anything. Exits non-zero if any step is needed.",
    ),
) -> None:
    """One-command first-run setup: preflight + init + build + setup.

    Skips any step whose end-state is already present. Safe to re-run.
    Machine-parseable via --json.

    Examples:

        safeyolo bootstrap
        safeyolo bootstrap --check --json
    """
    t0 = time.monotonic()

    plan = {
        "init": _needs_init(),
        "build": _needs_build(),
        "setup": _needs_setup(),
    }
    missing_deps, package_manager = _missing_deps()
    # Back-compat for the harness scenario that reads .missing_apt_deps —
    # populated only when the detected manager is apt, empty otherwise.
    missing_apt_deps = missing_deps if package_manager == "apt" else []

    # umoci is resolved separately from the package-manager preflight
    # because dnf / apk / pacman don't ship it in their default repos.
    # `_ensure_umoci()` implements the operator-supplied algorithm:
    # PATH → SafeYolo bin dir → native package if the manager has one →
    # pinned upstream binary. On --check we probe without side effects
    # (so no download happens during check); on the real run we invoke
    # the resolver eagerly before build so umoci is on PATH when
    # `safeyolo build` starts.
    umoci_state: dict = {"state": "skipped", "path": "", "version": ""}
    if _platform.system() == "Linux":
        _prepend_safeyolo_bin_to_path()
        if check:
            # Non-side-effecting probe: report whether we'd need to
            # download, but do NOT download.
            on_path = shutil.which("umoci")
            sy_bin = _safeyolo_bin_dir() / "umoci"
            if on_path:
                umoci_state = {"state": "on_path", "path": on_path, "version": ""}
            elif sy_bin.exists() and os.access(sy_bin, os.X_OK):
                umoci_state = {"state": "safeyolo_bin", "path": str(sy_bin), "version": _UMOCI_VERSION}
            elif package_manager in _UMOCI_NATIVE_PACKAGE_MANAGERS:
                umoci_state = {"state": "needs_native", "path": "", "version": ""}
            else:
                umoci_state = {"state": "would_download", "path": str(sy_bin), "version": _UMOCI_VERSION}
        else:
            umoci_state = _ensure_umoci(package_manager)

    if check:
        result = {
            "check": True,
            "would_run": [k for k, v in plan.items() if v],
            "already_done": [k for k, v in plan.items() if not v],
            "package_manager": package_manager,
            "missing_deps": missing_deps,
            "install_command": (
                _install_command(package_manager, missing_deps)
                if missing_deps and package_manager else None
            ),
            "umoci": umoci_state,
            "missing_apt_deps": missing_apt_deps,
        }
        if json_out:
            _emit_json(result)
        else:
            console.print("[bold]bootstrap plan:[/bold]")
            console.print(f"  would run:    {result['would_run'] or '(none — already bootstrapped)'}")
            console.print(f"  already done: {result['already_done']}")
            if missing_deps:
                console.print(
                    f"  [red]blocked on missing deps ({package_manager}):[/red] {missing_deps}"
                )
            if umoci_state["state"] == "would_download":
                console.print(
                    f"  [yellow]umoci:[/yellow] would download pinned "
                    f"{umoci_state['version']} → {umoci_state['path']}"
                )
            elif umoci_state["state"] in ("on_path", "safeyolo_bin"):
                console.print(f"  [green]umoci:[/green] {umoci_state['state']} ({umoci_state['path']})")
        needs_work = bool(result["would_run"]) or bool(missing_deps)
        raise typer.Exit(1 if needs_work else 0)

    # Preflight: refuse to start if build is needed AND OS deps are missing.
    # Init/setup can proceed without them, but running build with deps missing
    # produces an ugly failure mid-run — better to surface it up-front.
    if plan["build"] and missing_deps:
        if json_out:
            _emit_json({
                "status": "blocked",
                "reason": "missing_deps",
                "package_manager": package_manager,
                "missing_deps": missing_deps,
                "install_command": _install_command(package_manager or "unknown", missing_deps),
                "missing_apt_deps": missing_apt_deps,
                "umoci": umoci_state,
                "steps_run": [],
                "steps_skipped": [k for k, v in plan.items() if not v],
                "duration_ms": int((time.monotonic() - t0) * 1000),
            })
        else:
            _print_missing_deps_hint(missing_deps, package_manager)
        raise typer.Exit(2)

    steps_run: list[str] = []
    steps_skipped: list[str] = []
    step_errors: dict[str, str] = {}

    # When --json, redirect subcommand stdout to stderr for the whole run so
    # human-facing rich output (from init/build/setup) doesn't corrupt the
    # single JSON line stdout will carry at the end.
    redirect_ctx = _stdout_to_stderr() if json_out else contextlib.nullcontext()

    with redirect_ctx:
        # init
        if plan["init"]:
            if not json_out:
                console.print("[bold]▶ safeyolo init[/bold]")
            from .init import init as _init
            try:
                _init(force=False, interactive=False)
                steps_run.append("init")
            except SystemExit as e:
                if e.code not in (0, None):
                    step_errors["init"] = f"exit={e.code}"
                    steps_run.append("init")
        else:
            steps_skipped.append("init")
            if not json_out:
                console.print("  [dim]init: already done[/dim]")

        # build
        if plan["build"]:
            if not json_out:
                console.print("[bold]▶ safeyolo build[/bold]  (may take several minutes on first run)")
            from .lifecycle import build as _build
            try:
                _build()
                steps_run.append("build")
            except SystemExit as e:
                if e.code not in (0, None):
                    step_errors["build"] = f"exit={e.code}"
                    steps_run.append("build")
        else:
            steps_skipped.append("build")
            if not json_out:
                console.print("  [dim]build: already done[/dim]")

        # setup (Linux only; on macOS _needs_setup always returns False so plan['setup'] is False)
        if plan["setup"]:
            if not json_out:
                console.print("[bold]▶ safeyolo setup[/bold]  (may prompt for sudo)")
            from .setup import setup as _setup
            try:
                _setup()
                steps_run.append("setup")
            except SystemExit as e:
                if e.code not in (0, None):
                    step_errors["setup"] = f"exit={e.code}"
                    steps_run.append("setup")
        else:
            steps_skipped.append("setup")
            if not json_out:
                console.print("  [dim]setup: already done[/dim]")

    duration_ms = int((time.monotonic() - t0) * 1000)
    status = "ok" if not step_errors else "partial"

    payload = {
        "status": status,
        "steps_run": steps_run,
        "steps_skipped": steps_skipped,
        "step_errors": step_errors,
        "package_manager": package_manager,
        "missing_deps": missing_deps,
        "missing_apt_deps": missing_apt_deps,
        "umoci": umoci_state,
        "duration_ms": duration_ms,
    }

    if json_out:
        _emit_json(payload)
    else:
        console.print()
        if status == "ok":
            console.print(f"[green]bootstrap complete[/green] in {duration_ms/1000:.1f}s")
            console.print(f"  ran:     {steps_run or '(nothing — already bootstrapped)'}")
            if steps_skipped:
                console.print(f"  skipped: {steps_skipped}")
            console.print()
            console.print("Next: [bold]safeyolo agent add[/bold] [italic]<name>[/italic] [italic]<dir>[/italic] --host-script [italic]<path>[/italic]")
        else:
            console.print(f"[yellow]bootstrap partial[/yellow] ({duration_ms/1000:.1f}s) — see errors above.")
            console.print(f"  errors: {step_errors}")

    if step_errors:
        raise typer.Exit(1)
