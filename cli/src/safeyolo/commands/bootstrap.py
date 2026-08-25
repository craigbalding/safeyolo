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
import json
import os
import platform as _platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

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


# Ubuntu / Debian package names required by `safeyolo build` on Linux.
# skopeo + umoci: pull + unpack the debian OCI image used for the guest rootfs.
# mmdebstrap + debootstrap: fallback rootfs build path.
# acl: setfacl on /dev/kvm for the subordinate uid (gVisor KVM platform).
# jq: used by helper scripts and by this bootstrap for JSON emission.
LINUX_BUILD_APT_DEPS = (
    "skopeo", "umoci", "mmdebstrap", "debootstrap", "acl", "jq",
)


def _missing_apt_deps() -> list[str]:
    """Return LINUX_BUILD_APT_DEPS entries not installed. Empty on non-apt hosts."""
    if _platform.system() != "Linux":
        return []
    if not shutil.which("dpkg"):
        return []
    missing: list[str] = []
    for pkg in LINUX_BUILD_APT_DEPS:
        r = subprocess.run(
            ["dpkg-query", "-W", "-f=${Status}", pkg],
            capture_output=True, text=True,
        )
        if r.returncode != 0 or "install ok installed" not in r.stdout:
            missing.append(pkg)
    return missing


def _needs_init() -> bool:
    """True when the config dir hasn't been initialised yet."""
    cfg = get_config_dir()
    return not (cfg / "policy.toml").exists()


def _needs_build() -> bool:
    """True when the guest rootfs tree is missing."""
    return not check_guest_images()


def _needs_setup() -> bool:
    """True when AppArmor profile or /dev/kvm ACL is missing on Linux; always False on macOS.

    On a truly bare host the `acl` package (which provides `getfacl`) may not
    be installed yet. In that case we can't inspect the /dev/kvm ACL, but we
    definitely need setup to run (setup will install `acl` as part of its
    Linux runtime-packages step). Return True in that case.
    """
    if _platform.system() != "Linux":
        return False
    apparmor_missing = not Path("/etc/apparmor.d/safeyolo-runsc").exists()
    kvm_acl_missing = True
    if shutil.which("getfacl") and Path("/dev/kvm").exists():
        r = subprocess.run(
            ["getfacl", "-p", "/dev/kvm"], capture_output=True, text=True,
        )
        if r.returncode == 0 and "user:100000" in r.stdout:
            kvm_acl_missing = False
    # If getfacl is missing, kvm_acl_missing stays True — setup needs to run
    # (it'll apt-install acl as part of the Linux runtime packages step).
    return apparmor_missing or kvm_acl_missing


def _print_missing_deps_hint(missing: list[str]) -> None:
    console.print("[red]Missing build prerequisites:[/red] " + ", ".join(missing))
    console.print()
    console.print("Install with:")
    console.print(f"  [bold]sudo apt-get install -y {' '.join(missing)}[/bold]")
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
    missing_deps = _missing_apt_deps()

    if check:
        result = {
            "check": True,
            "would_run": [k for k, v in plan.items() if v],
            "already_done": [k for k, v in plan.items() if not v],
            "missing_apt_deps": missing_deps,
        }
        if json_out:
            _emit_json(result)
        else:
            console.print("[bold]bootstrap plan:[/bold]")
            console.print(f"  would run:    {result['would_run'] or '(none — already bootstrapped)'}")
            console.print(f"  already done: {result['already_done']}")
            if missing_deps:
                console.print(f"  [red]blocked on missing apt deps:[/red] {missing_deps}")
        needs_work = bool(result["would_run"]) or bool(missing_deps)
        raise typer.Exit(1 if needs_work else 0)

    # Preflight: refuse to start if build is needed AND OS deps are missing.
    # Init/setup can proceed without them, but running build with deps missing
    # produces an ugly failure mid-run — better to surface it up-front.
    if plan["build"] and missing_deps:
        if json_out:
            _emit_json({
                "status": "blocked",
                "reason": "missing_apt_deps",
                "missing_apt_deps": missing_deps,
                "steps_run": [],
                "steps_skipped": [k for k, v in plan.items() if not v],
                "duration_ms": int((time.monotonic() - t0) * 1000),
            })
        else:
            _print_missing_deps_hint(missing_deps)
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
        "missing_apt_deps": missing_deps,
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
