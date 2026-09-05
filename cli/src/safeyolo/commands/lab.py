"""First-class operator entry point for SafeYolo experimentation labs."""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.markup import escape

from ..agents_store import load_all_agents, mutate_agent
from ..config import find_config_dir, get_agents_dir, get_config_dir
from ..vm import get_agent_home_dir

console = Console()

LAB_SCHEMA = 1
LAB_BACKENDS = {"codex"}
LAB_SESSION = "lab"
LAB_STATE_NAME = "lab-state.json"
LAB_EVIDENCE_ROOT = "/home/agent/.safeyolo/lab-evidence"
LAB_DIAGNOSTIC_MAX_LENGTH = 512
LAB_NAME_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
LAB_STATUS_FIELDS = ("session_exists", "owned", "controller_alive")
LAB_STATUS_STATES = {
    (False, False, False): "absent",
    (True, False, False): "unowned",
    (True, True, False): "controller-dead",
    (True, True, True): "owned",
}


def is_lab_managed(metadata: dict[str, Any]) -> bool:
    """Return whether metadata explicitly opts an agent into Lab ownership."""
    return metadata.get("lab_managed") is True


def is_compatible_lab(metadata: dict[str, Any], backend: str = "codex") -> bool:
    """Return whether an explicitly managed agent can run the Lab backend."""
    if not is_lab_managed(metadata):
        return False
    if metadata.get("lab_schema") != LAB_SCHEMA:
        return False
    if metadata.get("lab_backend") != backend or backend not in LAB_BACKENDS:
        return False

    host_script = str(metadata.get("host_script", ""))
    return host_script in {"@codex", "codex"} or Path(host_script).name == "codex-host-setup.sh"


def _is_safe_name(name: str) -> bool:
    return bool(LAB_NAME_PATTERN.fullmatch(name))


def _lab_candidates(backend: str) -> list[tuple[str, dict[str, Any]]]:
    return sorted(
        (
            (name, metadata)
            for name, metadata in load_all_agents().items()
            if _is_safe_name(name)
            and isinstance(metadata, dict)
            and is_compatible_lab(metadata, backend)
        ),
        key=lambda item: item[0],
    )


def _proposed_name() -> str:
    """Choose a deterministic unused name without touching existing agents."""
    configured = load_all_agents()
    agents_dir = get_agents_dir()
    agent_dirs = {path.name for path in agents_dir.iterdir()} if agents_dir.is_dir() else set()
    base = "safeyolo-lab"
    if base not in configured and base not in agent_dirs:
        return base
    suffix = 2
    while f"{base}-{suffix}" in configured or f"{base}-{suffix}" in agent_dirs:
        suffix += 1
    return f"{base}-{suffix}"


def _state_path(name: str) -> Path:
    if not _is_safe_name(name):
        raise ValueError("invalid Lab agent name")
    return get_config_dir() / "labs" / name / LAB_STATE_NAME


def _write_state(name: str, state: dict[str, Any]) -> Path:
    """Atomically persist the Lab record inside its managed agent home."""
    destination = _state_path(name)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination.parent.chmod(0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{LAB_STATE_NAME}.", dir=destination.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(state, stream, ensure_ascii=False, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            # Publication may already have moved the temporary file.
            pass
        raise
    return destination


def _read_state(name: str) -> dict[str, Any]:
    path = _state_path(name)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _new_state(name: str, workspace: Path, backend: str, objective: str) -> dict[str, Any]:
    return {
        "schema": LAB_SCHEMA,
        "agent": name,
        "backend": backend,
        "session": LAB_SESSION,
        "workspace": str(workspace),
        "objective": objective,
        "pass_signal": (
            "Capture evidence before interpretation, then restore the baseline "
            "and prove the same path again."
        ),
        "forbidden_actions": [
            "Do not weaken the outer SafeYolo boundary.",
            "Do not capture credential values.",
            "Do not adopt an unrelated agent, session, or controller.",
        ],
        "evidence_root": LAB_EVIDENCE_ROOT,
        "recovery": f"safeyolo lab --agent {name} --recover",
        "teardown_authority": (
            "Lab-owned guest session, controller, agent, and evidence root only; "
            "retention and deletion remain separate choices."
        ),
        "phase": "prepared",
    }


def _select_agent(
    requested: str | None,
    backend: str,
    *,
    allow_none: bool = False,
) -> tuple[str, dict[str, Any]] | None:
    candidates = _lab_candidates(backend)
    if requested:
        metadata = load_all_agents().get(requested)
        if not _is_safe_name(requested) or not isinstance(metadata, dict) or not is_compatible_lab(metadata, backend):
            console.print(
                f"[red]Agent '{escape(requested)}' is not an explicitly Lab-managed "
                f"compatible {backend} agent.[/red]"
            )
            console.print(
                "Lab never broadens an existing agent's scope. Create a new Lab "
                "agent or select an agent marked as Lab-managed."
            )
            raise typer.Exit(1)
        return requested, metadata

    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        if allow_none:
            return None
        return None

    console.print("Multiple compatible Lab agents are available:")
    for index, (name, metadata) in enumerate(candidates, 1):
        console.print(f"  {index}. {name} — {metadata.get('folder', '(unknown workspace)')}")
    choice = typer.prompt("Select a Lab agent", type=int)
    if choice < 1 or choice > len(candidates):
        console.print("[red]The Lab agent selection is out of range.[/red]")
        raise typer.Exit(1)
    return candidates[choice - 1]


def _guest_status(platform: Any, name: str) -> tuple[dict[str, Any], str]:
    """Read the guest-owned status record without attaching to its session."""
    process = platform.popen_in_sandbox(name, "safeyolo-lab --status --json", user="agent")
    try:
        stdout, stderr = process.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        _reap_timed_out_process(process)
        return {}, "Lab status did not complete before the 30 second deadline."
    output = stdout or ""
    try:
        value = json.loads(output.strip())
    except (TypeError, json.JSONDecodeError):
        return {}, _bounded_diagnostic(stderr or output, "The guest returned no Lab status.")
    if not isinstance(value, dict):
        return {}, "The guest returned an invalid Lab status object."
    return value, _bounded_diagnostic(stderr, "")


def _bounded_diagnostic(value: str, fallback: str) -> str:
    detail = " ".join((value or "").split())
    return (detail[:LAB_DIAGNOSTIC_MAX_LENGTH] or fallback)[:LAB_DIAGNOSTIC_MAX_LENGTH]


def _authoritative_guest_status(status: dict[str, Any], name: str) -> bool:
    if status.get("agent") != name or status.get("session") != LAB_SESSION:
        return False
    if not all(isinstance(status.get(field), bool) for field in LAB_STATUS_FIELDS):
        return False
    return tuple(status[field] for field in LAB_STATUS_FIELDS) in LAB_STATUS_STATES


def _guest_status_diagnostic(status: dict[str, Any], name: str, diagnostic: str) -> str:
    if diagnostic:
        return _bounded_diagnostic(diagnostic, "")
    if status.get("agent") != name:
        return "The guest reported a different Lab agent identity."
    if status.get("session") != LAB_SESSION:
        return "The guest reported a different Lab session."
    if not all(isinstance(status.get(field), bool) for field in LAB_STATUS_FIELDS):
        return "The guest Lab status has an invalid boolean schema."
    return "The guest Lab status has an impossible state combination."


def _guest_status_state(status: dict[str, Any]) -> str:
    return LAB_STATUS_STATES[tuple(status[field] for field in LAB_STATUS_FIELDS)]


def _teardown_evidence_path(output: str) -> str | None:
    prefix = "Lab session removed after redacted evidence capture:"
    for line in output.splitlines():
        if line.startswith(prefix):
            path = line[len(prefix) :].strip()
            if path == LAB_EVIDENCE_ROOT or path.startswith(f"{LAB_EVIDENCE_ROOT}/"):
                return path
    return None


def _has_verified_teardown_evidence(name: str, guest_path: str) -> bool:
    guest_root = Path(LAB_EVIDENCE_ROOT)
    try:
        relative = Path(guest_path).relative_to(guest_root)
    except ValueError:
        return False
    if len(relative.parts) != 1:
        return False

    host_root = get_agent_home_dir(name) / ".safeyolo" / "lab-evidence"
    capture_dir = host_root / relative
    try:
        resolved_root = host_root.resolve(strict=True)
        resolved_capture = capture_dir.resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    if (
        resolved_capture.parent != resolved_root
        or capture_dir.is_symlink()
        or not capture_dir.is_dir()
    ):
        return False

    required_files = (
        capture_dir / "capture-status.txt",
        capture_dir / "manifest.jsonl",
        capture_dir / "SHA256SUMS",
    )
    if not all(path.is_file() and not path.is_symlink() for path in required_files):
        return False
    try:
        status = required_files[0].read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False
    return any(line.strip() == "status=complete" for line in status.splitlines())


def _require_guest_status(status: dict[str, Any], diagnostic: str, name: str) -> None:
    if _authoritative_guest_status(status, name):
        return
    detail = _guest_status_diagnostic(status, name, diagnostic)
    console.print(f"[red]Cannot safely continue Lab lifecycle: {escape(detail)}[/red]")
    raise typer.Exit(2)


def _guest_command(platform: Any, name: str, command: str) -> tuple[int, str, str]:
    process = platform.popen_in_sandbox(name, command, user="agent")
    try:
        stdout, stderr = process.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        _reap_timed_out_process(process)
        return 124, "", "The guest Lab command exceeded its 60 second deadline."
    return process.returncode or 0, stdout or "", stderr or ""


def _reap_timed_out_process(process: Any) -> None:
    """Kill a timed-out guest process and make a bounded effort to reap it."""
    try:
        process.kill()
    except OSError:
        # The process may have exited before the kill; still try to reap it.
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            # It may have exited during the second kill attempt.
            pass
        try:
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            # Preserve the original timeout result after bounded cleanup.
            pass
    except OSError:
        # Reaping failed; preserve the original timeout as the command result.
        pass


def _start_agent(name: str, *, allow_unowned: bool = False) -> None:
    from .agent import _run_agent

    result = _run_agent(
        name,
        yolo=True,
        dangerously_allow_unowned=allow_unowned,
        detach=True,
        no_snapshot=True,
        rename_tmux_window=False,
        skip_configured_command=True,
    )
    if result != 0:
        raise typer.Exit(result)


def _attach(platform: Any, name: str, objective: str | None = None) -> int:
    command = "safeyolo-lab"
    if objective is not None:
        command += " --objective " + shlex.quote(objective)
    return platform.exec_in_sandbox(name, command, user="agent", interactive=True)


def _print_status(name: str, metadata: dict[str, Any], platform: Any, *, as_json: bool) -> int:
    running = platform.is_sandbox_running(name)
    guest: dict[str, Any] = {}
    diagnostic = ""
    guest_status: dict[str, str] | None = None
    if running:
        guest, diagnostic = _guest_status(platform, name)
        if _authoritative_guest_status(guest, name):
            guest_status = {"state": _guest_status_state(guest)}
        else:
            guest_status = {
                "state": "unknown",
                "diagnostic": _guest_status_diagnostic(guest, name, diagnostic),
            }
    record = {
        "agent": name,
        "backend": metadata.get("lab_backend"),
        "managed": is_lab_managed(metadata),
        "running": running,
        "state": _read_state(name),
        "guest": guest,
    }
    if guest_status is not None:
        record["guest_status"] = guest_status
    if as_json:
        console.print(json.dumps(record, ensure_ascii=False, sort_keys=True), soft_wrap=True)
    else:
        console.print(f"Lab agent: {name}")
        console.print(f"  Backend: {metadata.get('lab_backend', '(unknown)')}")
        console.print(f"  Agent: {'running' if running else 'stopped'}")
        if running:
            if guest_status and guest_status["state"] == "unknown":
                console.print("  Guest status: unknown")
                console.print(f"  [yellow]Diagnostic:[/yellow] {escape(guest_status['diagnostic'])}")
            else:
                session = guest["session_exists"]
                owner = guest["owned"]
                controller = guest["controller_alive"]
                console.print(f"  Guest session: {'owned' if session and owner else 'absent or not owned'}")
                console.print(f"  Controller: {'alive' if controller else 'not alive'}")
                if diagnostic:
                    console.print(f"  [yellow]Diagnostic:[/yellow] {escape(diagnostic)}")
    if running and guest_status and guest_status["state"] == "unknown":
        return 2
    return 0


def _create_agent(name: str, workspace: Path, backend: str) -> None:
    from .agent import add as agent_add

    agent_add(
        name=name,
        folder=str(workspace),
        host_script="@codex",
        rootfs_script=None,
        rootfs_from=None,
        ephemeral=False,
        force=False,
        no_run=True,
        user_default_args=None,
        mount=[],
        port=[],
        dangerously_allow_unowned=False,
        no_rename_window=True,
    )

    def mark(metadata: Any) -> None:
        metadata["lab_managed"] = True
        metadata["lab_schema"] = LAB_SCHEMA
        metadata["lab_backend"] = backend

    mutate_agent(name, mark)


def _require_mode(options: list[bool]) -> None:
    if sum(options) > 1:
        console.print("[red]Choose only one Lab lifecycle action.[/red]")
        raise typer.Exit(1)


def lab(
    agent: str | None = typer.Option(None, "--agent", "-a", help="Use this explicitly Lab-managed agent."),
    folder: str | None = typer.Option(None, "--folder", "-f", help="Workspace for a new Lab agent."),
    backend: str = typer.Option("codex", "--backend", help="Lab backend (currently: codex)."),
    objective: str | None = typer.Option(None, "--objective", help="State the Lab objective without an extra prompt."),
    status: bool = typer.Option(False, "--status", help="Show Lab and guest controller status."),
    recover: bool = typer.Option(False, "--recover", help="Relaunch an owned dead controller, then attach."),
    relaunch: bool = typer.Option(False, "--relaunch", help="Explicitly relaunch an owned controller, then attach."),
    teardown: bool = typer.Option(False, "--teardown", help="Capture final guest evidence and tear down the Lab session."),
    keep_agent: bool = typer.Option(False, "--keep-agent", help="Keep the Lab agent running after --teardown."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Confirm the proposed Lab agent."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable status with --status."),
) -> None:
    """Create, attach to, recover, inspect, or tear down a SafeYolo Lab.

    Lab is an operator-guided experimentation workbench. It uses the existing
    SafeYolo agent lifecycle and the Codex tmux controller as its first backend.
    """
    _require_mode([status, recover, relaunch, teardown])
    if backend not in LAB_BACKENDS:
        console.print(f"[red]Unsupported Lab backend: {escape(backend)}.[/red]")
        console.print("Available backends: codex")
        raise typer.Exit(1)
    if json_output and not status:
        console.print("[red]--json is valid only with --status.[/red]")
        raise typer.Exit(1)
    if keep_agent and not teardown:
        console.print("[red]--keep-agent is valid only with --teardown.[/red]")
        raise typer.Exit(1)
    if (status or recover or relaunch or teardown) and objective is not None:
        console.print("[red]--objective is valid only when starting or attaching to a Lab.[/red]")
        raise typer.Exit(1)

    if find_config_dir() is None:
        console.print("[red]No SafeYolo configuration found.[/red]")
        console.print("Run [bold]safeyolo init[/bold] first.")
        raise typer.Exit(1)

    selected = _select_agent(agent, backend, allow_none=status)
    if status:
        if selected is None:
            if json_output:
                console.print(json.dumps({"managed": False, "agents": []}, sort_keys=True))
            else:
                console.print("No explicitly Lab-managed compatible agents are configured.")
            return
        name, metadata = selected
        from ..platform import get_platform

        raise typer.Exit(_print_status(name, metadata, get_platform(), as_json=json_output))

    lifecycle_action = recover or relaunch or teardown
    if lifecycle_action and selected is None:
        console.print("No explicitly Lab-managed compatible agent is available for that action.")
        console.print("Start a Lab first with `safeyolo lab`.")
        raise typer.Exit(1)

    from ..platform import get_platform

    platform = get_platform()
    if selected is not None:
        name, metadata = selected
        workspace = Path(str(metadata.get("folder", "."))).expanduser().resolve()
        created = False
    else:
        name = _proposed_name()
        workspace = Path(folder or ".").expanduser().resolve()
        if not workspace.is_dir():
            console.print(f"[red]Workspace not found: {escape(str(workspace))}[/red]")
            raise typer.Exit(1)
        metadata = {}
        created = True

    if created:
        objective = objective or typer.prompt("What do you want to build, test, or understand?")
        objective = objective.strip()
        if not objective:
            console.print("[red]The Lab objective cannot be empty.[/red]")
            raise typer.Exit(1)
        console.print("Proposed Lab:")
        console.print(f"  Agent: {name}")
        console.print(f"  Workspace: {workspace}")
        console.print(f"  Backend: {backend}")
        if not yes and not typer.confirm("Create and start this Lab?", default=False):
            console.print("Lab start cancelled. No agent or session was changed.")
            return
        _write_state(name, _new_state(name, workspace, backend, objective))
        _create_agent(name, workspace, backend)
    else:
        state = _read_state(name)
        if lifecycle_action:
            objective = str(state.get("objective", "")).strip()
            if not objective and not teardown:
                console.print(
                    f"[red]Lab state for '{name}' has no recorded objective; "
                    "recovery cannot safely start it.[/red]"
                )
                raise typer.Exit(1)
        else:
            running = platform.is_sandbox_running(name)
            if running:
                guest, diagnostic = _guest_status(platform, name)
                _require_guest_status(guest, diagnostic, name)
                if guest.get("session_exists") and not guest.get("owned"):
                    console.print(
                        "[red]A guest session named 'lab' exists, but SafeYolo does not own it. "
                        "The Lab will not adopt or overwrite it.[/red]"
                    )
                    raise typer.Exit(1)
                if guest.get("session_exists") and guest.get("controller_alive"):
                    if diagnostic:
                        console.print(f"[yellow]Lab status diagnostic:[/yellow] {escape(diagnostic)}")
                    raise typer.Exit(_attach(platform, name))
                if guest.get("session_exists"):
                    console.print("[yellow]The owned Lab controller is not alive.[/yellow]")
                    console.print(f"Run `safeyolo lab --agent {name} --recover` to relaunch it.")
                    raise typer.Exit(2)
            objective = objective or str(state.get("objective", "")).strip()
            objective = objective or typer.prompt("What do you want to build, test, or understand?")
            objective = objective.strip()
            if not objective:
                console.print("[red]The Lab objective cannot be empty.[/red]")
                raise typer.Exit(1)
            state = state or _new_state(name, workspace, backend, objective)
            state["objective"] = objective
            state["phase"] = "prepared"
            _write_state(name, state)

    if teardown and not platform.is_sandbox_running(name):
        state = state or _new_state(name, workspace, backend, objective or "")
        state["phase"] = "teardown-complete"
        state["evidence_status"] = "not-captured-no-live-guest"
        state["teardown_result"] = (
            "Agent was already stopped; no guest session was inspected or removed. "
            "Evidence and configuration were retained."
        )
        _write_state(name, state)
        console.print(
            f"Lab agent '{name}' is already stopped. "
            "No guest resources were removed; evidence and configuration were retained."
        )
        return

    if not platform.is_sandbox_running(name):
        console.print(f"Starting Lab agent '{name}'...")
        _start_agent(name)

    guest, diagnostic = _guest_status(platform, name)
    _require_guest_status(guest, diagnostic, name)
    if guest.get("session_exists") and not guest.get("owned"):
        console.print(
            "[red]A guest session named 'lab' exists, but SafeYolo does not own it. "
            "The Lab will not adopt or overwrite it.[/red]"
        )
        raise typer.Exit(1)
    if guest.get("session_exists") and not guest.get("controller_alive") and not lifecycle_action:
        console.print("[yellow]The owned Lab controller is not alive.[/yellow]")
        console.print(f"Run `safeyolo lab --agent {name} --recover` to relaunch it.")
        raise typer.Exit(2)

    if recover or relaunch:
        if guest.get("session_exists"):
            command = "safeyolo-lab --relaunch" if relaunch else "safeyolo-lab --recover"
            rc, output, error = _guest_command(platform, name, command)
            if output.strip():
                console.print(output.strip())
            if rc != 0:
                if error:
                    console.print(f"[red]{escape(error.strip())}[/red]")
                raise typer.Exit(rc)

    state = _read_state(name)
    state["phase"] = "running"
    _write_state(name, state)
    if teardown and not guest["session_exists"]:
        state["phase"] = "teardown-complete"
        state["evidence_status"] = "not-captured-no-live-session"
        state["teardown_result"] = (
            "No live guest Lab session was present; no guest resources were removed. "
            "Evidence and configuration were retained."
        )
        _write_state(name, state)
        if not keep_agent and platform.is_sandbox_running(name):
            platform.stop_sandbox(name)
            console.print(f"Stopped Lab agent '{name}'. No guest resources were removed.")
        else:
            console.print(
                "No live guest Lab session was present. "
                "No guest resources were removed; evidence and configuration were retained."
            )
        return
    if teardown:
        rc, output, error = _guest_command(platform, name, "safeyolo-lab --teardown")
        if output.strip():
            console.print(output.strip())
        if rc != 0:
            if error:
                console.print(f"[red]{escape(error.strip())}[/red]")
            raise typer.Exit(rc)
        evidence_path = _teardown_evidence_path(output)
        if evidence_path is None or not _has_verified_teardown_evidence(name, evidence_path):
            state["phase"] = "teardown-incomplete"
            state["evidence_status"] = "not-captured"
            state["teardown_result"] = "Guest teardown did not provide verified evidence capture."
            _write_state(name, state)
            console.print("[red]Guest teardown did not provide verified evidence capture.[/red]")
            raise typer.Exit(2)
        state["phase"] = "teardown-complete"
        state["final_evidence"] = evidence_path
        state["evidence_status"] = "captured"
        state["teardown_result"] = "Guest evidence captured and the owned session was removed."
        _write_state(name, state)
        if not keep_agent and platform.is_sandbox_running(name):
            platform.stop_sandbox(name)
            console.print(f"Stopped Lab agent '{name}'. Evidence and configuration were retained.")
        return

    if diagnostic:
        console.print(f"[yellow]Lab status diagnostic:[/yellow] {escape(diagnostic)}")
    rc = _attach(platform, name, objective if not guest.get("session_exists") else None)
    raise typer.Exit(rc)
