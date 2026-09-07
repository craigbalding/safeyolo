"""Host-owned launch selection and the current coding-agent session.

This is not a sandbox registry or a restart supervisor. One record remembers
the launcher used by the current run; the platform and session manager provide
liveness. Host scripts are selected only from local configuration.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import shlex
import signal
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from .agents_store import get_or_mint_agent_id, load_agent, load_all_agents
from .config import get_agents_dir, get_config_dir, get_logs_dir, load_config
from .runtime_identity import process_start_token

LaunchMode = Literal["foreground", "background", "sandbox"]
log = logging.getLogger("safeyolo.agent-launcher")
PRESETS = {"tmux-window", "tmux-pane"}


@dataclass(frozen=True)
class Launcher:
    kind: str
    source: str
    script: str | None = None


def resolve_launcher(metadata: dict, config: dict, mode: LaunchMode, *, interactive: bool = False) -> Launcher:  # DOC: docs/agent-launchers.md
    """Resolve one explicit manager, agent override, inherited script or default."""
    if mode == "sandbox":
        return Launcher("sandbox", "requested")
    if interactive:
        value, source = "interactive", "requested"
    elif metadata.get("launcher"):
        value, source = metadata["launcher"], "agent"
    elif config.get("agent_launcher", {}).get("default"):
        value, source = config["agent_launcher"]["default"], "host default"
    else:
        value, source = "interactive", "built-in"
    if not isinstance(value, str):
        raise ValueError("launcher must be interactive, supervisor, a tmux preset, or an absolute host-script path")
    if value == "interactive":
        value = "tmux-window" if mode == "background" else value
    if value in {"interactive", "supervisor"}:
        return Launcher(value, source)
    if value in PRESETS:
        return Launcher(value, source, str(Path(__file__).with_name("launchers") / f"{value}.sh"))
    kind = "manager" if value.startswith("manager:") else "script"
    script = value.removeprefix("manager:")
    if not Path(script).expanduser().is_absolute():
        raise ValueError("host launcher must be an absolute path (or manager:/absolute/path)")
    return Launcher(kind, source, str(Path(script).expanduser().resolve()))


def _path(name: str) -> Path:
    # Reuse the CLI's name contract. This import is deferred to keep CLI startup
    # lazy; names never come from a script result or guest file.
    from .commands.agent import _validate_instance_name

    _validate_instance_name(name)
    return get_agents_dir() / name / "current-launch.json"


@contextmanager
def launch_lock(name: str):
    """Serialize launch/stop and short record mutations outside guest mounts."""
    path = _path(name).with_suffix(".lock")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def read_launch(name: str) -> dict | None:
    try:
        record = json.loads(_path(name).read_text())
    except FileNotFoundError:
        return None
    if not isinstance(record, dict) or record.get("agent_id") != load_agent(name).get("agent_id"):
        raise RuntimeError(f"Stored launcher identity does not match agent {name}")
    required = {"name", "agent_id", "launch_id", "launcher", "mode", "state", "command", "workspace", "tmux_session"}
    if not required <= record.keys() or record["name"] != name:
        raise RuntimeError(f"Incomplete launcher record for agent {name}")
    if not isinstance(record["launcher"], dict) or not {"kind", "source"} <= record["launcher"].keys():
        raise RuntimeError(f"Invalid launcher selection for agent {name}")
    return record


def _save(name: str, record: dict) -> None:
    # The supervisor's existing atomic JSON writer uses unique temporary files.
    from .agent_command_supervisor import _write_json

    _write_json(_path(name), record)
    from .core.audit_schema import sanitize_for_log
    from .events import write_event

    write_event("agent.launch_state", kind="agent", severity="low",
                summary=f"Agent {sanitize_for_log(name, max_len=None)}: {sanitize_for_log(record['state'], max_len=None)}",
                agent=name, details={"launch_id": record["launch_id"], "state": record["state"],
                                    "exit_code": record.get("exit_code")})


def update_launch(name: str, launch_id: str, **changes) -> dict:
    with launch_lock(name):
        record = read_launch(name)
        if record is None or record["launch_id"] != launch_id:
            raise RuntimeError("The coding-agent launch changed; refusing to update another run")
        record.update(changes, updated_at=datetime.now(UTC).isoformat())
        _save(name, record)
        return record


def _boot_context(name: str) -> dict:
    from .vm import get_agent_config_share_dir

    try:
        return json.loads((get_agent_config_share_dir(name) / "host-launch-context.json").read_text())
    except FileNotFoundError:
        return {}


def validate_script(launcher: Launcher) -> None:
    """Do not execute a guest-writable custom launcher on the host."""
    if launcher.script is None:
        return
    script = Path(launcher.script).resolve()
    if not script.is_file() or not os.access(script, os.X_OK):
        raise RuntimeError(f"Host launcher is missing or not executable: {script}")
    if launcher.kind in PRESETS:
        return  # Installed product resources share the host application's trust.
    from .commands.agent import _resolve_extra_shares

    for name, metadata in load_all_agents().items():
        writable = [get_agents_dir() / name / leaf for leaf in ("home", "status", "cache")]
        if metadata.get("folder"):
            writable.append(Path(metadata["folder"]).expanduser())
        writable.extend(Path(host) for host, _guest, read_only in _resolve_extra_shares(metadata, None)
                        if not read_only)
        boot = _boot_context(name)
        if boot.get("workspace"):
            writable.append(Path(boot["workspace"]))
        writable.extend(Path(host) for host in boot.get("writable_mounts", []))
        if any(script.is_relative_to(root.resolve()) for root in writable):
            raise RuntimeError(f"Host launcher is inside an agent-writable mount: {script}")


def launch_environment(record: dict) -> dict[str, str]:
    """Pass fixed context as data; retain the host user's terminal environment."""
    env = dict(os.environ)
    env.update({
        "SAFEYOLO_CONFIG_DIR": str(get_config_dir().resolve()),
        "SAFEYOLO_LOGS_DIR": str(get_logs_dir().resolve()),
        "SAFEYOLO_AGENT_NAME": record["name"],
        "SAFEYOLO_AGENT_ID": record["agent_id"],
        "SAFEYOLO_LAUNCH_ID": record["launch_id"],
        "SAFEYOLO_WORKSPACE": record["workspace"],
        "SAFEYOLO_LAUNCH_MODE": record["mode"],
        "SAFEYOLO_PYTHON": sys.executable,
        "SAFEYOLO_LAUNCHER_PRESETS": str(Path(__file__).with_name("launchers")),
        "SAFEYOLO_TMUX_SESSION": record["tmux_session"],
        "SAFEYOLO_LAUNCH_PANE": record.get("pane_id", ""),
        "SAFEYOLO_AGENT_EXIT_CODE": str(record.get("exit_code", "")),
        "SAFEYOLO_AGENT_EXIT_REASON": record.get("exit_reason", ""),
    })
    return env


def _script(record: dict, action: str, *, capture: bool = True) -> subprocess.CompletedProcess:
    launcher = Launcher(**record["launcher"])
    validate_script(launcher)
    if launcher.script is None:
        raise RuntimeError("This launcher has no host script")
    return subprocess.run([launcher.script, action], env=launch_environment(record),
                          text=True, capture_output=capture, check=False)


def _live_process(pid: int | None, token: str | None) -> bool:
    if not pid or not token or process_start_token(pid) != token:
        return False
    # A retained zombie is not a live session even though its start token matches.
    if sys.platform == "linux":
        try:
            return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
        except FileNotFoundError:
            return False
    return True


def observe_launch(name: str, *, sandbox_ready: bool) -> dict:
    record = read_launch(name)
    selected = resolve_launcher(load_agent(name), load_config(), "background")
    result = {"agent_state": "stopped", "launcher": asdict(selected), "attachable": False}
    if record is None:
        return result
    result.update({key: record[key] for key in ("launcher", "launch_id", "exit_code", "error", "hook_errors") if key in record})
    if not sandbox_ready:
        if record["state"] in {"launching", "running", "stopping", "finishing"} and _live_process(record.get("runner_pid"), record.get("runner_token")):
            result["agent_state"] = "finishing"
        return result
    kind = record["launcher"]["kind"]
    if kind == "supervisor":
        from .agent_command_supervisor import read_command_supervisor_state, supervisor_process_is_live

        if record["state"] == "starting":
            result["agent_state"] = "starting"
            return result
        state = read_command_supervisor_state(name)
        if state:
            if state["state"] in {"starting", "restarting", "failed", "stopped", "exited"}:
                result["agent_state"] = state["state"]
            else:
                result["agent_state"] = "running" if supervisor_process_is_live(state) else "unknown"
            result["error"] = state.get("last_stderr", "")
        return result
    state = record["state"]
    if state in {"launching", "running", "stopping", "finishing"} and record.get("runner_pid"):
        if not _live_process(record["runner_pid"], record.get("runner_token")):
            result.update(agent_state="exited", error=record.get("error") or "Launch process exited without recording its result")
            return result
    if kind in {"script", "manager"} and not record.get("runner_pid") and state in {"starting", "running", "unknown"}:
        probe = _script(record, "status")
        if probe.returncode or not probe.stdout.strip():
            state = "unknown"
        else:
            status = json.loads(probe.stdout)
            if not isinstance(status, dict):
                raise RuntimeError("Host launcher status must be a JSON object")
            state = status.get("state", "unknown")
            if state not in {"starting", "running", "exited", "failed", "stopped", "unknown"}:
                raise RuntimeError(f"Host launcher returned an unknown state: {state}")
    if state == "running" and (record.get("runner_pid") or kind not in {"script", "manager"}):
        state = "running" if _live_process(record.get("pid"), record.get("process_token")) else "finishing" if record.get("runner_pid") else "exited"
    if state == "starting" and kind in PRESETS and record.get("pane_id"):
        probe = _script(record, "status")
        if probe.returncode:
            state = "failed"
            result["error"] = "The host terminal closed before the agent entrypoint started"
    if state == "starting" and not record.get("pane_id") and not _live_process(record.get("requester_pid"), record.get("requester_token")):
        state = "failed"
        result["error"] = "The launch requester exited before starting the agent"
    result["agent_state"] = state
    result["attachable"] = state == "running" and kind != "interactive"
    return result


def prepare_launch(name: str, selection: Launcher, mode: LaunchMode, command: str) -> dict:
    """Write a new current launch while the caller holds the launch lock."""
    validate_script(selection)
    metadata = load_agent(name)
    record = {
        "name": name, "agent_id": get_or_mint_agent_id(name),
        "launch_id": "launch-" + uuid.uuid4().hex, "launcher": asdict(selection),
        "workspace": _boot_context(name).get("workspace") or str(Path(metadata["folder"]).expanduser().resolve()),
        "mode": mode, "command": command, "state": "starting",
        "tmux_session": load_config().get("agent_launcher", {}).get("tmux_session", "safeyolo"),
        "started_at": datetime.now(UTC).isoformat(),
        "requester_pid": os.getpid(), "requester_token": process_start_token(os.getpid()),
    }
    _save(name, record)
    return record


def invoke_launcher(record: dict) -> int:
    """Launch once, without keeping the caller attached to a background run."""
    name, launch_id = record["name"], record["launch_id"]
    kind = record["launcher"]["kind"]
    if kind == "interactive":
        return run_entrypoint(name, launch_id)
    if kind == "supervisor":
        from .agent_command_supervisor import start_command_supervisor

        try:
            start_command_supervisor(name, record["command"])
        except (OSError, RuntimeError, ValueError) as exc:
            update_launch(name, launch_id, state="failed", error=str(exc))
            raise
        update_launch(name, launch_id, state="managed")
        return 0
    try:
        completed = _script(record, "launch")
    except (OSError, RuntimeError) as exc:
        update_launch(name, launch_id, state="failed", error=str(exc))
        raise
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip() or f"exit {completed.returncode}"
        update_launch(name, launch_id, state="failed", error=detail)
        raise RuntimeError(f"Host launcher failed: {detail}")
    # A successful script may start an external manager with no observable
    # session. Never turn its zero exit code into a 'running' claim.
    try:
        result = json.loads(completed.stdout) if completed.stdout.strip() else {}
    except json.JSONDecodeError as exc:
        update_launch(name, launch_id, state="unknown", error="Host launcher returned invalid JSON")
        raise RuntimeError("Host launcher returned invalid JSON; inspect its session before retrying") from exc
    if not isinstance(result, dict):
        update_launch(name, launch_id, state="unknown", error="Host launch result was not a JSON object")
        raise RuntimeError("Host launch result must be a JSON object or empty")
    changes = {key: result[key] for key in ("pane_id",) if key in result}
    with launch_lock(name):
        current = read_launch(name)
        if current is None or current["launch_id"] != launch_id:
            raise RuntimeError("The coding-agent launch changed during host launch")
        if kind not in PRESETS and current["state"] == "starting":
            changes["state"] = "unknown"
        current.update(changes)
        _save(name, current)
    return 0


def _hook(record: dict, action: str) -> int:
    if not record["launcher"].get("script"):
        return 0
    try:
        completed = _script(record, action)
    except (OSError, RuntimeError) as exc:
        # Optional post-launch/exit hooks cannot kill a live command or replace
        # its exit result. Retain a distinct hook failure for diagnostics.
        completed = subprocess.CompletedProcess(action, 1, "", str(exc))
    if completed.returncode:
        from .core.audit_schema import sanitize_for_log

        detail = completed.stderr.strip() or completed.stdout.strip() or f"exit {completed.returncode}"
        log.error("Launcher hook %s failed: %s", action, sanitize_for_log(detail, max_len=None))
        current = read_launch(record["name"]) or record
        errors = [*current.get("hook_errors", []), {"hook": action, "exit_code": completed.returncode, "detail": detail}]
        update_launch(record["name"], record["launch_id"], hook_errors=errors)
    return completed.returncode


def run_entrypoint(name: str, launch_id: str) -> int:
    """Run the configured guest command in this terminal, never on the host."""
    from .platform import get_platform

    with launch_lock(name):
        record = read_launch(name)
        if (record is None or record["launch_id"] != launch_id
                or record["state"] not in {"starting", "unknown"} or record.get("runner_pid")):
            raise RuntimeError("No matching stopped coding-agent launch is ready")
        record.update(state="launching", runner_pid=os.getpid(), runner_token=process_start_token(os.getpid()))
        if record["launcher"].get("script") and os.environ.get("TMUX_PANE"):
            record["pane_id"] = os.environ["TMUX_PANE"]
            subprocess.run(["tmux", "set-option", "-p", "-t", record["pane_id"],
                            "@safeyolo_launch_id", launch_id], check=True)
        _save(name, record)
    if not get_platform().is_sandbox_running(name):
        update_launch(name, launch_id, state="failed", error="The sandbox is not ready")
        raise RuntimeError("The sandbox is not ready")
    pre_exit = _hook(record, "pre_launch")
    if pre_exit:
        update_launch(name, launch_id, state="failed", error="pre_launch hook failed")
        return pre_exit

    old_handlers = {}
    exit_signal = None

    def started(process):
        def forward(signum, _frame):
            nonlocal exit_signal
            exit_signal = signum
            if process.poll() is None:
                process.send_signal(signum)

        if threading.current_thread() is threading.main_thread():
            for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
                old_handlers[signum] = signal.signal(signum, forward)
        update_launch(name, launch_id, state="running", pid=process.pid,
                      process_token=process_start_token(process.pid))
        _hook(record, "post_launch")

    code = 1
    reason = "command failed"
    state = "exited"
    try:
        code = get_platform().exec_in_sandbox(name, record["command"], user="agent", interactive=True, on_start=started)
        reason = f"signal {exit_signal}" if exit_signal else "command exited"
        code = 128 - code if code < 0 else code
    except KeyboardInterrupt:
        code, reason = 130, "interrupted"
    except SystemExit as exc:
        code, reason = exc.code if isinstance(exc.code, int) else 1, "terminated"
        raise
    except Exception as exc:
        update_launch(name, launch_id, state="failed", error=str(exc))
        state = "failed"
        reason = type(exc).__name__
        raise
    finally:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
        record.update(exit_code=code, exit_reason=reason)
        update_launch(name, launch_id, state="finishing", exit_code=code, exit_reason=reason)
        _hook(record, "on_exit")
        # Publish completion only after the exit hook, so a new launch cannot
        # replace the record while the previous launch is still cleaning up.
        update_launch(name, launch_id, state=state, exit_code=code, exit_reason=reason)
    return code


def attach_agent(name: str) -> int:
    from .platform import get_platform

    observed = observe_launch(name, sandbox_ready=get_platform().is_sandbox_running(name))
    record = read_launch(name)
    if record and record["launcher"]["kind"] == "supervisor":
        raise RuntimeError("Supervised agents have no interactive terminal. Use agent diag or Coord output; use run --interactive for a stopped agent.")
    if not record or observed["agent_state"] not in {"starting", "launching", "running", "unknown"}:
        raise RuntimeError(f"Agent {name} has no live session to attach to")
    if record["launcher"]["kind"] == "interactive":
        raise RuntimeError("This agent is running in its original terminal, not an attachable session")
    return _script(record, "attach", capture=False).returncode


def stop_launcher(name: str) -> None:
    """Request only the current launcher to stop; do not kill unrelated panes."""
    with launch_lock(name):
        record = read_launch(name)
        if not record:
            return
        if record["state"] not in {"exited", "failed", "stopped"}:
            record["state"] = "stopping"
        _save(name, record)
    kind = record["launcher"]["kind"]
    if kind in {"script", "manager"}:
        completed = _script(record, "stop")
        if completed.returncode:
            raise RuntimeError(f"Host launcher stop failed: {completed.stderr.strip()}")
    elif _live_process(record.get("pid"), record.get("process_token")):
        # Stop the guest transport, not its host wrapper. The wrapper waits for
        # the command and runs on_exit before its tmux pane closes naturally.
        os.kill(record["pid"], signal.SIGTERM)


def configured_guest_command(name: str, args: list[str], *, interactive: bool = False) -> str:
    from .vm import get_agent_home_dir

    entry = ".safeyolo-interactive-command" if interactive else ".safeyolo-command"
    path = get_agent_home_dir(name) / entry
    if path.is_file() and os.access(path, os.X_OK):
        return shlex.join([f"/home/agent/{entry}", *args])
    if interactive:
        raise RuntimeError("The managed agent has no separate interactive entrypoint; reapply its host setup once")
    return shlex.join(args) if args else "exec /bin/bash -l"


def wait_for_launcher_exit(name: str) -> None:
    """Do not delete a run's files while its exit callback still uses them.

    The host script owns callback duration. Ctrl-C cancels removal without
    deleting the stopped agent; no new callback timeout policy is imposed.
    """
    record = read_launch(name)
    if record:
        while _live_process(record.get("runner_pid"), record.get("runner_token")):
            time.sleep(0.05)
