"""Typed agent lifecycle operations shared by CLI and operator clients."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import asdict, dataclass, field

from .agents_store import get_agent_by_id, get_or_mint_agent_id, load_all_agents

log = logging.getLogger(__name__)


class AgentLifecycleError(RuntimeError):
    """A configured agent could not complete a lifecycle transition."""

    def __init__(self, message: str, *, status_code: int = 500) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class AgentRuntime:
    """Operator-facing state for one configured agent."""

    agent_id: str
    name: str
    sandbox_state: str
    agent_state: str = "stopped"
    launcher: dict | None = None
    attachable: bool = False
    launch_id: str | None = None
    exit_code: int | None = None
    error: str | None = None
    hook_errors: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _runtime(name: str, agent_id: str) -> AgentRuntime:
    from .agent_launchers import observe_launch
    from .platform import get_platform

    ready = get_platform().is_sandbox_running(name)
    try:
        observed = observe_launch(name, sandbox_ready=ready)
    except (OSError, ValueError, RuntimeError) as exc:
        # One broken launcher must not hide every other configured agent.
        observed = {"agent_state": "unknown", "error": str(exc)}
    return AgentRuntime(agent_id=agent_id, name=name, sandbox_state="ready" if ready else "stopped", **observed)


def list_agent_runtimes() -> list[AgentRuntime]:
    """Return all configured agents with stable identities and live state."""
    agents = load_all_agents()
    runtimes = []
    for name, metadata in sorted(agents.items()):
        agent_id = str(metadata.get("agent_id") or get_or_mint_agent_id(name))
        runtimes.append(_runtime(name, agent_id))
    return runtimes


def _resolve(agent_id: str) -> tuple[str, str]:
    found = get_agent_by_id(agent_id)
    if found is None:
        raise AgentLifecycleError("Agent not found", status_code=404)
    name, _ = found
    return name, agent_id


def start_agent(agent_id: str, *, interactive: bool = False) -> AgentRuntime:
    """Start one configured agent using the ordinary fixed lifecycle path."""
    name, stable_id = _resolve(agent_id)
    from .platform import get_platform

    platform = get_platform()

    # Import lazily: the CLI module is large and imports this module for stop.
    from .commands.agent import _run_agent

    try:
        exit_code = _run_agent(
            name=name,
            yolo=True,
            launch_mode="background",
            interactive=interactive,
            no_snapshot=True,
            rename_tmux_window=False,
        )
    except Exception as exc:
        from .core.audit_schema import sanitize_for_log

        log.exception("Agent %s failed to start", sanitize_for_log(name, max_len=None))
        detail = str(exc).strip() or "no additional detail"
        exit_code = getattr(exc, "exit_code", None)
        if exit_code is not None:
            detail = f"exit code {exit_code}: {detail}"
        raise AgentLifecycleError(
            f"Agent start failed: {type(exc).__name__}: {detail}",
        ) from exc
    if exit_code != 0 or not platform.is_sandbox_running(name):
        raise AgentLifecycleError(f"Agent start failed with exit code {exit_code}")
    return _runtime(name, stable_id)


def stop_agent(agent_id: str) -> AgentRuntime:
    """Stop one configured agent and its command supervisor."""
    name, stable_id = _resolve(agent_id)
    return stop_agent_by_name(name, agent_id=stable_id)


def stop_agent_by_name(
    name: str,
    *,
    agent_id: str = "",
    on_phase: Callable[[str], None] | None = None,
) -> AgentRuntime:
    """Stop one named agent; the CLI also permits an absent stale name."""
    from .commands.agent import _agent_host_setup_lock

    with _agent_host_setup_lock(name):
        return _stop_agent_by_name(name, agent_id=agent_id, on_phase=on_phase)


def _stop_agent_by_name(name: str, *, agent_id: str, on_phase: Callable[[str], None] | None) -> AgentRuntime:
    from .agent_command_supervisor import request_command_supervisor_stop
    from .agent_launchers import stop_launcher
    from .platform import get_platform

    if on_phase:
        on_phase("command supervisor stop intent")
    if not request_command_supervisor_stop(name):
        raise AgentLifecycleError(
            "Could not stop the command supervisor; the sandbox was left intact "
            "to prevent an automatic restart",
        )

    # An external manager must see stop intent before its sandbox disappears;
    # otherwise it may treat the shutdown as a crash and relaunch the agent.
    stop_launcher(name)
    platform = get_platform()
    if not platform.is_sandbox_running(name):
        return _runtime(name, agent_id)

    if on_phase:
        on_phase("platform sandbox shutdown and cleanup")
    platform.stop_sandbox(name)

    # stop_sandbox updates agent_map.json. Reconcile the live proxy listener
    # when there is a proxy to notify; its next start otherwise reads the map.
    from .config import load_config
    from .proxy import is_proxy_running, sync_proxy_modes

    if on_phase:
        on_phase("check proxy before listener reconciliation")
    if is_proxy_running():
        admin_port = load_config().get("proxy", {}).get("admin_port", 9090)
        if on_phase:
            on_phase("remove proxy listener for stopped agent")
        sync_proxy_modes(admin_port=admin_port)

    from .events import write_event

    if on_phase:
        on_phase("record and render stop result")
    write_event(
        "agent.stopped",
        kind="agent",
        severity="low",
        summary=f"Agent {name} stopped by user",
        agent=name,
        details={"reason": "user_request"},
    )
    return _runtime(name, agent_id)
