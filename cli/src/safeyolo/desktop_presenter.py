"""Typed, SafeYolo-owned desktop presentation for operator clients."""

from __future__ import annotations

import os
import shlex
import threading
from dataclasses import dataclass

from .agents_store import (
    get_agent_by_id,
    reserve_agent_tailnet_port_change,
    restore_agent_tailnet_port,
)
from .config import get_desktop_size
from .platform import get_platform
from .preview import (
    ManagedPreview,
    PreviewConfig,
    resolve_vnc_geometry,
    start_managed_preview,
)
from .vm import stage_guest_desktop_launcher


class DesktopPresentationError(RuntimeError):
    pass


@dataclass(frozen=True)
class DesktopPresentation:
    agent_id: str
    agent: str
    url: str
    unlock_code: str
    reused: bool

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "agent": self.agent,
            "url": self.url,
            "unlock_code": self.unlock_code,
            "reused": self.reused,
        }


class DesktopPresenter:
    """Own at most one active host preview for each configured agent."""

    def __init__(self) -> None:
        self._sessions: dict[str, ManagedPreview] = {}
        self._lock = threading.Lock()

    def present(self, agent_id: str) -> DesktopPresentation:
        """Start or reuse the local noVNC presentation for ``agent_id``."""
        found = get_agent_by_id(agent_id)
        if found is None:
            raise DesktopPresentationError("Agent not found")
        agent, _metadata = found

        with self._lock:
            existing = self._sessions.get(agent_id)
            if existing is not None and existing.is_running:
                return DesktopPresentation(
                    agent_id=agent_id,
                    agent=agent,
                    url=existing.url,
                    unlock_code=existing.issue_unlock_code(),
                    reused=True,
                )
            if existing is not None:
                existing.close()
                self._sessions.pop(agent_id, None)

            tailnet_port: int | None = None
            previous_tailnet_port: int | None = None
            if os.environ.get("SAFEYOLO_COMMAND_CENTRE_SHARE", "local") == "tailnet":
                tailnet_port, previous_tailnet_port = reserve_agent_tailnet_port_change(agent)

            try:
                platform = get_platform()
                if not platform.is_sandbox_running(agent):
                    raise DesktopPresentationError(f"Agent '{agent}' is not running")

                preferred_size = get_desktop_size()
                geometry, _detected = resolve_vnc_geometry(preferred_size)
                stage_guest_desktop_launcher(agent, preferred_size=preferred_size)
                command = f"SAFEYOLO_PREVIEW_MANAGED=1 /safeyolo/guest-desktop start {shlex.quote(geometry)}"
                exit_code = platform.exec_in_sandbox(
                    agent,
                    command,
                    user="agent",
                    interactive=False,
                )
                if exit_code != 0:
                    raise DesktopPresentationError(f"Agent desktop failed to start (exit {exit_code})")

                session = start_managed_preview(
                    PreviewConfig(
                        agent=agent,
                        guest_port=6080,
                        host_port=0,
                        display_path="/vnc.html#autoconnect=true&resize=remote",
                        tailnet_port=tailnet_port,
                    ),
                    platform,
                )
            except Exception:
                if tailnet_port is not None and tailnet_port != previous_tailnet_port:
                    restore_agent_tailnet_port(
                        agent,
                        tailnet_port,
                        previous_tailnet_port,
                    )
                raise
            self._sessions[agent_id] = session
            return DesktopPresentation(
                agent_id=agent_id,
                agent=agent,
                url=session.url,
                unlock_code=session.unlock_code,
                reused=False,
            )

    def close_all(self) -> None:
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            session.close()

    def close(self, agent_id: str) -> None:
        """Close the active host preview for one stable agent identity."""
        with self._lock:
            session = self._sessions.pop(agent_id, None)
        if session is not None:
            session.close()
