"""Operator recovery of selected work in stopped supervisor checkpoints."""

from __future__ import annotations

import asyncio
import copy
import os
import runpy
from collections.abc import Callable
from contextlib import ExitStack
from types import SimpleNamespace
from typing import Any

from .agents_store import load_agent
from .coord import api as coord_api
from .coord.identity import new_operation_id
from .factory_contract import FactoryContractError
from .factory_doctor import _bundled_contrib_path
from .platform import get_platform
from .vm import get_agent_home_dir


def _supervisor() -> SimpleNamespace:
    # Use the shipped decoder, atomic writer and correlation parser. Never
    # execute a script from the agent's writable home to interpret its state.
    return SimpleNamespace(**runpy.run_path(str(_bundled_contrib_path("codex-coord-supervisor.py"))))


def _release_state(supervisor, state: dict[str, Any], room: str, targets: set[str]) -> dict[str, Any]:
    updated = copy.deepcopy(state)
    for item in list(updated["in_flight"]):
        fields = supervisor._message_fields(item["body"]) or {}
        if item["room_name"] == room and fields.get("target") in targets:
            supervisor._complete_attention(updated, item["attention_id"])
    updated["awaiting_handoffs"] = [
        item for item in updated["awaiting_handoffs"]
        if not (item["room_name"] == room and item["correlation"].get("target") in targets)
    ]
    if updated != state:
        # A fresh turn must not resume instructions for the released work.
        # Unrelated pending work remains in the canonical checkpoint.
        updated["thread_id"] = None
        updated["owned_process"] = None
    return updated


def _collect_releases(supervisor, agents, room, targets, locks):
    plans = []
    platform = get_platform()
    for agent in agents:
        path = get_agent_home_dir(agent) / ".safeyolo/codex-coord-supervisor-state.json"
        if not path.exists():
            continue
        state = supervisor.load_state(path)
        updated = _release_state(supervisor, state, room, targets)
        if updated == state:
            continue
        if platform.is_sandbox_running(agent):
            raise FactoryContractError(f"agent {agent!r} has selected work and is running; stop it before release")
        locks.enter_context(supervisor._lock_state(path))
        if supervisor.load_state(path) != state:
            raise FactoryContractError(f"checkpoint changed for {agent!r}; inspect and retry")
        plans.append((agent, path, path.read_bytes(), state, updated))
    return plans


def _apply_releases(supervisor, plans, room: str, description: str) -> str:
    operation = new_operation_id()
    backups = []
    platform = get_platform()
    for agent, path, original, _before, _after in plans:
        if platform.is_sandbox_running(agent) or path.read_bytes() != original:
            raise FactoryContractError(f"agent or checkpoint changed for {agent!r}; nothing released")
    for _agent, path, original, _before, _after in plans:
        backup = path.with_name(f"{path.stem}.before-release-{operation}.json")
        with backup.open("xb") as handle:
            os.chmod(backup, 0o600)
            handle.write(original)
            handle.flush()
            os.fsync(handle.fileno())
        backups.append(str(backup))

    async def record(status: str) -> None:
        await coord_api.send(
            room, "operator", None,
            f"Factory work release {status}. operation_id={operation}\n{description}",
            declared_content_type="text/plain", notify="none",
        )

    changed = []
    try:
        asyncio.run(record("requested"))
        for agent, path, _original, _before, updated in plans:
            supervisor.save_state(path, updated)
            changed.append(agent)
        asyncio.run(record("completed"))
    except Exception as exc:
        raise FactoryContractError(
            f"release {operation} did not finish: {exc}; changed agents={','.join(changed) or 'none'}. "
            f"Keep affected agents stopped; inspect checkpoints and retry the same selection if work remains. "
            f"Backups: {', '.join(backups)}"
        ) from exc
    return (
        f"Released checkpointed work for {', '.join(changed)}. operation_id={operation}\n"
        "Files and room history are retained. Agents were not started.\n"
        + "\n".join(f"backup={backup}" for backup in backups)
    )


def release_stopped_work(
    payload: dict[str, Any],
    room: str,
    targets: set[str],
    confirm: Callable[[str], bool],
) -> str:
    """Release matching checkpoint records; leave all agents stopped.

    Host setup locks prevent a normal start during recovery. The supervisor's
    own state locks also exclude another checkpoint writer. Coord records the
    request before state changes and completion afterward. A partial failure
    leaves backups and names the agents already changed; repeating the exact
    selection releases the remaining records without resetting other work.
    """
    from .commands.agent import _agent_host_setup_lock

    supervisor = _supervisor()
    if not targets or any(not supervisor._valid_target_url(target) for target in targets):
        raise FactoryContractError("release requires exact absolute target URLs")
    agents = sorted({role["agent"] for role in payload["roles"].values()})
    with ExitStack() as locks:
        for agent in agents:
            if not load_agent(agent):
                raise FactoryContractError(f"factory agent {agent!r} is not registered")
            locks.enter_context(_agent_host_setup_lock(agent))
        plans = _collect_releases(supervisor, agents, room, targets, locks)
        if not plans:
            return "No matching checkpointed work; nothing changed."
        selection = "\n".join(f"target={target}" for target in sorted(targets))
        details = "\n".join(
            f"agent={agent} in_flight={len(before['in_flight']) - len(after['in_flight'])} "
            f"awaiting_handoffs={len(before['awaiting_handoffs']) - len(after['awaiting_handoffs'])}"
            for agent, _path, _raw, before, after in plans
        )
        description = f"factory={payload['name']} room={room}\n{selection}\n{details}"
        if not confirm(description):
            return "Release cancelled; no checkpoint or room message changed."
        return _apply_releases(supervisor, plans, room, description)
