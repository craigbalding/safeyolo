"""Centralized read/write for agent config in policy.toml [agents] section."""

import fcntl
import ipaddress
import json
import logging
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import tomlkit

from .config import get_agent_map_path, get_config_dir

log = logging.getLogger("safeyolo.agents-store")

TAILNET_PORT_START = 8443
TAILNET_PORT_END = 8999
NETWORK_SLOT_MAX = 65534


def _policy_toml_path() -> Path:
    """Path to ~/.safeyolo/policy.toml."""
    return get_config_dir() / "policy.toml"


def _lock_path() -> Path:
    """Path to lock file sibling."""
    return get_config_dir() / ".policy.toml.lock"


def _load_doc() -> tomlkit.TOMLDocument:
    """Load policy.toml as a TOMLDocument. Returns empty doc if missing.

    Raises on parse errors — a corrupted policy.toml must NOT be silently
    replaced with an empty document, as that would destroy all policy data.
    """
    path = _policy_toml_path()
    if not path.exists():
        return tomlkit.document()
    return tomlkit.parse(path.read_text())


def _save_doc(doc: tomlkit.TOMLDocument) -> None:
    """Atomic write of TOMLDocument back to policy.toml."""
    path = _policy_toml_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    content = tomlkit.dumps(doc)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".toml", dir=path.parent, delete=False
    ) as tmp:
        tmp.write(content)
        tmp_path = tmp.name
    shutil.move(tmp_path, path)


def _locked_mutate(mutate_fn: Callable[[tomlkit.TOMLDocument], Any]) -> Any:
    """Read-modify-write policy.toml under exclusive file lock."""
    lock = _lock_path()
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.touch()
    with open(lock) as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            doc = _load_doc()
            result = mutate_fn(doc)
            _save_doc(doc)
            return result
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def _get_agents(doc: tomlkit.TOMLDocument) -> dict:
    """Extract [agents] section as plain dict."""
    agents = doc.get("agents")
    if agents is None:
        return {}
    if hasattr(agents, "unwrap"):
        return agents.unwrap()
    return dict(agents)


def _ensure_agents_table(doc: tomlkit.TOMLDocument):
    """Get or create the [agents] table."""
    if "agents" not in doc:
        doc.add("agents", tomlkit.table())
    return doc["agents"]


def _dict_to_toml_table(metadata: dict) -> tomlkit.items.Table:
    """Convert a metadata dict to a tomlkit Table with proper nesting."""
    agent_table = tomlkit.table()
    for key, value in metadata.items():
        if key == "services" and isinstance(value, dict):
            svc_table = tomlkit.table()
            for svc_name, svc_config in value.items():
                svc_entry = tomlkit.table()
                if isinstance(svc_config, dict):
                    for sk, sv in svc_config.items():
                        svc_entry.add(sk, sv)
                else:
                    svc_entry.add("capability", svc_config)
                svc_table.add(svc_name, svc_entry)
            agent_table.add("services", svc_table)
        elif key in ("contract_bindings", "grants") and isinstance(value, list):
            aot = tomlkit.aot()
            for item in value:
                entry = tomlkit.table()
                for ik, iv in item.items():
                    if isinstance(iv, dict):
                        sub = tomlkit.table()
                        for dk, dv in iv.items():
                            sub.add(dk, dv)
                        entry.add(ik, sub)
                    else:
                        entry.add(ik, iv)
                aot.append(entry)
            agent_table.add(key, aot)
        else:
            agent_table.add(key, value)
    return agent_table


def load_all_agents() -> dict[str, dict]:
    """Read all agent entries from policy.toml [agents]. Returns {} if missing."""
    doc = _load_doc()
    return _get_agents(doc)


def load_agent(name: str) -> dict:
    """Read a single agent entry. Returns {} if not found."""
    return load_all_agents().get(name, {})


def save_agent(name: str, metadata: dict) -> None:
    """Write a single agent entry (lock + read-modify-write)."""
    def mutate(doc):
        agents = _ensure_agents_table(doc)
        if name in agents:
            del agents[name]
        agents.add(name, _dict_to_toml_table(metadata))

    _locked_mutate(mutate)


def _active_network_slots() -> dict[str, int]:
    """Return valid runtime attribution slots from agent_map.json."""
    try:
        agent_map = json.loads(get_agent_map_path().read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}

    first = int(ipaddress.IPv4Address("10.200.0.1"))
    last = int(ipaddress.IPv4Address("10.200.255.255"))
    active: dict[str, int] = {}
    for agent, entry in agent_map.items():
        if not isinstance(entry, dict):
            continue
        try:
            address = int(ipaddress.IPv4Address(entry.get("ip", "")))
        except (ipaddress.AddressValueError, TypeError):
            continue
        if first <= address <= last:
            active[agent] = address - first
    return active


def reserve_agent_network_slot(name: str) -> int:
    """Return and persist a stable, unique 10.200/16 attribution slot.

    Legacy agents have no saved slot. Their currently active agent-map entries
    are treated as occupied so upgrading SafeYolo cannot assign a live address
    to a second agent. The policy lock serializes concurrent agent starts.
    """
    active = _active_network_slots()

    def mutate(doc):
        all_agents = _get_agents(doc)
        if name not in all_agents:
            raise KeyError(f"Agent not found: {name}")

        saved: dict[str, int] = {}
        slot_owners: dict[int, str] = {}
        for other_name, value in all_agents.items():
            if not isinstance(value, dict):
                continue
            slot = value.get("network_slot")
            if slot is None:
                continue
            if type(slot) is not int or not 0 <= slot <= NETWORK_SLOT_MAX:
                raise ValueError(
                    f"agent {other_name!r} has invalid network slot {slot!r}"
                )
            if slot in slot_owners:
                raise ValueError(
                    f"network slot {slot} is already assigned to both "
                    f"{slot_owners[slot]!r} and {other_name!r}"
                )
            saved[other_name] = slot
            slot_owners[slot] = other_name

        used = {
            slot for other_name, slot in saved.items() if other_name != name
        }
        used.update(
            slot for other_name, slot in active.items() if other_name != name
        )

        current = saved.get(name)
        if current is not None and current not in used:
            return current

        # Preserve the address of a running legacy agent when it is unique.
        own_active = active.get(name)
        if current is None and own_active is not None and own_active not in used:
            slot = own_active
        else:
            slot = next(
                (
                    candidate
                    for candidate in range(NETWORK_SLOT_MAX + 1)
                    if candidate not in used
                ),
                None,
            )
            if slot is None:
                raise ValueError("no free SafeYolo agent network slots")

        metadata = dict(all_agents[name])
        metadata["network_slot"] = slot
        agents = _ensure_agents_table(doc)
        del agents[name]
        agents.add(name, _dict_to_toml_table(metadata))
        return slot

    return _locked_mutate(mutate)


def reserve_agent_tailnet_port_change(
    name: str,
    requested: int | None = None,
) -> tuple[int, int | None]:
    """Persist a unique tailnet HTTPS port and return it with its prior value.

    Allocation shares the policy lock with other agent metadata mutations, so
    concurrent preview commands cannot reserve the same SafeYolo-managed port.
    An explicit port may sit outside the automatic range, but still cannot be
    assigned to two configured agents. The prior value lets a caller roll back
    a provisional reservation when preview startup fails.
    """
    if requested is not None and (
        type(requested) is not int or not 1 <= requested <= 65535
    ):
        raise ValueError("tailnet HTTPS port must be 1-65535")

    def mutate(doc):
        all_agents = _get_agents(doc)
        if name not in all_agents:
            raise KeyError(f"Agent not found: {name}")

        metadata = dict(all_agents[name])
        current = metadata.get("tailnet_port")
        used = {
            value.get("tailnet_port")
            for other_name, value in all_agents.items()
            if other_name != name
            and isinstance(value, dict)
            and type(value.get("tailnet_port")) is int
        }
        if requested is None and current is not None and type(current) is not int:
            raise ValueError(
                f"agent {name!r} has invalid tailnet HTTPS port {current!r}"
            )
        if requested is None and type(current) is int:
            if not 1 <= current <= 65535:
                raise ValueError(
                    f"agent {name!r} has invalid tailnet HTTPS port {current}"
                )
            if current in used:
                raise ValueError(
                    f"tailnet HTTPS port {current} is already assigned to another agent"
                )
            return current, current
        if requested is not None:
            port = requested
            if port in used:
                raise ValueError(
                    f"tailnet HTTPS port {port} is already assigned to another agent"
                )
        else:
            port = next(
                (candidate for candidate in range(TAILNET_PORT_START, TAILNET_PORT_END + 1)
                 if candidate not in used),
                None,
            )
            if port is None:
                raise ValueError(
                    f"no free automatic tailnet ports in "
                    f"{TAILNET_PORT_START}-{TAILNET_PORT_END}"
                )

        metadata["tailnet_port"] = port
        agents = _ensure_agents_table(doc)
        del agents[name]
        agents.add(name, _dict_to_toml_table(metadata))
        previous = current if type(current) is int else None
        return port, previous

    return _locked_mutate(mutate)


def reserve_agent_tailnet_port(name: str, requested: int | None = None) -> int:
    """Return and persist a unique tailnet HTTPS port for an agent."""
    port, _previous = reserve_agent_tailnet_port_change(name, requested)
    return port


def restore_agent_tailnet_port(
    name: str,
    expected: int,
    previous: int | None,
) -> bool:
    """Compare-and-swap a provisional reservation back to its prior value."""
    if type(expected) is not int or not 1 <= expected <= 65535:
        raise ValueError("tailnet HTTPS port must be 1-65535")
    if previous is not None and (
        type(previous) is not int or not 1 <= previous <= 65535
    ):
        raise ValueError("previous tailnet HTTPS port must be 1-65535")

    def mutate(doc):
        all_agents = _get_agents(doc)
        if name not in all_agents:
            return False
        metadata = dict(all_agents[name])
        if metadata.get("tailnet_port") != expected:
            return False
        if previous is None:
            metadata.pop("tailnet_port", None)
        else:
            metadata["tailnet_port"] = previous
        agents = _ensure_agents_table(doc)
        del agents[name]
        agents.add(name, _dict_to_toml_table(metadata))
        return True

    return _locked_mutate(mutate)


def remove_agent(name: str) -> bool:
    """Delete an agent entry. Returns True if it existed."""
    def mutate(doc):
        agents = doc.get("agents")
        if agents is None or name not in agents:
            return False
        del agents[name]
        return True

    return _locked_mutate(mutate)
