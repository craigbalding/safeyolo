"""Declarative, operator-approved contracts for supervised coord factories."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import get_config_dir

SCHEMA = "safeyolo.factory/v1"
_NAME_RE = re.compile(r"[A-Za-z0-9_.-]+")
_TYPE_RE = re.compile(r"[A-Z][A-Z0-9_]*")


class FactoryContractError(ValueError):
    """A factory file or stored snapshot is invalid."""


@dataclass(frozen=True)
class Role:
    name: str
    agent: str
    contract: str
    contract_sha256: str
    contract_text: str


@dataclass(frozen=True)
class Handoff:
    request: str
    source: str
    destination: str
    responses: tuple[str, ...]


@dataclass(frozen=True)
class FactoryContract:
    name: str
    room: str
    roles: tuple[Role, ...]
    handoffs: tuple[Handoff, ...]

    @property
    def agents(self) -> tuple[str, ...]:
        return tuple(role.agent for role in self.roles)

    def snapshot_payload(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "name": self.name,
            "room": self.room,
            "roles": {
                role.name: {
                    "agent": role.agent,
                    "contract": role.contract,
                    "contract_sha256": role.contract_sha256,
                    "contract_text": role.contract_text,
                }
                for role in self.roles
            },
            "handoffs": [
                {
                    "request": handoff.request,
                    "from": handoff.source,
                    "to": handoff.destination,
                    "responses": list(handoff.responses),
                }
                for handoff in self.handoffs
            ],
        }


def _simple_name(label: str, value: Any) -> str:
    if (
        not isinstance(value, str)
        or _NAME_RE.fullmatch(value) is None
        or value in {".", ".."}
    ):
        raise FactoryContractError(f"{label} must be one simple name")
    return value


def _message_type(label: str, value: Any) -> str:
    if not isinstance(value, str) or _TYPE_RE.fullmatch(value) is None:
        raise FactoryContractError(f"{label} must be one uppercase message type")
    return value


def _exact_keys(label: str, value: Any, expected: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        missing = sorted(expected - set(value)) if isinstance(value, dict) else sorted(expected)
        extra = sorted(set(value) - expected) if isinstance(value, dict) else []
        detail = []
        if missing:
            detail.append(f"missing {', '.join(missing)}")
        if extra:
            detail.append(f"unknown {', '.join(extra)}")
        raise FactoryContractError(f"{label} must contain exactly {', '.join(sorted(expected))} ({'; '.join(detail)})")
    return value


def load_factory_file(path: Path) -> FactoryContract:
    source = path.expanduser().resolve()
    try:
        raw = tomllib.loads(source.read_text())
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise FactoryContractError(f"cannot read factory file {source}: {exc}") from exc
    _exact_keys("factory", raw, {"schema", "name", "room", "roles", "handoffs"})
    if raw["schema"] != SCHEMA:
        raise FactoryContractError(f"schema must be {SCHEMA!r}")
    name = _simple_name("name", raw["name"])
    room = _simple_name("room", raw["room"])

    raw_roles = raw["roles"]
    if not isinstance(raw_roles, dict) or not raw_roles:
        raise FactoryContractError("roles must be a non-empty table")
    roles: list[Role] = []
    seen_agents: set[str] = set()
    for role_name, raw_role in raw_roles.items():
        role_name = _simple_name("role name", role_name)
        _exact_keys(f"roles.{role_name}", raw_role, {"agent", "contract"})
        agent = _simple_name(f"roles.{role_name}.agent", raw_role["agent"])
        if agent in seen_agents:
            raise FactoryContractError(f"agent {agent!r} is bound to more than one role")
        seen_agents.add(agent)
        contract = raw_role["contract"]
        if not isinstance(contract, str) or not contract or Path(contract).is_absolute():
            raise FactoryContractError(f"roles.{role_name}.contract must be an explicit relative path")
        contract_path = (source.parent / contract).resolve()
        try:
            contract_text = contract_path.read_text()
        except (OSError, UnicodeError) as exc:
            raise FactoryContractError(f"cannot read role contract {contract!r}: {exc}") from exc
        contract_hash = hashlib.sha256(contract_text.encode()).hexdigest()
        roles.append(Role(role_name, agent, contract, contract_hash, contract_text))

    raw_handoffs = raw["handoffs"]
    if not isinstance(raw_handoffs, list) or not raw_handoffs:
        raise FactoryContractError("handoffs must be a non-empty array of tables")
    role_names = {role.name for role in roles}
    handoffs: list[Handoff] = []
    inbound_requests: set[tuple[str, str]] = set()
    for index, raw_handoff in enumerate(raw_handoffs):
        label = f"handoffs[{index}]"
        _exact_keys(label, raw_handoff, {"request", "from", "to", "responses"})
        request = _message_type(f"{label}.request", raw_handoff["request"])
        source_role = _simple_name(f"{label}.from", raw_handoff["from"])
        destination_role = _simple_name(f"{label}.to", raw_handoff["to"])
        if source_role not in role_names or destination_role not in role_names:
            raise FactoryContractError(f"{label} references an unknown role")
        if source_role == destination_role:
            raise FactoryContractError(f"{label} must connect two different roles")
        responses_raw = raw_handoff["responses"]
        if not isinstance(responses_raw, list) or not responses_raw:
            raise FactoryContractError(f"{label}.responses must be a non-empty array")
        responses = tuple(_message_type(f"{label}.responses", item) for item in responses_raw)
        if len(set(responses)) != len(responses):
            raise FactoryContractError(f"{label}.responses contains a duplicate")
        route_key = (destination_role, request)
        if route_key in inbound_requests:
            raise FactoryContractError(f"role {destination_role!r} has more than one inbound {request} request")
        inbound_requests.add(route_key)
        handoffs.append(Handoff(request, source_role, destination_role, responses))

    # A token cannot be both a request and a response for the same receiving
    # role; that would make terminal handling depend on message history.
    for role in roles:
        requests = {handoff.request for handoff in handoffs if handoff.destination == role.name}
        responses = {response for handoff in handoffs if handoff.source == role.name for response in handoff.responses}
        overlap = requests & responses
        if overlap:
            raise FactoryContractError(f"role {role.name!r} has ambiguous request/response type {sorted(overlap)[0]!r}")
    return FactoryContract(name, room, tuple(roles), tuple(handoffs))


def canonical_snapshot(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def snapshot_id(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_snapshot(payload)).hexdigest()


def factories_dir() -> Path:
    return get_config_dir() / "factories"


def _contained_path(root: Path, *parts: str) -> Path:
    candidate = root.joinpath(*parts).resolve()
    if not candidate.is_relative_to(root):
        raise FactoryContractError(f"factory path escapes {root}")
    return candidate


def _factory_root(name: str) -> Path:
    name = _simple_name("factory name", name)
    factories = factories_dir().resolve()
    root = _contained_path(factories, name)
    if root == factories:
        raise FactoryContractError(f"factory path escapes {factories}")
    return root


def store_snapshot(contract: FactoryContract) -> tuple[str, Path]:
    payload = contract.snapshot_payload()
    identifier = snapshot_id(payload)
    root = _factory_root(contract.name)
    snapshots = _contained_path(root, "snapshots")
    snapshots.mkdir(parents=True, exist_ok=True)
    snapshot_path = _contained_path(root, "snapshots", f"{identifier}.json")
    encoded = canonical_snapshot(payload)
    try:
        descriptor = os.open(snapshot_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if snapshot_path.read_bytes() != encoded:
            raise FactoryContractError(f"immutable snapshot collision at {snapshot_path}")
    else:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    _atomic_write(_contained_path(root, "active"), f"{identifier}\n".encode())
    return identifier, snapshot_path


def load_active_snapshot(name: str) -> tuple[str, Path, dict[str, Any]]:
    name = _simple_name("factory name", name)
    root = _factory_root(name)
    try:
        identifier = _contained_path(root, "active").read_text().strip()
    except OSError as exc:
        raise FactoryContractError(f"factory {name!r} has no applied snapshot") from exc
    if re.fullmatch(r"[0-9a-f]{64}", identifier) is None:
        raise FactoryContractError(f"factory {name!r} has an invalid active snapshot pointer")
    path = _contained_path(root, "snapshots", f"{identifier}.json")
    try:
        payload = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FactoryContractError(f"cannot read factory snapshot {path}: {exc}") from exc
    if not isinstance(payload, dict) or snapshot_id(payload) != identifier:
        raise FactoryContractError(f"factory snapshot {identifier} failed its content hash")
    # Revalidate the security-relevant stored shape without consulting live
    # Markdown files. The host setup performs the same narrow checks per role.
    _validate_snapshot_payload(payload, expected_name=name)
    return identifier, path, payload


def _validate_snapshot_payload(payload: dict[str, Any], *, expected_name: str) -> None:
    _exact_keys("snapshot", payload, {"schema", "name", "room", "roles", "handoffs"})
    if payload["schema"] != SCHEMA or payload["name"] != expected_name:
        raise FactoryContractError("snapshot schema or factory name does not match")
    _simple_name("snapshot room", payload["room"])
    roles = payload["roles"]
    if not isinstance(roles, dict) or not roles:
        raise FactoryContractError("snapshot roles are invalid")
    agents: set[str] = set()
    for role_name, role in roles.items():
        _simple_name("snapshot role", role_name)
        _exact_keys(
            f"snapshot role {role_name}",
            role,
            {"agent", "contract", "contract_sha256", "contract_text"},
        )
        agent = _simple_name("snapshot agent", role["agent"])
        if agent in agents:
            raise FactoryContractError("snapshot binds one agent to multiple roles")
        agents.add(agent)
        if not isinstance(role["contract"], str) or not isinstance(role["contract_text"], str):
            raise FactoryContractError("snapshot role contract is invalid")
        digest = role["contract_sha256"]
        actual = hashlib.sha256(role["contract_text"].encode()).hexdigest()
        if digest != actual:
            raise FactoryContractError(f"snapshot role {role_name!r} contract hash does not match")
    handoffs = payload["handoffs"]
    if not isinstance(handoffs, list) or not handoffs:
        raise FactoryContractError("snapshot handoffs are invalid")
    for handoff in handoffs:
        _exact_keys("snapshot handoff", handoff, {"request", "from", "to", "responses"})
        _message_type("snapshot request", handoff["request"])
        if handoff["from"] not in roles or handoff["to"] not in roles:
            raise FactoryContractError("snapshot handoff references an unknown role")
        responses = handoff["responses"]
        if not isinstance(responses, list) or not responses:
            raise FactoryContractError("snapshot handoff responses are invalid")
        for response in responses:
            _message_type("snapshot response", response)


def _atomic_write(path: Path, encoded: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
