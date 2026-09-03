"""Declarative, operator-approved contracts for supervised coord factories."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import tomllib
from collections.abc import Iterable
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
    contract_source: Path
    contract_bytes: int
    contract_sha256: str
    contract_text: str


@dataclass(frozen=True)
class Handoff:
    request: str
    source: str
    destination: str
    responses: tuple[str, ...]
    response_to: tuple[str, ...]


@dataclass(frozen=True)
class OperatorInput:
    destination: str
    types: tuple[str, ...]


@dataclass(frozen=True)
class FactoryContract:
    name: str
    room: str
    roles: tuple[Role, ...]
    handoffs: tuple[Handoff, ...]
    operator_input: OperatorInput

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
                    "contract_bytes": role.contract_bytes,
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
                    "response_to": list(handoff.response_to),
                }
                for handoff in self.handoffs
            ],
            "operator_input": {
                "to": self.operator_input.destination,
                "types": list(self.operator_input.types),
            },
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
    if isinstance(raw, dict) and "operator_input" not in raw:
        raise FactoryContractError(
            "factory must declare operator_input so an authenticated operator can activate it"
        )
    _exact_keys(
        "factory",
        raw,
        {"schema", "name", "room", "roles", "handoffs", "operator_input"},
    )
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
            contract_encoded = contract_path.read_bytes()
            contract_text = contract_encoded.decode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise FactoryContractError(f"cannot read role contract {contract!r}: {exc}") from exc
        contract_hash = hashlib.sha256(contract_encoded).hexdigest()
        roles.append(
            Role(
                role_name,
                agent,
                contract,
                contract_path,
                len(contract_encoded),
                contract_hash,
                contract_text,
            )
        )

    raw_handoffs = raw["handoffs"]
    if not isinstance(raw_handoffs, list) or not raw_handoffs:
        raise FactoryContractError("handoffs must be a non-empty array of tables")
    role_names = {role.name for role in roles}
    handoffs: list[Handoff] = []
    inbound_requests: set[tuple[str, str]] = set()
    for index, raw_handoff in enumerate(raw_handoffs):
        label = f"handoffs[{index}]"
        if isinstance(raw_handoff, dict) and "response_to" not in raw_handoff:
            raw_handoff = {
                **raw_handoff,
                "response_to": [raw_handoff.get("from")],
            }
        _exact_keys(
            label,
            raw_handoff,
            {"request", "from", "to", "responses", "response_to"},
        )
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
        response_to_raw = raw_handoff["response_to"]
        if not isinstance(response_to_raw, list) or not response_to_raw:
            raise FactoryContractError(f"{label}.response_to must be a non-empty array")
        response_to = tuple(
            _simple_name(f"{label}.response_to", item) for item in response_to_raw
        )
        if len(set(response_to)) != len(response_to):
            raise FactoryContractError(f"{label}.response_to contains a duplicate")
        if any(role not in role_names for role in response_to):
            raise FactoryContractError(f"{label}.response_to references an unknown role")
        if source_role not in response_to:
            raise FactoryContractError(f"{label}.response_to must include the source role")
        route_key = (destination_role, request)
        if route_key in inbound_requests:
            raise FactoryContractError(f"role {destination_role!r} has more than one inbound {request} request")
        inbound_requests.add(route_key)
        handoffs.append(
            Handoff(request, source_role, destination_role, responses, response_to)
        )

    # A token cannot be both a request and a response for the same receiving
    # role; that would make terminal handling depend on message history.
    for role in roles:
        requests = {handoff.request for handoff in handoffs if handoff.destination == role.name}
        responses = {
            response
            for handoff in handoffs
            if role.name in handoff.response_to
            for response in handoff.responses
        }
        overlap = requests & responses
        if overlap:
            raise FactoryContractError(f"role {role.name!r} has ambiguous request/response type {sorted(overlap)[0]!r}")

    raw_operator_input = _exact_keys(
        "operator_input",
        raw["operator_input"],
        {"to", "types"},
    )
    operator_destination = _simple_name("operator_input.to", raw_operator_input["to"])
    if operator_destination not in role_names:
        raise FactoryContractError("operator_input.to references an unknown role")
    operator_types_raw = raw_operator_input["types"]
    if not isinstance(operator_types_raw, list) or not operator_types_raw:
        raise FactoryContractError("operator_input.types must be a non-empty array")
    operator_types = tuple(
        _message_type("operator_input.types", item) for item in operator_types_raw
    )
    if len(set(operator_types)) != len(operator_types):
        raise FactoryContractError("operator_input.types contains a duplicate")
    handoff_types = {
        item
        for handoff in handoffs
        for item in (handoff.request, *handoff.responses)
    }
    overlap = handoff_types & set(operator_types)
    if overlap:
        raise FactoryContractError(
            f"operator input cannot masquerade as handoff type {sorted(overlap)[0]!r}"
        )
    _validate_reachable_roles(
        role_names,
        ((handoff.source, handoff.destination) for handoff in handoffs),
        operator_destination,
    )
    return FactoryContract(
        name,
        room,
        tuple(roles),
        tuple(handoffs),
        OperatorInput(operator_destination, operator_types),
    )


def _validate_reachable_roles(
    role_names: set[str],
    edges: Iterable[tuple[str, str]],
    operator_destination: str,
) -> None:
    reachable = {operator_destination}
    edge_list = tuple(edges)
    while True:
        expanded = reachable | {
            destination
            for source, destination in edge_list
            if source in reachable
        }
        if expanded == reachable:
            break
        reachable = expanded
    unreachable = sorted(role_names - reachable)
    if unreachable:
        raise FactoryContractError(
            "factory roles are unreachable from operator_input.to: "
            + ", ".join(unreachable)
        )


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
    if isinstance(payload, dict) and "operator_input" not in payload:
        raise FactoryContractError(
            "factory snapshot has no operator_input and cannot be activated; check and apply a reachable contract"
        )
    _exact_keys(
        "snapshot",
        payload,
        {"schema", "name", "room", "roles", "handoffs", "operator_input"},
    )
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
            {"agent", "contract", "contract_bytes", "contract_sha256", "contract_text"},
        )
        agent = _simple_name("snapshot agent", role["agent"])
        if agent in agents:
            raise FactoryContractError("snapshot binds one agent to multiple roles")
        agents.add(agent)
        if not isinstance(role["contract"], str) or not isinstance(role["contract_text"], str):
            raise FactoryContractError("snapshot role contract is invalid")
        contract_encoded = role["contract_text"].encode()
        contract_bytes = role["contract_bytes"]
        if (
            isinstance(contract_bytes, bool)
            or not isinstance(contract_bytes, int)
            or contract_bytes != len(contract_encoded)
        ):
            raise FactoryContractError(
                f"snapshot role {role_name!r} contract byte count does not match"
            )
        digest = role["contract_sha256"]
        actual = hashlib.sha256(contract_encoded).hexdigest()
        if digest != actual:
            raise FactoryContractError(f"snapshot role {role_name!r} contract hash does not match")
    handoffs = payload["handoffs"]
    if not isinstance(handoffs, list) or not handoffs:
        raise FactoryContractError("snapshot handoffs are invalid")
    handoff_edges = []
    handoff_types = set()
    for handoff in handoffs:
        if not isinstance(handoff, dict):
            raise FactoryContractError("snapshot handoff must be an object")
        handoff_keys = set(handoff)
        required_handoff_keys = {"request", "from", "to", "responses"}
        if handoff_keys not in (
            required_handoff_keys,
            required_handoff_keys | {"response_to"},
        ):
            raise FactoryContractError("snapshot handoff has an invalid shape")
        request = _message_type("snapshot request", handoff["request"])
        if handoff["from"] not in roles or handoff["to"] not in roles:
            raise FactoryContractError("snapshot handoff references an unknown role")
        handoff_edges.append((handoff["from"], handoff["to"]))
        handoff_types.add(request)
        responses = handoff["responses"]
        if not isinstance(responses, list) or not responses:
            raise FactoryContractError("snapshot handoff responses are invalid")
        for response in responses:
            handoff_types.add(_message_type("snapshot response", response))
        response_to = handoff.get("response_to", [handoff["from"]])
        if (
            not isinstance(response_to, list)
            or not response_to
            or len(set(response_to)) != len(response_to)
            or any(role not in roles for role in response_to)
            or handoff["from"] not in response_to
        ):
            raise FactoryContractError("snapshot handoff response_to is invalid")

    operator_input = _exact_keys(
        "snapshot operator_input",
        payload["operator_input"],
        {"to", "types"},
    )
    destination = _simple_name("snapshot operator_input.to", operator_input["to"])
    if destination not in roles:
        raise FactoryContractError("snapshot operator_input.to references an unknown role")
    operator_types_raw = operator_input["types"]
    if not isinstance(operator_types_raw, list) or not operator_types_raw:
        raise FactoryContractError("snapshot operator_input.types are invalid")
    operator_types = [
        _message_type("snapshot operator input type", item)
        for item in operator_types_raw
    ]
    if len(set(operator_types)) != len(operator_types):
        raise FactoryContractError("snapshot operator_input.types contains a duplicate")
    overlap = handoff_types & set(operator_types)
    if overlap:
        raise FactoryContractError(
            f"snapshot operator input masquerades as handoff type {sorted(overlap)[0]!r}"
        )
    _validate_reachable_roles(set(roles), handoff_edges, destination)


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
