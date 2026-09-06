#!/usr/bin/env python3
"""Stage one verified factory role for the common supervised harness."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

NAME_RE = re.compile(r"[A-Za-z0-9_.-]+")
TYPE_RE = re.compile(r"[A-Z][A-Z0-9_]*")
HARNESSES = {"codex", "pi"}
ROLE_KEYS = {
    "agent",
    "contract",
    "contract_bytes",
    "contract_sha256",
    "contract_text",
}


def fail(message: str) -> None:
    raise SystemExit(f"factory-supervisor-setup: {message}")


def atomic_write(path: Path, value: str) -> None:
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        temporary_path.replace(path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def load_snapshot(path: Path) -> dict[str, Any]:
    try:
        snapshot = json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"cannot read factory snapshot: {exc}")
    if not isinstance(snapshot, dict) or set(snapshot) != {
        "schema",
        "name",
        "room",
        "roles",
        "handoffs",
        "operator_input",
    }:
        fail("invalid factory snapshot shape")
    if snapshot.get("schema") != "safeyolo.factory/v1":
        fail("unsupported factory snapshot schema")
    return snapshot


def runtime_factory(
    snapshot: dict[str, Any], agent_name: str, role_name: str, harness: str
) -> tuple[dict[str, Any], str]:
    room = snapshot.get("room")
    roles = snapshot.get("roles")
    handoffs = snapshot.get("handoffs")
    operator_input = snapshot.get("operator_input")
    if NAME_RE.fullmatch(str(room)) is None or not isinstance(roles, dict) or role_name not in roles:
        fail("factory role or room is invalid")
    role = roles[role_name]
    if (
        not isinstance(role, dict)
        or not ROLE_KEYS.issubset(role)
        or not set(role).issubset(ROLE_KEYS | {"harness", "args"})
    ):
        fail("factory role binding is invalid")
    role_harness = role.get("harness", "codex")
    if role_harness not in HARNESSES or role_harness != harness:
        fail("factory role is bound to a different harness")
    harness_args = role.get("args")
    if harness_args is not None and (
        not isinstance(harness_args, list) or any(not isinstance(item, str) or "\0" in item for item in harness_args)
    ):
        fail("factory role arguments are invalid")
    contract_text = role.get("contract_text")
    if role.get("agent") != agent_name or not isinstance(contract_text, str):
        fail("factory role is not bound to this agent")
    contract_encoded = contract_text.encode()
    contract_hash = hashlib.sha256(contract_encoded).hexdigest()
    if role.get("contract_bytes") != len(contract_encoded):
        fail("factory role contract byte count does not match")
    if role.get("contract_sha256") != contract_hash:
        fail("factory role contract hash does not match")

    role_agents: dict[str, str] = {}
    for key, value in roles.items():
        if NAME_RE.fullmatch(str(key)) is None or not isinstance(value, dict):
            fail("invalid factory role map")
        bound_agent = value.get("agent")
        if NAME_RE.fullmatch(str(bound_agent)) is None:
            fail("invalid factory agent binding")
        role_agents[key] = bound_agent

    if not isinstance(handoffs, list) or not handoffs:
        fail("factory has no handoffs")
    runtime_handoffs = []
    coordinators = []
    handoff_types = set()
    handoff_edges = []
    for handoff in handoffs:
        required = {"request", "from", "to", "responses"}
        if not isinstance(handoff, dict) or set(handoff) not in (
            required,
            required | {"response_to"},
        ):
            fail("invalid factory handoff")
        request = handoff.get("request")
        source = handoff.get("from")
        destination = handoff.get("to")
        responses = handoff.get("responses")
        response_to = handoff.get("response_to", [source])
        if (
            TYPE_RE.fullmatch(str(request)) is None
            or source not in role_agents
            or destination not in role_agents
            or not isinstance(responses, list)
            or not responses
            or any(TYPE_RE.fullmatch(str(item)) is None for item in responses)
            or not isinstance(response_to, list)
            or not response_to
            or len(set(response_to)) != len(response_to)
            or any(item not in role_agents for item in response_to)
            or source not in response_to
        ):
            fail("invalid factory handoff values")
        runtime_handoffs.append(
            {
                "request": request,
                "from": source,
                "to": destination,
                "responses": responses,
                "response_to": response_to,
            }
        )
        handoff_edges.append((source, destination))
        handoff_types.add(request)
        handoff_types.update(responses)
        if request == "TASK" and role_agents[source] not in coordinators:
            coordinators.append(role_agents[source])
    if not coordinators:
        fail("factory must declare a TASK coordinator handoff")

    if not isinstance(operator_input, dict) or set(operator_input) != {"to", "types"}:
        fail("invalid factory operator input")
    operator_role = operator_input.get("to")
    operator_types = operator_input.get("types")
    if (
        operator_role not in role_agents
        or not isinstance(operator_types, list)
        or not operator_types
        or any(TYPE_RE.fullmatch(str(item)) is None for item in operator_types)
        or len(set(operator_types)) != len(operator_types)
        or handoff_types.intersection(operator_types)
    ):
        fail("invalid factory operator input values")
    reachable = {operator_role}
    while True:
        expanded = reachable | {destination for source, destination in handoff_edges if source in reachable}
        if expanded == reachable:
            break
        reachable = expanded
    unreachable = sorted(set(role_agents) - reachable)
    if unreachable:
        fail("factory roles are unreachable from operator input: " + ", ".join(unreachable))

    snapshot_id = hashlib.sha256(
        (json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    ).hexdigest()
    config = {
        "agent_name": agent_name,
        "agent_room": f"{agent_name}-agent",
        "rooms": [room],
        "coordinators": coordinators,
        "harness": harness,
        "workspace": "/workspace",
        "factory": {
            "schema": snapshot["schema"],
            "name": snapshot["name"],
            "role": role_name,
            "roles": role_agents,
            "handoffs": runtime_handoffs,
            "operator_input": {"to": operator_role, "types": operator_types},
            "contract_sha256": contract_hash,
            "snapshot_id": snapshot_id,
        },
    }
    return config, contract_text


def main() -> None:
    if len(sys.argv) != 7:
        fail("expected CONFIG INSTRUCTIONS AGENT SNAPSHOT ROLE HARNESS")
    config_path, instructions_path, agent_name, snapshot_path, role_name, harness = (
        Path(sys.argv[1]),
        Path(sys.argv[2]),
        sys.argv[3],
        Path(sys.argv[4]),
        sys.argv[5],
        sys.argv[6],
    )
    if NAME_RE.fullmatch(agent_name) is None or NAME_RE.fullmatch(role_name) is None or harness not in HARNESSES:
        fail("invalid factory agent, role, or harness")
    snapshot = load_snapshot(snapshot_path)
    config, contract_text = runtime_factory(snapshot, agent_name, role_name, harness)
    try:
        baseline = instructions_path.read_text()
    except (OSError, UnicodeError) as exc:
        fail(f"cannot read SafeYolo instructions: {exc}")
    atomic_write(
        config_path,
        json.dumps(config, sort_keys=True, separators=(",", ":")) + "\n",
    )
    atomic_write(
        instructions_path,
        baseline.rstrip() + "\n\n---\n\n" + contract_text.lstrip(),
    )


if __name__ == "__main__":
    main()
