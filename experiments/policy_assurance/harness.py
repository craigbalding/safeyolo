"""Shared real-policy harness for policy assurance experiments."""

from __future__ import annotations

import hashlib
import json
import multiprocessing
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import patch

import tomlkit

from safeyolo.policy.compiler import compile_policy
from safeyolo.policy.engine import PolicyEngine
from safeyolo.policy.models import UnifiedPolicy
from safeyolo.policy.toml_normalize import denormalize

EFFECT_RANK = {
    "deny": 0,
    "budget_exceeded": 0,
    "prompt": 1,
    "allow": 2,
}


@dataclass(frozen=True)
class PolicyWorld:
    """A policy plus names used to build a broad but bounded probe surface."""

    policy: dict[str, Any]
    agents: tuple[str, ...]
    hosts: tuple[str, ...]
    credentials: tuple[str, ...]

    @property
    def owner(self) -> str:
        return self.agents[0]

    @property
    def peer(self) -> str:
        return self.agents[1]

    @property
    def allow_host(self) -> str:
        return self.hosts[0]

    @property
    def deny_host(self) -> str:
        return self.hosts[1]

    @property
    def prompt_host(self) -> str:
        return self.hosts[2]

    @property
    def owned_host(self) -> str:
        return self.hosts[3]


@dataclass(frozen=True, order=True)
class Probe:
    kind: str
    agent: str
    host: str
    path: str
    method_or_credential: str


@dataclass(frozen=True)
class PermissionSurface:
    """Effective decisions for a deliberately varied request universe."""

    decisions: dict[Probe, str]

    def changed(self, other: PermissionSurface) -> dict[Probe, tuple[str, str]]:
        keys = self.decisions.keys() | other.decisions.keys()
        return {
            probe: (self.decisions.get(probe, "<missing>"), other.decisions.get(probe, "<missing>"))
            for probe in keys
            if self.decisions.get(probe) != other.decisions.get(probe)
        }

    def broadened(self, other: PermissionSurface) -> dict[Probe, tuple[str, str]]:
        return {
            probe: effects
            for probe, effects in self.changed(other).items()
            if EFFECT_RANK.get(effects[1], -1) > EFFECT_RANK.get(effects[0], -1)
        }


@dataclass(frozen=True)
class TransactionObservation:
    """One writer call observed across result, bytes, policy and audit planes."""

    result: Any = None
    exception_type: str | None = None
    exception_message: str | None = None
    original_hash: str | None = None
    final_hash: str | None = None
    toml_valid: bool = False
    active_decisions: PermissionSurface | None = None
    fresh_process_decisions: PermissionSurface | None = None
    unrelated_preserved: bool = False
    audit_events: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    temporary_files: tuple[str, ...] = field(default_factory=tuple)

    @property
    def reported_success(self) -> bool:
        return self.exception_type is None


def file_hash(path: Path) -> str | None:
    """Return a stable digest, including a distinct value for absence."""
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parseable_toml(path: Path) -> bool:
    try:
        tomlkit.parse(path.read_text())
    except (OSError, UnicodeError, tomlkit.exceptions.TOMLKitError):
        return False
    return True


def temporary_policy_files(path: Path) -> tuple[str, ...]:
    """Record residue without assigning cleanup semantics to it."""
    return tuple(
        sorted(
            candidate.name
            for candidate in path.parent.iterdir()
            if candidate != path and candidate.name != ".policy.toml.lock" and candidate.suffix == ".toml"
        )
    )


def observe_transaction(
    path: Path,
    world: PolicyWorld,
    operation: Callable[[], Any],
    *,
    engine: PolicyEngine | None = None,
    related: Callable[[Probe], bool] | None = None,
    audit_targets: tuple[str, ...] = ("safeyolo.policy.engine.write_event",),
    broad: bool = False,
) -> TransactionObservation:
    """Capture a consistent real-file transaction observation.

    ``related`` names probes the requested mutation is allowed to change. All
    other decisions form the unrelated-policy preservation check.
    """
    actual_engine = engine or engine_from_path(path)
    before = permission_surface(world, engine=actual_engine, broad=broad)
    original_hash = file_hash(path)
    events: list[dict[str, Any]] = []

    def record_event(event_type: str, **kwargs: Any) -> None:
        events.append({"event_type": event_type, **kwargs})

    patchers = [patch(target, autospec=True, side_effect=record_event) for target in audit_targets]
    result: Any = None
    exception_type = None
    exception_message = None
    try:
        for patcher in patchers:
            patcher.start()
        try:
            result = operation()
        except Exception as exc:  # the exception is experiment evidence
            exception_type = type(exc).__name__
            exception_message = str(exc)
    finally:
        for patcher in reversed(patchers):
            patcher.stop()

    active = permission_surface(world, engine=actual_engine, broad=broad)
    fresh = None
    valid = parseable_toml(path)
    if valid:
        try:
            fresh = fresh_process_surface(path, world, broad=broad)
        except (OSError, RuntimeError, TimeoutError, ValueError):
            valid = False

    predicate = related or (lambda _probe: False)
    changed = before.changed(fresh) if fresh else before.decisions
    unrelated_preserved = all(predicate(probe) for probe in changed)

    return TransactionObservation(
        result=result,
        exception_type=exception_type,
        exception_message=exception_message,
        original_hash=original_hash,
        final_hash=file_hash(path),
        toml_valid=valid,
        active_decisions=active,
        fresh_process_decisions=fresh,
        unrelated_preserved=unrelated_preserved,
        audit_events=tuple(events),
        temporary_files=temporary_policy_files(path),
    )


def append_observation(payload: dict[str, Any]) -> None:
    """Append non-normative evidence to the runner-provided JSONL artifact."""
    import os

    destination = os.environ.get("POLICY_ASSURANCE_OBSERVATIONS")
    if destination:
        with Path(destination).open("a") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")


def make_world(
    agents: list[str] | tuple[str, ...],
    hosts: list[str] | tuple[str, ...],
    credentials: list[str] | tuple[str, ...],
) -> PolicyWorld:
    """Build a policy with overlapping baseline and agent-specific decisions."""
    agents = tuple(agents)
    hosts = tuple(hosts)
    credentials = tuple(credentials)
    if len(agents) < 3 or len(hosts) < 4 or len(credentials) < 3:
        raise ValueError("world requires at least 3 agents, 4 hosts, and 3 credentials")

    owner, peer, observer = agents[:3]
    allow_host, deny_host, prompt_host, owned_host = hosts[:4]
    selected_credential, peer_credential = credentials[:2]
    policy: dict[str, Any] = {
        "metadata": {"version": "2.0", "description": "policy assurance experiment"},
        "global_budget": 1_000_000,
        "hosts": {
            allow_host: {
                "credentials": [f"{selected_credential}:*"],
                "rate_limit": 100_000,
            },
            deny_host: {"egress": "deny"},
            prompt_host: {
                "credentials": [f"{peer_credential}:*"],
                "egress": "prompt",
            },
            "*": {"egress": "deny", "unknown_credentials": "prompt"},
        },
        "agents": {
            owner: {
                "egress": "deny",
                "hosts": {
                    allow_host: {"egress": "deny"},
                    owned_host: {"rate_limit": 100_000},
                },
            },
            peer: {
                "egress": "deny",
                "hosts": {deny_host: {"rate_limit": 100_000}},
            },
            observer: {"egress": "deny", "hosts": {}},
        },
        "required": [],
        "addons": {},
        "scan_patterns": [],
    }
    return PolicyWorld(policy, agents, hosts, credentials)


def clone_policy(policy: dict[str, Any]) -> dict[str, Any]:
    return deepcopy(policy)


def engine_from_internal(policy: dict[str, Any]) -> PolicyEngine:
    """Compile a policy without starting a file-watcher thread."""
    compiled = compile_policy(deepcopy(policy))
    model = UnifiedPolicy.model_validate(compiled)
    engine = PolicyEngine()
    engine._loader.set_baseline(model)
    return engine


def engine_from_path(path: Path) -> PolicyEngine:
    """Load a real TOML file without starting the background watcher."""
    engine = PolicyEngine()
    engine._loader._baseline_path = path
    if not engine._loader._load_baseline():
        raise ValueError(f"policy did not load: {path}")
    return engine


def toml_text(policy: dict[str, Any]) -> str:
    return tomlkit.dumps(denormalize(deepcopy(policy)))


def write_policy(path: Path, policy: dict[str, Any]) -> None:
    path.write_text(toml_text(policy))


def _host_variants(hosts: tuple[str, ...]) -> tuple[str, ...]:
    variants: set[str] = set(hosts)
    for host in hosts:
        variants.add(host.upper())
        if not host.startswith("*."):
            variants.add(f"child.{host}")
    variants.update(("unlisted.invalid", "xn--bcher-kva.example", "bücher.example"))
    return tuple(sorted(variants))


def permission_surface(
    world: PolicyWorld,
    *,
    engine: PolicyEngine | None = None,
    broad: bool = True,
) -> PermissionSurface:
    """Evaluate network and credential decisions across a broad finite universe."""
    actual_engine = engine or engine_from_internal(world.policy)
    decisions: dict[Probe, str] = {}
    agents = (None, *world.agents, "outside-agent")
    hosts = _host_variants(world.hosts) if broad else (*world.hosts, "unlisted.invalid")
    paths = ("/", "/v1/items", "/encoded/%2e%2e/value") if broad else ("/",)
    methods = ("GET", "POST", "DELETE") if broad else ("GET",)

    for agent in agents:
        for host in hosts:
            for path in paths:
                for method in methods:
                    decision = actual_engine.evaluate_request(
                        host=host,
                        path=path,
                        method=method,
                        agent=agent,
                    )
                    decisions[Probe("network", agent or "<baseline>", host, path, method)] = str(decision.effect)

    credential_types = (*world.credentials, "unknown", "outside-credential")
    for credential in credential_types:
        for host in hosts:
            for path in paths:
                decision = actual_engine.evaluate_credential(
                    credential_type=credential,
                    destination=host,
                    path=path,
                    credential_hmac=f"hmac:{credential}",
                )
                decisions[Probe("credential", "<none>", host, path, credential)] = str(decision.effect)

    return PermissionSurface(decisions)


def surface_for_path(
    path: Path,
    world: PolicyWorld,
    *,
    broad: bool = True,
) -> PermissionSurface:
    return permission_surface(world, engine=engine_from_path(path), broad=broad)


def _surface_child(connection, path: str, world: PolicyWorld, broad: bool) -> None:
    try:
        connection.send((True, surface_for_path(Path(path), world, broad=broad)))
    except Exception as exc:
        connection.send((False, (type(exc).__name__, str(exc))))
    finally:
        connection.close()


def fresh_process_surface(
    path: Path,
    world: PolicyWorld,
    *,
    broad: bool = False,
    timeout: float = 10.0,
) -> PermissionSurface:
    """Reload and evaluate in a spawned interpreter, with a deadlock guard."""
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(target=_surface_child, args=(child, str(path), world, broad))
    process.start()
    child.close()
    try:
        if not parent.poll(timeout):
            process.kill()
            process.join(timeout=2)
            raise TimeoutError("fresh-process decision probe timed out")
        ok, payload = parent.recv()
    finally:
        parent.close()
    process.join(timeout=2)
    if process.is_alive():
        process.kill()
        process.join(timeout=2)
        raise TimeoutError("fresh-process decision probe did not exit")
    if process.exitcode != 0:
        raise RuntimeError(f"fresh-process probe exited {process.exitcode}")
    if not ok:
        exception_type, message = payload
        raise ValueError(f"fresh-process probe {exception_type}: {message}")
    return payload
