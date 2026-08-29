"""Authoritative, bounded room capability and resource inventory."""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import re
import sqlite3
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from safeyolo.config import get_config_dir

from . import store
from .kernel import LOCAL_OPERATOR_ID, execute_mutation

MAX_MEMBERS = 100
MAX_CAPABILITY_ADVERTISEMENTS = 512
MAX_RESOURCE_ADVERTISEMENTS = 128
MAX_DECLARATIONS_PER_AGENT = 32
MAX_DECLARATION_TTL_SECONDS = 3600
MAX_PROVIDER_COUNT = 16
MAX_PROVIDER_RESULT_ENTRIES = 1024
MAX_PROVIDER_DIRECTORY_ENTRIES = 128
MAX_PROVIDER_SNAPSHOT_BYTES = 512 * 1024
MAX_PROVIDER_TTL_MS = 5 * 60 * 1000
PROVIDER_TIMEOUT_SECONDS = 1.0
MAX_STATE_BYTES = 512 * 1024

_PUBLIC_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_AGENT_ID_RE = re.compile(r"^ag-[0-9a-f]{32}$")
_FORBIDDEN_PUBLIC_TERMS = frozenset(
    {
        "account",
        "binding",
        "credential",
        "credentials",
        "host",
        "key",
        "password",
        "path",
        "persona",
        "route",
        "secret",
        "token",
        "url",
    }
)

log = logging.getLogger("safeyolo.coord.inventory")


class InventoryBoundsError(ValueError):
    """Authoritative input cannot be represented inside the public bounds."""


@dataclass(frozen=True)
class InventorySnapshot:
    members: tuple[tuple[str, tuple[str, ...]], ...]
    capability_advertisements: tuple[tuple[str, str], ...]
    resource_advertisements: tuple[tuple[str, str], ...]
    declarations: tuple[tuple[str, str, int, int], ...]


@dataclass(frozen=True)
class ConfiguredAgent:
    display_name: str
    granted_capabilities: frozenset[str]


@dataclass(frozen=True)
class ProviderRequest:
    """The only information coord supplies to an availability provider."""

    provider: str
    room_id: str
    member_agent_ids: tuple[str, ...]
    capabilities: tuple[tuple[str, str], ...]
    resources: tuple[str, ...]


class ProviderAdapter(Protocol):
    """Narrow provider-owned observation contract.

    Implementations return a mapping with ``capabilities`` and ``leases``
    lists. Coord allow-lists individual fields and never serializes raw output
    or exception text. ``observe`` runs on an isolated worker event loop, so an
    adapter must create any event-loop-bound client inside the call rather than
    retain a client from the Agent API loop.
    """

    async def observe(self, request: ProviderRequest) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class CapabilityEvidence:
    availability: str
    observed_at: int
    valid_until: int


@dataclass(frozen=True)
class LeaseEvidence:
    state: str
    holder_agent_id: str | None
    observed_at: int
    valid_until: int


@dataclass(frozen=True)
class ProviderEvidence:
    capabilities: Mapping[tuple[str, str], CapabilityEvidence]
    leases: Mapping[str, LeaseEvidence]


_PROVIDER_ADAPTERS: dict[str, ProviderAdapter] = {}
_DISCOVERED_PROVIDER_ADAPTERS: dict[str, ProviderAdapter] = {}


@dataclass(frozen=True)
class SnapshotFileProvider:
    """Generic production adapter for a provider-owned public snapshot."""

    path: Path

    async def observe(self, _request: ProviderRequest) -> Mapping[str, Any]:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("provider snapshot is not a regular file")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                encoded = handle.read(MAX_PROVIDER_SNAPSHOT_BYTES + 1)
        finally:
            os.close(descriptor)
        if len(encoded) > MAX_PROVIDER_SNAPSHOT_BYTES:
            raise InventoryBoundsError("provider snapshot exceeds byte bound")
        payload = json.loads(encoded)
        if not isinstance(payload, Mapping):
            raise ValueError("provider snapshot must contain a JSON object")
        return payload


def register_provider_adapter(provider: str, adapter: ProviderAdapter) -> None:
    """Register one process-local adapter without giving coord its secrets."""
    validate_public_name(provider, field="provider")
    observe = getattr(adapter, "observe", None)
    if not callable(observe) or not inspect.iscoroutinefunction(observe):
        raise TypeError("provider adapter must define async observe(request)")
    _PROVIDER_ADAPTERS[provider] = adapter


def provider_snapshot_dir() -> Path:
    """Operator/provider integration directory for public observation files."""
    return get_config_dir() / "coord-providers"


def discover_provider_adapters() -> tuple[str, ...]:
    """Reconstruct generic provider adapters from durable public snapshots.

    Each ``<provider>.json`` file is provider-owned and uses the narrow
    ``capabilities``/``leases`` observation shape. Coord only reads it. No
    token, endpoint, route, or provider-specific integration enters coord.
    """
    directory = provider_snapshot_dir()
    discovered: dict[str, ProviderAdapter] = {}
    if directory.is_dir() and not directory.is_symlink():
        try:
            with os.scandir(directory) as entries:
                for entry_index, entry in enumerate(entries, start=1):
                    if entry_index > MAX_PROVIDER_DIRECTORY_ENTRIES:
                        log.warning(
                            "coord provider discovery returned unknown "
                            "(directory entry bound)"
                        )
                        discovered.clear()
                        break
                    try:
                        regular_file = entry.is_file(follow_symlinks=False)
                    except OSError as exc:
                        log.warning(
                            "ignored unreadable coord provider directory entry (%s)",
                            type(exc).__name__,
                        )
                        continue
                    if not entry.name.endswith(".json") or not regular_file:
                        continue
                    provider = entry.name.removesuffix(".json")
                    try:
                        validate_public_name(provider, field="provider")
                    except ValueError:
                        log.warning("ignored invalid coord provider snapshot filename")
                        continue
                    discovered[provider] = SnapshotFileProvider(Path(entry.path))
                    if len(discovered) > MAX_PROVIDER_COUNT:
                        log.warning(
                            "coord provider discovery returned unknown "
                            "(provider count bound)"
                        )
                        discovered.clear()
                        break
        except OSError as exc:
            log.warning(
                "coord provider discovery returned unknown (%s)",
                type(exc).__name__,
            )
            discovered.clear()
    _DISCOVERED_PROVIDER_ADAPTERS.clear()
    _DISCOVERED_PROVIDER_ADAPTERS.update(discovered)
    return tuple(sorted(discovered))


def clear_provider_adapters() -> None:
    """Clear process-local adapters (primarily lifecycle/test teardown)."""
    _PROVIDER_ADAPTERS.clear()
    _DISCOVERED_PROVIDER_ADAPTERS.clear()


def validate_public_name(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not _PUBLIC_NAME_RE.fullmatch(value):
        raise ValueError(
            f"{field} must be 1-64 lowercase ASCII letters, digits, '.', '_' or '-'"
        )
    terms = {term for term in re.split(r"[._-]+", value) if term}
    if terms & _FORBIDDEN_PUBLIC_TERMS:
        raise ValueError(f"{field} contains a prohibited sensitive term")
    return value


def validate_capability(value: str) -> str:
    if not isinstance(value, str) or value.count(":") != 1:
        raise ValueError("capability must be provider:name")
    provider, name = value.split(":", 1)
    validate_public_name(provider, field="capability provider")
    validate_public_name(name, field="capability name")
    return value


def capability_provider(capability: str) -> str:
    return validate_capability(capability).split(":", 1)[0]


def _validate_agent_id(agent_id: str) -> str:
    if not isinstance(agent_id, str) or not _AGENT_ID_RE.fullmatch(agent_id):
        raise ValueError("agent_id must be a canonical SafeYolo agent ID")
    return agent_id


def set_capability_advertisement(
    room_id: str,
    agent_id: str,
    capability: str,
    *,
    advertised: bool,
    operation_id: str,
) -> dict[str, Any]:
    """Idempotently change one operator-owned room-visible capability label."""
    _validate_agent_id(agent_id)
    capability = validate_capability(capability)
    request = {
        "room_id": room_id,
        "agent_id": agent_id,
        "capability": capability,
        "advertised": advertised,
    }

    def mutate(conn: sqlite3.Connection) -> dict[str, Any]:
        if advertised:
            membership = conn.execute(
                """SELECT 1 FROM memberships
                   WHERE room_id = ? AND principal_kind = 'agent'
                     AND principal_id = ? AND revoked_at IS NULL
                   LIMIT 1""",
                (room_id, agent_id),
            ).fetchone()
            if membership is None:
                raise ValueError("capability subject is not a current room member")
            changed = bool(
                conn.execute(
                    """INSERT OR IGNORE INTO coord_capability_advertisements
                       (room_id, agent_id, capability, operation_id, created_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        room_id,
                        agent_id,
                        capability,
                        operation_id,
                        store.now_ms(),
                    ),
                ).rowcount
            )
        else:
            changed = bool(
                conn.execute(
                    """DELETE FROM coord_capability_advertisements
                       WHERE room_id = ? AND agent_id = ? AND capability = ?""",
                    (room_id, agent_id, capability),
                ).rowcount
            )
        if changed and advertised:
            _enforce_advertisement_bounds(conn, room_id)
        if changed:
            _enqueue_advertisement_event(
                conn,
                room_id=room_id,
                kind="capability",
                agent_id=agent_id,
                provider=capability_provider(capability),
                label=capability,
                advertised=advertised,
                operation_id=operation_id,
            )
        return {
            "kind": "capability",
            "agent_id": agent_id,
            "capability": capability,
            "advertised": advertised,
            "changed": changed,
        }

    return execute_mutation(
        operation_id=operation_id,
        operation_type="coord.inventory.capability_advertise",
        request=request,
        mutate=mutate,
    )


def set_resource_advertisement(
    room_id: str,
    provider: str,
    resource: str,
    *,
    advertised: bool,
    operation_id: str,
) -> dict[str, Any]:
    """Idempotently change one room-visible provider resource label."""
    provider = validate_public_name(provider, field="provider")
    resource = validate_public_name(resource, field="resource")
    request = {
        "room_id": room_id,
        "provider": provider,
        "resource": resource,
        "advertised": advertised,
    }

    def mutate(conn: sqlite3.Connection) -> dict[str, Any]:
        if advertised:
            changed = bool(
                conn.execute(
                    """INSERT OR IGNORE INTO coord_resource_advertisements
                       (room_id, provider, resource, operation_id, created_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (room_id, provider, resource, operation_id, store.now_ms()),
                ).rowcount
            )
        else:
            changed = bool(
                conn.execute(
                    """DELETE FROM coord_resource_advertisements
                       WHERE room_id = ? AND provider = ? AND resource = ?""",
                    (room_id, provider, resource),
                ).rowcount
            )
        if changed and advertised:
            _enforce_advertisement_bounds(conn, room_id)
        if changed:
            _enqueue_advertisement_event(
                conn,
                room_id=room_id,
                kind="resource",
                agent_id=None,
                provider=provider,
                label=resource,
                advertised=advertised,
                operation_id=operation_id,
            )
        return {
            "kind": "resource",
            "provider": provider,
            "resource": resource,
            "advertised": advertised,
            "changed": changed,
        }

    return execute_mutation(
        operation_id=operation_id,
        operation_type="coord.inventory.resource_advertise",
        request=request,
        mutate=mutate,
    )


def _enforce_advertisement_bounds(conn: sqlite3.Connection, room_id: str) -> None:
    capability_count = conn.execute(
        """SELECT count(*) FROM coord_capability_advertisements
           WHERE room_id = ?""",
        (room_id,),
    ).fetchone()[0]
    if capability_count > MAX_CAPABILITY_ADVERTISEMENTS:
        raise InventoryBoundsError("room exceeds capability advertisement bound")
    resource_count = conn.execute(
        """SELECT count(*) FROM coord_resource_advertisements
           WHERE room_id = ?""",
        (room_id,),
    ).fetchone()[0]
    if resource_count > MAX_RESOURCE_ADVERTISEMENTS:
        raise InventoryBoundsError("room exceeds resource advertisement bound")
    provider_count = conn.execute(
        """SELECT count(*) FROM (
               SELECT substr(capability, 1, instr(capability, ':') - 1) AS provider
               FROM coord_capability_advertisements WHERE room_id = ?
               UNION
               SELECT provider FROM coord_resource_advertisements WHERE room_id = ?
           )""",
        (room_id, room_id),
    ).fetchone()[0]
    if provider_count > MAX_PROVIDER_COUNT:
        raise InventoryBoundsError(f"room exceeds {MAX_PROVIDER_COUNT} providers")


def _enqueue_advertisement_event(
    conn: sqlite3.Connection,
    *,
    room_id: str,
    kind: str,
    agent_id: str | None,
    provider: str,
    label: str,
    advertised: bool,
    operation_id: str,
) -> None:
    from .outbox import enqueue_coord_event

    details: dict[str, Any] = {
        "actor": LOCAL_OPERATOR_ID,
        "room_id": room_id,
        "object_id": room_id,
        "advertisement_kind": kind,
        "provider": provider,
        "label": label,
        "operation_id": operation_id,
        "operation_type": f"coord.inventory.{kind}_advertise",
        "transition": "advertised" if advertised else "unadvertised",
    }
    if agent_id is not None:
        details["agent_id"] = agent_id
    enqueue_coord_event(conn, "coord.inventory_advertisement_changed", details)


def replace_declarations(
    conn: sqlite3.Connection,
    room_id: str,
    agent_id: str,
    capabilities: list[str],
    *,
    ttl_seconds: int,
) -> dict[str, Any]:
    """Replace an agent's attributed, explicitly untrusted declarations."""
    _validate_agent_id(agent_id)
    if not isinstance(capabilities, list):
        raise ValueError("capabilities must be a list")
    if len(capabilities) > MAX_DECLARATIONS_PER_AGENT:
        raise ValueError(
            f"at most {MAX_DECLARATIONS_PER_AGENT} declarations are allowed"
        )
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= MAX_DECLARATION_TTL_SECONDS:
        raise ValueError(
            f"ttl_seconds must be 1-{MAX_DECLARATION_TTL_SECONDS}"
        )
    labels = sorted({validate_capability(value) for value in capabilities})
    asserted_at = store.now_ms()
    valid_until = asserted_at + ttl_seconds * 1000
    conn.execute(
        """DELETE FROM coord_capability_declarations
           WHERE room_id = ? AND agent_id = ?""",
        (room_id, agent_id),
    )
    conn.executemany(
        """INSERT INTO coord_capability_declarations
           (room_id, agent_id, capability, asserted_at, valid_until)
           VALUES (?, ?, ?, ?, ?)""",
        [
            (room_id, agent_id, capability, asserted_at, valid_until)
            for capability in labels
        ],
    )
    return {
        "agent_id": agent_id,
        "count": len(labels),
        "asserted_at": asserted_at,
        "valid_until": valid_until,
    }


def read_snapshot(conn: sqlite3.Connection, room_id: str) -> InventorySnapshot:
    """Read all SQLite-owned inventory inputs inside the caller's snapshot."""
    member_rows = conn.execute(
        """SELECT principal_id, permissions, granted_at
           FROM memberships
           WHERE room_id = ? AND principal_kind = 'agent'
             AND revoked_at IS NULL
           ORDER BY principal_id, granted_at DESC""",
        (room_id,),
    ).fetchall()
    members: dict[str, tuple[str, ...]] = {}
    for row in member_rows:
        members.setdefault(
            row["principal_id"], tuple(row["permissions"].split(","))
        )
    if len(members) > MAX_MEMBERS:
        raise InventoryBoundsError(f"room exceeds {MAX_MEMBERS} agent members")

    capability_rows = conn.execute(
        """SELECT agent_id, capability
           FROM coord_capability_advertisements
           WHERE room_id = ? ORDER BY agent_id, capability""",
        (room_id,),
    ).fetchall()
    if len(capability_rows) > MAX_CAPABILITY_ADVERTISEMENTS:
        raise InventoryBoundsError(
            "room exceeds capability advertisement bound"
        )

    resource_rows = conn.execute(
        """SELECT provider, resource
           FROM coord_resource_advertisements
           WHERE room_id = ? ORDER BY provider, resource""",
        (room_id,),
    ).fetchall()
    if len(resource_rows) > MAX_RESOURCE_ADVERTISEMENTS:
        raise InventoryBoundsError("room exceeds resource advertisement bound")

    declaration_rows = conn.execute(
        """SELECT agent_id, capability, asserted_at, valid_until
           FROM coord_capability_declarations
           WHERE room_id = ? ORDER BY agent_id, capability""",
        (room_id,),
    ).fetchall()
    if len(declaration_rows) > MAX_MEMBERS * MAX_DECLARATIONS_PER_AGENT:
        raise InventoryBoundsError("room exceeds declaration bound")

    return InventorySnapshot(
        members=tuple(sorted(members.items())),
        capability_advertisements=tuple(
            (row["agent_id"], row["capability"]) for row in capability_rows
        ),
        resource_advertisements=tuple(
            (row["provider"], row["resource"]) for row in resource_rows
        ),
        declarations=tuple(
            (
                row["agent_id"],
                row["capability"],
                int(row["asserted_at"]),
                int(row["valid_until"]),
            )
            for row in declaration_rows
        ),
    )


def configured_agents(raw_agents: Mapping[str, Any]) -> dict[str, ConfiguredAgent]:
    """Project only stable identity, current display name and safe grant labels."""
    by_id: dict[str, list[ConfiguredAgent]] = {}
    for display_name, metadata in raw_agents.items():
        if (
            not isinstance(display_name, str)
            or not _PUBLIC_NAME_RE.fullmatch(display_name)
            or not isinstance(metadata, Mapping)
        ):
            continue
        agent_id = metadata.get("agent_id")
        if not isinstance(agent_id, str) or not _AGENT_ID_RE.fullmatch(agent_id):
            continue
        grants: set[str] = set()
        services = metadata.get("services", {})
        if isinstance(services, Mapping):
            for service, config in services.items():
                if not isinstance(service, str):
                    continue
                if isinstance(config, str):
                    capability = config
                elif isinstance(config, Mapping):
                    capability = config.get("capability", config.get("role"))
                else:
                    continue
                if not isinstance(capability, str):
                    continue
                label = f"{service}:{capability}"
                try:
                    grants.add(validate_capability(label))
                except ValueError:
                    continue
        by_id.setdefault(agent_id, []).append(
            ConfiguredAgent(display_name, frozenset(grants))
        )
    # Duplicate manually-forged durable IDs are ambiguous. Fail closed: do not
    # attribute either name or grants to that ID.
    return {agent_id: values[0] for agent_id, values in by_id.items() if len(values) == 1}


def plan_provider_requests(
    room_id: str,
    snapshot: InventorySnapshot,
    agents: Mapping[str, ConfiguredAgent],
) -> dict[str, ProviderRequest]:
    """Plan bounded provider reads from advertised, currently granted labels."""
    current_members = {agent_id for agent_id, _permissions in snapshot.members}
    capabilities: dict[str, list[tuple[str, str]]] = {}
    resources: dict[str, list[str]] = {}
    for agent_id, capability in snapshot.capability_advertisements:
        configured = agents.get(agent_id)
        if (
            agent_id in current_members
            and configured is not None
            and capability in configured.granted_capabilities
        ):
            capabilities.setdefault(capability_provider(capability), []).append(
                (agent_id, capability)
            )
    for provider, resource in snapshot.resource_advertisements:
        resources.setdefault(provider, []).append(resource)
    providers = sorted(set(capabilities) | set(resources))
    if len(providers) > MAX_PROVIDER_COUNT:
        raise InventoryBoundsError(f"room exceeds {MAX_PROVIDER_COUNT} providers")
    member_ids = tuple(sorted(current_members))
    return {
        provider: ProviderRequest(
            provider=provider,
            room_id=room_id,
            member_agent_ids=member_ids,
            capabilities=tuple(sorted(capabilities.get(provider, []))),
            resources=tuple(sorted(resources.get(provider, []))),
        )
        for provider in providers
    }


async def query_providers(
    requests: Mapping[str, ProviderRequest],
) -> dict[str, ProviderEvidence]:
    """Query providers concurrently with a strict latency and shape boundary."""

    async def query_one(
        provider: str, request: ProviderRequest
    ) -> tuple[str, ProviderEvidence]:
        adapter = _PROVIDER_ADAPTERS.get(
            provider,
            _DISCOVERED_PROVIDER_ADAPTERS.get(provider),
        )
        if adapter is None:
            return provider, ProviderEvidence({}, {})
        try:
            def observe_and_normalize() -> ProviderEvidence:
                async def observe() -> Any:
                    pending = adapter.observe(request)
                    if not inspect.isawaitable(pending):
                        raise TypeError("provider observe result is not awaitable")
                    return await pending

                # The complete adapter call runs on a worker event loop. Even
                # an incorrectly blocking async implementation cannot freeze
                # the Agent API loop past the wait_for boundary below.
                payload = asyncio.run(observe())
                return _normalize_provider_payload(payload, request)

            evidence = await asyncio.wait_for(
                asyncio.to_thread(observe_and_normalize),
                timeout=PROVIDER_TIMEOUT_SECONDS,
            )
            return provider, evidence
        except BaseException as exc:
            if isinstance(exc, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
                raise
            log.warning(
                "coord inventory provider %s returned unknown (%s)",
                provider,
                type(exc).__name__,
            )
            return provider, ProviderEvidence({}, {})

    return dict(
        await asyncio.gather(
            *(query_one(provider, request) for provider, request in requests.items())
        )
    )


def _normalize_provider_payload(
    payload: Any,
    request: ProviderRequest,
) -> ProviderEvidence:
    if not isinstance(payload, Mapping):
        raise ValueError("provider result must be a mapping")
    capability_rows = payload.get("capabilities", [])
    lease_rows = payload.get("leases", [])
    if not isinstance(capability_rows, list) or not isinstance(lease_rows, list):
        raise ValueError("provider result collections must be lists")
    if len(capability_rows) + len(lease_rows) > MAX_PROVIDER_RESULT_ENTRIES:
        raise InventoryBoundsError("provider result exceeds entry bound")

    requested_capabilities = set(request.capabilities)
    capabilities: dict[tuple[str, str], CapabilityEvidence] = {}
    for row in capability_rows:
        if not isinstance(row, Mapping):
            raise ValueError("malformed capability evidence")
        key = (row.get("agent_id"), row.get("capability"))
        if key not in requested_capabilities:
            continue
        if key in capabilities:
            raise ValueError("duplicate capability evidence")
        availability = row.get("availability")
        if availability not in {"available", "unavailable"}:
            raise ValueError("malformed capability availability")
        observed_at, valid_until = _evidence_times(row)
        capabilities[key] = CapabilityEvidence(
            availability,
            observed_at,
            valid_until,
        )

    requested_resources = set(request.resources)
    member_ids = set(request.member_agent_ids)
    leases: dict[str, LeaseEvidence] = {}
    for row in lease_rows:
        if not isinstance(row, Mapping):
            raise ValueError("malformed lease evidence")
        resource = row.get("resource")
        if resource not in requested_resources:
            continue
        if resource in leases:
            raise ValueError("duplicate lease evidence")
        state = row.get("state")
        holder = row.get("holder_agent_id")
        if state == "held":
            if holder not in member_ids:
                raise ValueError("lease holder is not a current room member")
        elif state == "unleased":
            if holder is not None:
                raise ValueError("unleased resource cannot have a holder")
        else:
            raise ValueError("malformed lease state")
        observed_at, valid_until = _evidence_times(row)
        leases[resource] = LeaseEvidence(
            state,
            holder,
            observed_at,
            valid_until,
        )
    return ProviderEvidence(capabilities, leases)


def _evidence_times(row: Mapping[str, Any]) -> tuple[int, int]:
    observed_at = row.get("observed_at")
    valid_until = row.get("valid_until")
    if (
        type(observed_at) is not int
        or type(valid_until) is not int
        or observed_at < 0
        or valid_until < 0
    ):
        raise ValueError("malformed provider evidence timestamp")
    return observed_at, valid_until


def _freshness(
    observed_at: int,
    valid_until: int,
    now_ms: int,
) -> str:
    if (
        observed_at > now_ms
        or valid_until <= observed_at
        or valid_until - observed_at > MAX_PROVIDER_TTL_MS
    ):
        return "unknown"
    if now_ms >= valid_until:
        return "stale"
    return "fresh"


def build_room_state(
    *,
    room_id: str,
    room_name: str,
    snapshot: InventorySnapshot,
    agents: Mapping[str, ConfiguredAgent],
    provider_evidence: Mapping[str, ProviderEvidence],
    origin_instance_id: str,
    brief: Mapping[str, Any],
    now_ms: int,
) -> dict[str, Any]:
    """Build the allow-listed public model from the final authoritative inputs."""
    member_permissions = dict(snapshot.members)
    verified: dict[str, list[dict[str, Any]]] = {
        agent_id: [] for agent_id in member_permissions
    }
    for agent_id, capability in snapshot.capability_advertisements:
        configured = agents.get(agent_id)
        if (
            agent_id not in member_permissions
            or configured is None
            or capability not in configured.granted_capabilities
        ):
            continue
        provider = capability_provider(capability)
        evidence = provider_evidence.get(provider, ProviderEvidence({}, {}))
        observation = evidence.capabilities.get((agent_id, capability))
        if observation is None:
            availability = "unknown"
            observed_at = None
            valid_until = None
            freshness = "unknown"
        else:
            freshness = _freshness(
                observation.observed_at,
                observation.valid_until,
                now_ms,
            )
            availability = (
                observation.availability if freshness == "fresh" else "unknown"
            )
            observed_at = observation.observed_at
            valid_until = observation.valid_until
        verified[agent_id].append(
            {
                "capability": capability,
                "authorized": True,
                "availability": availability,
                "provider": provider,
                "observed_at": observed_at,
                "valid_until": valid_until,
                "freshness": freshness,
                "provenance": {
                    "authorization": "safeyolo_current_grant",
                    "visibility": "operator_room_advertisement",
                    "availability": "provider_observation",
                },
            }
        )

    declared: dict[str, list[dict[str, Any]]] = {
        agent_id: [] for agent_id in member_permissions
    }
    for agent_id, capability, asserted_at, valid_until in snapshot.declarations:
        if agent_id not in member_permissions or now_ms >= valid_until:
            continue
        declared[agent_id].append(
            {
                "capability": capability,
                "asserted_by_agent_id": agent_id,
                "asserted_at": asserted_at,
                "valid_until": valid_until,
                "freshness": "fresh",
                "provenance": "agent_declared",
            }
        )

    members = []
    for agent_id, permissions in snapshot.members:
        configured = agents.get(agent_id)
        members.append(
            {
                "agent_id": agent_id,
                "display_name": (
                    configured.display_name if configured is not None else None
                ),
                "configured": configured is not None,
                "origin_instance_id": origin_instance_id,
                "room_permissions": list(permissions),
                "verified": sorted(
                    verified[agent_id], key=lambda item: item["capability"]
                ),
                "declared": sorted(
                    declared[agent_id], key=lambda item: item["capability"]
                ),
            }
        )

    leases = []
    for provider, resource in snapshot.resource_advertisements:
        evidence = provider_evidence.get(provider, ProviderEvidence({}, {}))
        observation = evidence.leases.get(resource)
        if observation is None:
            state = "unknown"
            holder = None
            observed_at = None
            valid_until = None
            freshness = "unknown"
        else:
            freshness = _freshness(
                observation.observed_at,
                observation.valid_until,
                now_ms,
            )
            if (
                freshness == "fresh"
                and (
                    observation.state != "held"
                    or observation.holder_agent_id in member_permissions
                )
            ):
                state = observation.state
                holder = observation.holder_agent_id
            else:
                state = "unknown"
                holder = None
                if freshness == "fresh":
                    # Membership is re-read after provider I/O. Never expose a
                    # lease holder that disappeared from that final snapshot.
                    freshness = "unknown"
            observed_at = observation.observed_at
            valid_until = observation.valid_until
        holder_config = agents.get(holder) if holder is not None else None
        leases.append(
            {
                "provider": provider,
                "resource": resource,
                "state": state,
                "holder_agent_id": holder,
                "holder_display_name": (
                    holder_config.display_name if holder_config is not None else None
                ),
                "observed_at": observed_at,
                "valid_until": valid_until,
                "freshness": freshness,
                "provenance": "provider_owned_lease",
            }
        )

    state = {
        "room_id": room_id,
        "room_name": room_name,
        "origin_instance_id": origin_instance_id,
        "generated_at": now_ms,
        "brief": dict(brief),
        "members": members,
        "resource_leases": leases,
    }
    encoded_size = len(
        json.dumps(
            state,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    )
    if encoded_size > MAX_STATE_BYTES:
        raise InventoryBoundsError(
            f"room state exceeds {MAX_STATE_BYTES} UTF-8 bytes"
        )
    return state
