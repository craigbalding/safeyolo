"""Trusted agent identity resolution for mitmproxy flows.

The per-agent Unix-domain-socket mode is authoritative.  The legacy IP map is
still useful when a flow did not arrive through a UDS listener, but it may not
contradict the UDS identity.  ``flow.metadata["agent"]`` is an output/cache,
never an independent trust source.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from mitmproxy import http

from safeyolo.core.audit_schema import (
    AttributionStatus,
    Decision,
    EventKind,
    Severity,
    TrafficInitiator,
)

_NON_IDENTITIES = frozenset({"", "unknown", "default"})
_ATTRIBUTION_VALUE_MAX_LEN = 128
ATTRIBUTION_SNAPSHOT_KEY = "_safeyolo_attribution_snapshot"
ATTRIBUTION_IDENTITY_SNAPSHOT_KEY = "_safeyolo_identity_snapshot"
LATE_ATTRIBUTION_CHANGE_KEY = "_safeyolo_late_attribution_change"


class AgentLookup(Protocol):
    """The service-discovery surface needed by identity resolution."""

    def get_client_for_ip(self, ip: str) -> str | None:
        """Return the agent mapped to ``ip``, if one is known."""
        raise NotImplementedError


class IdentityStatus(StrEnum):
    RESOLVED = "resolved"
    UNAVAILABLE = "unavailable"
    CONFLICT = "conflict"


@dataclass(frozen=True)
class AgentIdentity:
    """One reconciled identity decision with diagnostic provenance."""

    status: IdentityStatus
    agent: str | None = None
    source: str | None = None
    uds_agent: str | None = None
    mapped_agent: str | None = None
    metadata_agent: str | None = None
    reason: str | None = None

    @property
    def is_resolved(self) -> bool:
        return self.status is IdentityStatus.RESOLVED

    def provenance(self) -> dict[str, str]:
        """Return bounded trusted source facts.

        The pre-stamped ``agent`` metadata is intentionally absent. It can be
        useful when explaining a conflict, but it is not a provenance source
        and must not be copied into an attribution field.
        """
        result: dict[str, str] = {}
        if self.source:
            result["transport_source"] = _bounded(self.source)
        if self.uds_agent:
            result["uds_agent"] = _bounded(self.uds_agent)
        if self.mapped_agent:
            result["ip_map_agent"] = _bounded(self.mapped_agent)
        if self.reason:
            result["reason"] = _bounded(self.reason)
        return result

    def conflict_details(self) -> dict[str, str]:
        """Return a bounded operator diagnostic for a trusted-source conflict."""
        result: dict[str, str] = {}
        for key, value in (
            ("reason", self.reason),
            ("uds_agent", self.uds_agent),
            ("mapped_agent", self.mapped_agent),
            ("metadata_agent", self.metadata_agent),
        ):
            if value is not None:
                result[key] = _bounded(value)
        return result


@dataclass(frozen=True)
class TrafficAttribution:
    """Separate evidence ownership from transport identity and initiator."""

    evidence_owner: str | None
    trusted_transport_identity: str | None
    initiator: TrafficInitiator
    status: AttributionStatus
    provenance: dict[str, str]

    @property
    def agent(self) -> str | None:
        """Compatibility alias for the former audit/storage agent field."""
        return self.evidence_owner


def _bounded(value: object, maximum: int = _ATTRIBUTION_VALUE_MAX_LEN) -> str:
    """Return a bounded text value for attribution diagnostics."""
    return str(value)[:maximum]


def attribution_fields(attribution: TrafficAttribution) -> dict[str, object]:
    """Return the shared attribution fields used by audit and storage writers."""
    return {
        "agent": attribution.agent,
        "evidence_owner": attribution.evidence_owner,
        "trusted_transport_identity": attribution.trusted_transport_identity,
        "initiator": attribution.initiator.value,
        "attribution_status": attribution.status.value,
        "attribution_provenance": attribution.provenance,
    }


def _trusted_identity_signature(identity: AgentIdentity) -> tuple:
    """Return identity facts that are stable across metadata stamping.

    ``metadata_agent`` is deliberately excluded: it is an output/cache and
    normally changes from ``None`` to the resolved name when the first
    resolver stamps the flow.  Comparing it would report a false late change.
    """
    return (
        identity.status,
        identity.agent,
        identity.source,
        identity.uds_agent,
        identity.mapped_agent,
        identity.reason,
    )


def _identity_provenance(identity: AgentIdentity) -> dict[str, str]:
    """Return bounded trusted facts for a late-change diagnostic."""
    result = {"status": identity.status.value}
    if identity.agent:
        result["agent"] = _bounded(identity.agent)
    result.update(identity.provenance())
    return result


def _late_change_provenance(
    snapshot: AgentIdentity,
    current: AgentIdentity,
) -> dict[str, str]:
    """Flatten two trusted identity snapshots into bounded event fields."""
    result: dict[str, str] = {}
    for prefix, identity in (("snapshot", snapshot), ("current", current)):
        for key, value in _identity_provenance(identity).items():
            result[f"{prefix}_{key}"] = _bounded(value)
    return result


class AttributionQuarantined(RuntimeError):
    """Raised when a terminal flow cannot safely enter an agent partition."""


def _identity_snapshot(identity: AgentIdentity) -> tuple:
    """Encode trusted identity as flow-state-safe immutable primitives."""
    return (
        identity.status.value,
        identity.agent,
        identity.source,
        identity.uds_agent,
        identity.mapped_agent,
        identity.metadata_agent,
        identity.reason,
    )


def _identity_from_snapshot(value: object) -> AgentIdentity | None:
    """Decode an identity snapshot, tolerating flow-state list conversion."""
    if isinstance(value, AgentIdentity):
        return value
    if not isinstance(value, (tuple, list)) or len(value) != 7:
        return None
    try:
        return AgentIdentity(
            status=IdentityStatus(value[0]),
            agent=value[1],
            source=value[2],
            uds_agent=value[3],
            mapped_agent=value[4],
            metadata_agent=value[5],
            reason=value[6],
        )
    except (TypeError, ValueError):
        return None


def _attribution_snapshot(attribution: TrafficAttribution) -> tuple:
    """Encode attribution as flow-state-safe immutable primitives."""
    return (
        attribution.evidence_owner,
        attribution.trusted_transport_identity,
        attribution.initiator.value,
        attribution.status.value,
        tuple(sorted(attribution.provenance.items())),
    )


def _attribution_from_snapshot(value: object) -> TrafficAttribution | None:
    """Decode a flow attribution snapshot."""
    if isinstance(value, TrafficAttribution):
        return value
    if not isinstance(value, (tuple, list)) or len(value) != 5:
        return None
    try:
        provenance = dict(value[4])
        return TrafficAttribution(
            evidence_owner=value[0],
            trusted_transport_identity=value[1],
            initiator=TrafficInitiator(value[2]),
            status=AttributionStatus(value[3]),
            provenance=provenance,
        )
    except (TypeError, ValueError):
        return None


def snapshot_flow_attribution(
    flow: http.HTTPFlow,
    discovery: AgentLookup | None = None,
) -> TrafficAttribution:
    """Capture immutable per-flow attribution at the request boundary.

    The transport sources are resolved once and retained for the lifetime of
    the flow.  Downstream audit and storage consumers use this same snapshot,
    so a mutable IP map cannot make request and response events disagree.
    """
    existing = _attribution_from_snapshot(flow.metadata.get(ATTRIBUTION_SNAPSHOT_KEY))
    identity = _identity_from_snapshot(flow.metadata.get(ATTRIBUTION_IDENTITY_SNAPSHOT_KEY))
    if existing is not None and identity is not None:
        return existing

    identity = resolve_agent_identity(flow, discovery)
    attribution = attribute_traffic(flow, identity)
    # Keep internal snapshots serializable for mitmproxy view save/replay.
    # They are not request metadata and are never accepted as a trust source.
    flow.metadata[ATTRIBUTION_IDENTITY_SNAPSHOT_KEY] = _identity_snapshot(identity)
    flow.metadata[ATTRIBUTION_SNAPSHOT_KEY] = _attribution_snapshot(attribution)
    return attribution


def flow_attribution(
    flow: http.HTTPFlow,
    discovery: AgentLookup | None = None,
    *,
    check_late_change: bool = False,
) -> TrafficAttribution:
    """Return the stable flow attribution, optionally checking live sources.

    A late identity change is recorded once as an operator-only event and
    marks the flow quarantined.  The returned attribution remains the request
    snapshot; it is never silently reassigned to a new owner.
    """
    attribution = snapshot_flow_attribution(flow, discovery)
    if check_late_change:
        detect_late_attribution_change(flow, discovery)
    return attribution


def flow_identity(
    flow: http.HTTPFlow,
    discovery: AgentLookup | None = None,
) -> AgentIdentity:
    """Return the trusted identity captured for this flow."""
    snapshot_flow_attribution(flow, discovery)
    identity = _identity_from_snapshot(
        flow.metadata.get(ATTRIBUTION_IDENTITY_SNAPSHOT_KEY)
    )
    if identity is not None:
        return identity
    # Defensive fallback for malformed test/manual metadata.  Normal flows
    # always take the branch above because snapshot_flow_attribution stores
    # both values atomically from the hook's perspective.
    return resolve_agent_identity(flow, discovery)


def detect_late_attribution_change(
    flow: http.HTTPFlow,
    discovery: AgentLookup | None = None,
) -> bool:
    """Detect a changed or newly available trusted source after request time.

    The current source is inspected only for comparison.  It is not used to
    populate traffic evidence or an agent query scope.
    """
    snapshot_flow_attribution(flow, discovery)
    if LATE_ATTRIBUTION_CHANGE_KEY in flow.metadata:
        return True

    original = _identity_from_snapshot(
        flow.metadata.get(ATTRIBUTION_IDENTITY_SNAPSHOT_KEY)
    )
    if original is None:
        return False
    current = resolve_agent_identity(
        flow,
        discovery,
        stamp=False,
        use_cached_conflict=False,
    )
    if _trusted_identity_signature(original) == _trusted_identity_signature(current):
        return False

    provenance = _late_change_provenance(original, current)
    details = {
        "quarantined": True,
        "snapshot_status": original.status.value,
        "current_status": current.status.value,
    }
    flow.metadata[LATE_ATTRIBUTION_CHANGE_KEY] = {
        **details,
        "provenance": provenance,
    }

    # A late change is never assigned to an agent.  Keep the event correlated
    # by request_id so operators can join it with the stable request/response
    # traffic events without exposing the conflict to an agent partition.
    event_status = AttributionStatus.UNAVAILABLE
    if current.status is IdentityStatus.CONFLICT or (
        original.status is IdentityStatus.RESOLVED
        and current.status is IdentityStatus.RESOLVED
        and current.agent != original.agent
    ):
        event_status = AttributionStatus.CONFLICT
    late_attribution = TrafficAttribution(
        evidence_owner=None,
        trusted_transport_identity=None,
        initiator=TrafficInitiator.UNKNOWN,
        status=event_status,
        provenance=provenance,
    )
    from safeyolo.core.utils import write_event

    write_event(
        "security.agent_identity_late_change",
        kind=EventKind.SECURITY,
        severity=Severity.CRITICAL,
        summary="Trusted agent identity changed after request attribution",
        decision=Decision.LOG,
        request_id=flow.metadata.get("request_id"),
        **attribution_fields(late_attribution),
        addon="identity",
        details=details,
    )
    return True


def attribute_traffic(
    flow: http.HTTPFlow,
    identity: AgentIdentity | None = None,
) -> TrafficAttribution:
    """Build observability attribution from trusted identity and host marks.

    ``origin=operator`` is written by the trusted operator-provenance addon;
    it is not accepted from request headers or other guest-controlled input.
    All other traffic keeps an unknown initiator because UDS/IP-map identity
    alone proves the evidence owner, not who caused the request.
    """
    identity = identity or resolve_agent_identity(flow)
    provenance = identity.provenance()
    operator_mark = flow.metadata.get("origin") == "operator"
    if operator_mark:
        provenance["delegation"] = "operator-provenance"

    if identity.status is IdentityStatus.CONFLICT:
        status = AttributionStatus.CONFLICT
    elif identity.status is IdentityStatus.UNAVAILABLE:
        status = AttributionStatus.UNAVAILABLE
    elif operator_mark:
        status = AttributionStatus.DELEGATED
    else:
        status = AttributionStatus.RESOLVED

    return TrafficAttribution(
        evidence_owner=identity.agent if identity.is_resolved else None,
        trusted_transport_identity=identity.agent if identity.is_resolved else None,
        initiator=TrafficInitiator.OPERATOR if operator_mark else TrafficInitiator.UNKNOWN,
        status=status,
        provenance=provenance,
    )


def _identity(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return None if normalized in _NON_IDENTITIES else normalized


def _uds_agent(flow: http.HTTPFlow) -> str | None:
    try:
        return _identity(getattr(flow.client_conn.proxy_mode, "agent", None))
    except AttributeError:
        return None


def _client_ip(flow: http.HTTPFlow) -> str | None:
    try:
        peername = flow.client_conn.peername
    except AttributeError:
        return None
    return peername[0] if peername else None


def resolve_agent_identity(
    flow: http.HTTPFlow,
    discovery: AgentLookup | None = None,
    *,
    stamp: bool = True,
    use_cached_conflict: bool = True,
) -> AgentIdentity:
    """Resolve and optionally stamp the trusted identity for ``flow``.

    Resolution order and invariants:

    1. A UDS-mode agent is authoritative.
    2. An IP-map identity is a fallback only when no UDS identity exists.
    3. Two concrete trusted sources must agree.
    4. Pre-stamped metadata must agree with the trusted result, but metadata
       alone is never accepted as identity.
    """

    # Conflicts are terminal for a flow. The first resolver quarantines the
    # canonical metadata value; downstream resolvers must not reinterpret that
    # cleanup as evidence that the disagreement never happened.
    existing_conflict = flow.metadata.get("agent_identity_conflict")
    if (
        use_cached_conflict
        and
        flow.metadata.get("agent_identity_status") == IdentityStatus.CONFLICT.value
        and isinstance(existing_conflict, dict)
    ):
        result = AgentIdentity(
            status=IdentityStatus.CONFLICT,
            uds_agent=_identity(existing_conflict.get("uds_agent")),
            mapped_agent=_identity(existing_conflict.get("mapped_agent")),
            metadata_agent=_identity(existing_conflict.get("metadata_agent")),
            reason=existing_conflict.get("reason") or "previous_identity_conflict",
        )
        if stamp:
            flow.metadata.pop("agent", None)
            flow.metadata.pop("agent_identity_source", None)
        return result

    uds_agent = _uds_agent(flow)
    metadata_agent = _identity(flow.metadata.get("agent"))
    mapped_agent = None
    lookup_error = None

    client_ip = _client_ip(flow)
    if discovery is not None and client_ip is not None:
        try:
            mapped_agent = _identity(discovery.get_client_for_ip(client_ip))
        except Exception as exc:  # identity lookup must fail closed, not crash hooks
            lookup_error = f"{type(exc).__name__}: {exc}"

    if uds_agent and mapped_agent and uds_agent != mapped_agent:
        result = AgentIdentity(
            status=IdentityStatus.CONFLICT,
            uds_agent=uds_agent,
            mapped_agent=mapped_agent,
            metadata_agent=metadata_agent,
            reason="uds_ip_map_mismatch",
        )
    else:
        trusted_agent = uds_agent or mapped_agent
        source = "uds" if uds_agent else "ip_map" if mapped_agent else None
        if trusted_agent and metadata_agent and metadata_agent != trusted_agent:
            result = AgentIdentity(
                status=IdentityStatus.CONFLICT,
                uds_agent=uds_agent,
                mapped_agent=mapped_agent,
                metadata_agent=metadata_agent,
                reason="trusted_metadata_mismatch",
            )
        elif trusted_agent:
            result = AgentIdentity(
                status=IdentityStatus.RESOLVED,
                agent=trusted_agent,
                source=source,
                uds_agent=uds_agent,
                mapped_agent=mapped_agent,
                metadata_agent=metadata_agent,
            )
        else:
            result = AgentIdentity(
                status=IdentityStatus.UNAVAILABLE,
                uds_agent=uds_agent,
                mapped_agent=mapped_agent,
                metadata_agent=metadata_agent,
                reason="lookup_error" if lookup_error else "no_trusted_identity",
            )

    if stamp:
        flow.metadata["agent_identity_status"] = result.status.value
        if result.is_resolved:
            flow.metadata["agent"] = result.agent
            flow.metadata["agent_identity_source"] = result.source
            flow.metadata.pop("agent_identity_conflict", None)
        else:
            # Never leave unverified or conflicting identity in the canonical
            # metadata field where downstream audit/storage code may trust it.
            flow.metadata.pop("agent", None)
            flow.metadata.pop("agent_identity_source", None)
            if result.status is IdentityStatus.CONFLICT:
                flow.metadata["agent_identity_conflict"] = result.conflict_details()

    return result
