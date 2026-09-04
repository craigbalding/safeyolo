"""Attribute native mitmproxy operator actions without restricting them."""

from __future__ import annotations

from mitmproxy import ctx, flow, http

from safeyolo.core.audit_schema import EventKind, Severity
from safeyolo.core.identity import attribute_traffic, attribution_fields, resolve_agent_identity
from safeyolo.core.utils import find_addon, write_event

ORIGIN = "operator"


class _State:
    """Small state snapshot; kept dataclass-free for mitmproxy script loading."""

    __slots__ = ("intercepted", "is_replay", "killed", "modified", "terminal")

    def __init__(
        self,
        *,
        modified: bool,
        intercepted: bool,
        killed: bool,
        is_replay: str | None,
        terminal: bool,
    ) -> None:
        self.modified = modified
        self.intercepted = intercepted
        self.killed = killed
        self.is_replay = is_replay
        self.terminal = terminal


def _state(item: flow.Flow) -> _State:
    error = getattr(item, "error", None)
    return _State(
        modified=item.modified(),
        intercepted=item.intercepted,
        killed=bool(error and error.msg == flow.Error.KILLED_MESSAGE),
        is_replay=item.is_replay,
        terminal=bool(getattr(item, "response", None) is not None or error is not None),
    )


class OperatorProvenance:
    """Observe the shared View and annotate trusted-operator actions."""

    name = "operator-provenance"

    def __init__(self) -> None:
        self._states: dict[str, _State] = {}
        self._request_sources: dict[str, str] = {}
        self._view = None

    def running(self) -> None:
        self._view = ctx.master.view
        self._view.sig_view_add.connect(self._view_add)
        self._view.sig_view_update.connect(self._view_update)
        for item in self._view.resolve("@all"):
            self._remember(item)

    def done(self) -> None:
        if self._view is not None:
            self._view.sig_view_add.disconnect(self._view_add)
            self._view.sig_view_update.disconnect(self._view_update)

    def _remember(self, item: flow.Flow) -> None:
        self._states[item.id] = _state(item)
        request_id = item.metadata.get("request_id")
        if request_id and item.metadata.get("origin") != ORIGIN:
            self._request_sources.setdefault(str(request_id), item.id)

    def _annotate(self, item: flow.Flow, action: str, source_flow_id: str) -> None:
        item.metadata["origin"] = ORIGIN
        item.metadata["operator_action"] = action
        item.metadata["source_flow_id"] = source_flow_id

    def _audit(self, item: flow.Flow, action: str, *, resulting_flow_id: str | None = None) -> None:
        source_flow_id = str(item.metadata.get("source_flow_id", item.id))
        details = {"action": action, "source_flow_id": source_flow_id}
        if resulting_flow_id is not None:
            details["resulting_flow_id"] = resulting_flow_id
        attribution = attribute_traffic(
            item,
            resolve_agent_identity(item, find_addon("service-discovery")),
        )
        write_event(
            "admin.traffic_operator_action",
            kind=EventKind.ADMIN,
            severity=Severity.LOW,
            summary=f"Operator {action} on traffic flow {source_flow_id}",
            host=getattr(getattr(item, "request", None), "pretty_host", None),
            request_id=item.metadata.get("request_id"),
            **attribution_fields(attribution),
            addon=self.name,
            details=details,
        )

    def _view_add(self, flow: flow.Flow) -> None:
        request_id = flow.metadata.get("request_id")
        source = self._request_sources.get(str(request_id)) if request_id else None
        if source is not None and source != flow.id:
            self._annotate(flow, "duplicate", source)
            self._audit(flow, "duplicate", resulting_flow_id=flow.id)
        self._remember(flow)

    def _view_update(self, flow: flow.Flow) -> None:
        previous = self._states.get(flow.id)
        current = _state(flow)
        if previous is None:
            self._remember(flow)
            return

        replay_started = (
            current.is_replay == "request"
            and not current.terminal
            and (previous.is_replay != "request" or previous.terminal)
        )
        if replay_started:
            source = str(flow.metadata.get("source_flow_id", flow.id))
            self._annotate(flow, "replay", source)
            flow.metadata["operator_audit_pending"] = True
        elif not previous.killed and current.killed:
            self._annotate(flow, "kill", str(flow.metadata.get("source_flow_id", flow.id)))
            self._audit(flow, "kill")
        elif previous.intercepted and not current.intercepted:
            self._annotate(flow, "resume", str(flow.metadata.get("source_flow_id", flow.id)))
            self._audit(flow, "resume")
        elif previous.modified and not current.modified:
            self._audit(flow, "revert")
        elif not previous.modified and current.modified and current.is_replay is None:
            self._annotate(flow, "edit", str(flow.metadata.get("source_flow_id", flow.id)))
            self._audit(flow, "edit")

        self._remember(flow)

    def request(self, flow: http.HTTPFlow) -> None:
        """Link replay audit to the fresh request ID assigned by request-id."""
        if flow.metadata.pop("operator_audit_pending", False):
            self._audit(flow, "replay", resulting_flow_id=flow.id)
        self._remember(flow)


addons = [OperatorProvenance()]
