"""Bound the canonical interactive flow working set.

The console and web frontends share one mitmproxy ``View``. Pruning operates
on that view's underlying store, not its currently filtered/sorted projection,
and never touches durable FlowStore evidence.
"""

import logging
import time
from collections.abc import Iterable

from mitmproxy import ctx, exceptions

log = logging.getLogger("safeyolo.flow-pruner")

DEFAULT_MAX_FLOWS = 5_000
DEFAULT_MAX_BODY_BYTES = 1024**3
PRUNE_INTERVAL_SECONDS = 30


def _all_stored_flows(view) -> list:
    """Return every retained flow, including flows hidden by ``view_filter``."""
    resolve = getattr(view, "resolve", None)
    if callable(resolve):
        try:
            return list(resolve("@all"))
        except (KeyError, TypeError, ValueError):
            pass
    store = getattr(view, "_store", None)
    if store is not None:
        values = getattr(store, "values", None)
        return list(values() if callable(values) else store)
    return list(view)


def _completion_timestamp(flow) -> float:
    """Return an explicit timestamp suitable for oldest-first eviction."""
    websocket = getattr(flow, "websocket", None)
    candidates = [
        getattr(websocket, "timestamp_end", None),
        getattr(getattr(flow, "response", None), "timestamp_end", None),
        getattr(getattr(flow, "error", None), "timestamp", None),
        getattr(flow, "timestamp_end", None),
        getattr(getattr(flow, "request", None), "timestamp_start", None),
        getattr(flow, "timestamp_created", None),
    ]
    return next((float(value) for value in candidates if isinstance(value, (int, float))), 0.0)


def _is_terminal(flow) -> bool:
    """Return whether removing the flow cannot disrupt active traffic."""
    if bool(getattr(flow, "intercepted", False)) or bool(getattr(flow, "live", False)):
        return False

    websocket = getattr(flow, "websocket", None)
    if websocket is not None and getattr(websocket, "timestamp_end", None) is None:
        return False

    return bool(
        getattr(flow, "response", None)
        or getattr(flow, "error", None)
        or getattr(flow, "timestamp_end", None) is not None
        or (websocket is not None and getattr(websocket, "timestamp_end", None) is not None)
    )


def _retained_body_bytes(flows: Iterable) -> int:
    return sum(_flow_body_bytes(flow) for flow in flows)


def _flow_body_bytes(flow) -> int:
    total = 0
    for message in (getattr(flow, "request", None), getattr(flow, "response", None)):
        content = getattr(message, "raw_content", None)
        if content:
            total += len(content)
    websocket = getattr(flow, "websocket", None)
    for message in getattr(websocket, "messages", ()) if websocket else ():
        total += len(getattr(message, "content", b""))
    return total


def _message_timestamp(message, flow, position: int) -> float:
    value = getattr(message, "timestamp", None)
    if isinstance(value, (int, float)):
        return float(value)
    return _completion_timestamp(flow) + position


class FlowPruner:
    """Bound flow count and retained body bytes in the shared interactive view."""

    name = "flow-pruner"

    def __init__(self):
        self._last_prune: float = 0.0
        self._total_pruned: int = 0
        self._current_retained: int = 0
        self._retained_body_bytes: int = 0
        self._total_websocket_messages_trimmed: int = 0

    def load(self, loader):
        loader.add_option(
            name="flow_pruner_max",
            typespec=int,
            default=DEFAULT_MAX_FLOWS,
            help=f"Maximum flows in the shared live view (default: {DEFAULT_MAX_FLOWS})",
        )
        loader.add_option(
            name="flow_pruner_max_body_bytes",
            typespec=int,
            default=DEFAULT_MAX_BODY_BYTES,
            help=(
                "Maximum combined request, response, and WebSocket body bytes "
                f"in the shared live view (default: {DEFAULT_MAX_BODY_BYTES})"
            ),
        )

    def configure(self, updates):
        if "flow_pruner_max" in updates and ctx.options.flow_pruner_max <= 0:
            raise exceptions.OptionsError("flow_pruner_max must be a positive integer")
        if (
            "flow_pruner_max_body_bytes" in updates
            and ctx.options.flow_pruner_max_body_bytes <= 0
        ):
            raise exceptions.OptionsError(
                "flow_pruner_max_body_bytes must be a positive integer"
            )

    def running(self):
        log.info(
            "Flow pruner active (max %d flows, %d body bytes)",
            ctx.options.flow_pruner_max,
            ctx.options.flow_pruner_max_body_bytes,
        )
        self._refresh_stats()

    def response(self, flow):
        self._maybe_prune()

    def error(self, flow):
        self._maybe_prune()

    def websocket_end(self, flow):
        self._maybe_prune()

    def websocket_message(self, flow):
        self._maybe_prune()

    def tcp_end(self, flow):
        self._maybe_prune()

    def udp_end(self, flow):
        self._maybe_prune()

    def dns_response(self, flow):
        self._maybe_prune()

    def dns_error(self, flow):
        self._maybe_prune()

    def _view(self):
        return getattr(getattr(ctx, "master", None), "view", None)

    def _refresh_stats(self, flows: list | None = None) -> None:
        view = self._view()
        if view is None:
            self._current_retained = 0
            self._retained_body_bytes = 0
            return
        retained = _all_stored_flows(view) if flows is None else flows
        self._current_retained = len(retained)
        self._retained_body_bytes = _retained_body_bytes(retained)

    def _maybe_prune(self) -> None:
        view = self._view()
        if view is None:
            return
        flows = _all_stored_flows(view)
        max_flows = ctx.options.flow_pruner_max
        max_body_bytes = ctx.options.flow_pruner_max_body_bytes
        now = time.monotonic()
        interval_due = now - self._last_prune >= PRUNE_INTERVAL_SECONDS
        if len(flows) <= max_flows and not interval_due:
            return
        self._last_prune = now
        retained_body_bytes = _retained_body_bytes(flows)
        if len(flows) <= max_flows and retained_body_bytes <= max_body_bytes:
            self._refresh_stats(flows)
            return
        self._prune(view, flows, max_flows, max_body_bytes)

    def _prune(
        self,
        view=None,
        flows: list | None = None,
        max_flows: int | None = None,
        max_body_bytes: int | None = None,
    ):
        view = self._view() if view is None else view
        if view is None:
            return
        retained = _all_stored_flows(view) if flows is None else flows
        options = getattr(ctx, "options", None)
        if max_flows is None:
            max_flows = getattr(options, "flow_pruner_max", DEFAULT_MAX_FLOWS)
        if max_body_bytes is None:
            max_body_bytes = getattr(
                options,
                "flow_pruner_max_body_bytes",
                DEFAULT_MAX_BODY_BYTES,
            )
        body_bytes = _retained_body_bytes(retained)
        if len(retained) <= max_flows and body_bytes <= max_body_bytes:
            self._refresh_stats(retained)
            return

        candidates = sorted(
            (flow for flow in retained if _is_terminal(flow)),
            key=lambda flow: (_completion_timestamp(flow), str(getattr(flow, "id", ""))),
        )
        removable = []
        remaining_count = len(retained)
        for flow in candidates:
            if remaining_count <= max_flows and body_bytes <= max_body_bytes:
                break
            removable.append(flow)
            remaining_count -= 1
            body_bytes -= _flow_body_bytes(flow)
        if removable:
            view.remove(removable)
            self._total_pruned += len(removable)
        removed_ids = {id(flow) for flow in removable}
        remaining = [flow for flow in retained if id(flow) not in removed_ids]

        if body_bytes > max_body_bytes:
            body_bytes = self._trim_open_websocket_messages(
                remaining,
                body_bytes,
                max_body_bytes,
            )

        self._refresh_stats(remaining)
        if removable or body_bytes > max_body_bytes:
            log.info(
                "Pruned %d flows (total=%d retained=%d body_bytes=%d)",
                len(removable),
                self._total_pruned,
                self._current_retained,
                self._retained_body_bytes,
            )

    def _trim_open_websocket_messages(
        self,
        flows: list,
        body_bytes: int,
        max_body_bytes: int,
    ) -> int:
        candidates = []
        for flow in flows:
            websocket = getattr(flow, "websocket", None)
            messages = getattr(websocket, "messages", None) if websocket else None
            if (
                not isinstance(messages, list)
                or len(messages) <= 1
                or getattr(websocket, "timestamp_end", None) is not None
            ):
                continue
            for position, message in enumerate(messages[:-1]):
                size = len(getattr(message, "content", b""))
                if size:
                    candidates.append(
                        (
                            _message_timestamp(message, flow, position),
                            str(getattr(flow, "id", "")),
                            position,
                            messages,
                            message,
                            size,
                        )
                    )

        trimmed = 0
        for _, _, _, messages, message, size in sorted(candidates, key=lambda item: item[:3]):
            if body_bytes <= max_body_bytes:
                break
            for position, retained_message in enumerate(messages):
                if retained_message is message:
                    del messages[position]
                    body_bytes -= size
                    trimmed += 1
                    break
        self._total_websocket_messages_trimmed += trimmed
        if trimmed:
            log.info(
                "Trimmed %d old WebSocket messages (total=%d body_bytes=%d)",
                trimmed,
                self._total_websocket_messages_trimmed,
                body_bytes,
            )
        return body_bytes

    def get_stats(self) -> dict:
        self._refresh_stats()
        try:
            configured_max = ctx.options.flow_pruner_max
        except AttributeError:
            configured_max = DEFAULT_MAX_FLOWS
        try:
            configured_max_body_bytes = ctx.options.flow_pruner_max_body_bytes
        except AttributeError:
            configured_max_body_bytes = DEFAULT_MAX_BODY_BYTES
        return {
            "configured_max": configured_max,
            "configured_max_body_bytes": configured_max_body_bytes,
            "current_retained": self._current_retained,
            "retained_body_bytes": self._retained_body_bytes,
            "pruned_total": self._total_pruned,
            "trimmed_websocket_messages": self._total_websocket_messages_trimmed,
        }


addons = [FlowPruner()]
