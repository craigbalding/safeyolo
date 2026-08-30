"""Incremental mitmproxy body filters for live WebSocket transcripts.

Mitmproxy's body filters scan the complete retained WebSocket transcript on
every flow update.  That is necessary after an arbitrary edit, but wasteful
for the normal live-traffic case where exactly one message was appended.
This module preserves the stock filter tree and caches only its ``~b`` leaves.
"""

from __future__ import annotations

import logging
import re
import types
import weakref
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from importlib import metadata
from typing import Any

from mitmproxy import flowfilter, http

log = logging.getLogger("safeyolo.websocket-body-filter")

WEBSOCKET_BODY_FILTER_MAX_FLOWS = 1_024
MITMPROXY_BODY_FILTER_VERSION_PREFIX = "12.2."

_FBOD = getattr(flowfilter, "FBod", None)
_FBOD_REQUEST = getattr(flowfilter, "FBodRequest", None)
_FBOD_RESPONSE = getattr(flowfilter, "FBodResponse", None)
_FAND = getattr(flowfilter, "FAnd", None)
_FOR = getattr(flowfilter, "FOr", None)
_FNOT = getattr(flowfilter, "FNot", None)
_BODY_FILTER_TYPES = tuple(
    filter_type for filter_type in (_FBOD, _FBOD_REQUEST, _FBOD_RESPONSE) if isinstance(filter_type, type)
)
_BINARY_FILTER_TYPES = tuple(filter_type for filter_type in (_FAND, _FOR) if isinstance(filter_type, type))
try:
    _MITMPROXY_VERSION_SUPPORTED = metadata.version("mitmproxy").startswith(MITMPROXY_BODY_FILTER_VERSION_PREFIX)
except metadata.PackageNotFoundError:  # pragma: no cover - imported with mitmproxy
    _MITMPROXY_VERSION_SUPPORTED = False


@dataclass(frozen=True)
class _AppendNote:
    flow_ref: weakref.ReferenceType[http.HTTPFlow]
    websocket: Any
    messages: list[Any]
    message_count: int
    newest_message: Any


@dataclass(frozen=True)
class _HTTPBodySignature:
    message: Any
    raw_content: bytes | None
    headers: tuple[tuple[bytes, bytes], ...]


@dataclass
class _LeafState:
    flow_ref: weakref.ReferenceType[http.HTTPFlow]
    request: _HTTPBodySignature | None
    response: _HTTPBodySignature | None
    websocket: Any
    messages: list[Any]
    message_count: int
    newest_message: Any | None
    result: bool


@dataclass
class _FlowState:
    flow_ref: weakref.ReferenceType[http.HTTPFlow]
    leaves: dict[int, _LeafState] = field(default_factory=dict)


class _And:
    def __init__(self, children: Sequence[Callable[[Any], Any]]) -> None:
        self.children = children

    def __call__(self, flow: Any) -> bool:
        return all(child(flow) for child in self.children)


class _Or:
    def __init__(self, children: Sequence[Callable[[Any], Any]]) -> None:
        self.children = children

    def __call__(self, flow: Any) -> bool:
        return any(child(flow) for child in self.children)


class _Not:
    def __init__(self, child: Callable[[Any], Any]) -> None:
        self.child = child

    def __call__(self, flow: Any) -> bool:
        return not self.child(flow)


class _CachedBodyLeaf:
    def __init__(
        self,
        owner: _OptimizedFilter,
        leaf_id: int,
        original: flowfilter.TFilter,
    ) -> None:
        self.owner = owner
        self.leaf_id = leaf_id
        self.original = original

    def __call__(self, flow: Any) -> bool:
        return self.owner.match_body_leaf(self.leaf_id, self.original, flow)


def _value_signature(value: Any) -> tuple[Any, ...] | str | bytes | int | bool | None:
    if value is None or isinstance(value, (str, bytes, int, bool)):
        return value
    if isinstance(value, re.Pattern):
        return ("regex", value.pattern, value.flags)
    return ("identity", type(value), id(value))


def _ast_signature(node: Any, seen: set[int] | None = None) -> tuple[Any, ...] | None:
    """Describe the small stock AST, or decline optimization on uncertainty."""
    if seen is None:
        seen = set()
    node_id = id(node)
    if node_id in seen:
        return None
    seen.add(node_id)
    try:
        node_type = type(node)
        if node_type in _BINARY_FILTER_TYPES:
            children = getattr(node, "lst", None)
            if not isinstance(children, Sequence) or isinstance(children, (str, bytes)):
                return None
            signatures = []
            for child in children:
                signature = _ast_signature(child, seen)
                if signature is None:
                    return None
                signatures.append(signature)
            return (
                node_type,
                tuple(signatures),
                _value_signature(getattr(node, "pattern", None)),
            )
        if node_type is _FNOT:
            if not hasattr(node, "itm"):
                return None
            child_signature = _ast_signature(node.itm, seen)
            if child_signature is None:
                return None
            return (
                node_type,
                child_signature,
                _value_signature(getattr(node, "pattern", None)),
            )
        if not callable(node):
            return None
        attributes_source = getattr(node, "__dict__", {})
        if not isinstance(attributes_source, dict):
            return None
        attributes = tuple(
            sorted((key, _value_signature(value)) for key, value in attributes_source.items() if key != "pattern")
        )
        return (
            node_type,
            node_id,
            attributes,
            _value_signature(getattr(node, "pattern", None)),
        )
    finally:
        seen.remove(node_id)


def _http_body_signature(message: Any) -> _HTTPBodySignature | None:
    if message is None:
        return None
    raw_content = getattr(message, "raw_content", None)
    if raw_content is not None and not isinstance(raw_content, bytes):
        raise TypeError("HTTP raw_content is not immutable bytes")
    headers = getattr(message, "headers", None)
    fields = getattr(headers, "fields", None)
    if not isinstance(fields, tuple) or not all(
        isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], bytes) and isinstance(item[1], bytes)
        for item in fields
    ):
        raise TypeError("HTTP header storage has an unsupported shape")
    return _HTTPBodySignature(
        message=message,
        raw_content=raw_content,
        headers=tuple(fields),
    )


def _body_signatures(
    flow: http.HTTPFlow,
) -> tuple[_HTTPBodySignature | None, _HTTPBodySignature | None] | None:
    try:
        return (
            _http_body_signature(flow.request),
            _http_body_signature(flow.response),
        )
    except (AttributeError, TypeError):
        return None


def _websocket_shape(
    flow: http.HTTPFlow,
) -> tuple[Any, list[Any]] | None:
    websocket = getattr(flow, "websocket", None)
    messages = getattr(websocket, "messages", None)
    if websocket is None or type(messages) is not list:
        return None
    return websocket, messages


class _OptimizedFilter:
    """A stock filter tree with cache-aware body-filter leaves."""

    def __init__(
        self,
        original: flowfilter.TFilter,
        lifecycle: WebSocketBodyFilterCache,
        *,
        max_flows: int = WEBSOCKET_BODY_FILTER_MAX_FLOWS,
    ) -> None:
        self.original = original
        self.pattern = getattr(original, "pattern", "")
        self.lifecycle = lifecycle
        self.max_flows = max_flows
        self._flows: OrderedDict[str, _FlowState] = OrderedDict()
        self._signature: tuple[Any, ...] | None = None
        self._compiled: Callable[[Any], Any] = original
        self._body_leaf_count = 0
        self._refresh_compiled()

    @property
    def enabled(self) -> bool:
        return self._body_leaf_count > 0 and self._compiled is not self.original

    def _compile_node(self, node: Any) -> Callable[[Any], Any] | None:
        if not _MITMPROXY_VERSION_SUPPORTED:
            return node if callable(node) else None
        node_type = type(node)
        if node_type in _BODY_FILTER_TYPES:
            if not isinstance(getattr(node, "re", None), re.Pattern) or not isinstance(
                getattr(node, "expr", None), str
            ):
                return node
            leaf_id = self._body_leaf_count
            self._body_leaf_count += 1
            return _CachedBodyLeaf(self, leaf_id, node)
        if node_type in _BINARY_FILTER_TYPES:
            children = getattr(node, "lst", None)
            if not isinstance(children, Sequence) or isinstance(children, (str, bytes)):
                return None
            compiled_children = []
            for child in children:
                compiled = self._compile_node(child)
                if compiled is None:
                    return None
                compiled_children.append(compiled)
            if node_type is _FAND:
                return _And(compiled_children)
            return _Or(compiled_children)
        if node_type is _FNOT:
            if not hasattr(node, "itm"):
                return None
            child = self._compile_node(node.itm)
            return None if child is None else _Not(child)
        return node if callable(node) else None

    def _refresh_compiled(self) -> None:
        signature = _ast_signature(self.original)
        self._flows.clear()
        self._body_leaf_count = 0
        if signature is None:
            self._signature = None
            self._compiled = self.original
            return
        compiled = self._compile_node(self.original)
        if compiled is None or self._body_leaf_count == 0:
            self._compiled = self.original
        else:
            self._compiled = compiled
        self._signature = signature
        self.pattern = getattr(self.original, "pattern", "")

    def __call__(self, flow: Any) -> Any:
        signature = _ast_signature(self.original)
        if signature is None:
            self._flows.clear()
            self._signature = None
            self._compiled = self.original
        elif signature != self._signature:
            self._refresh_compiled()
        return self._compiled(flow)

    def clear(self) -> None:
        self._flows.clear()

    def evict(self, flow: Any) -> None:
        state = self._flows.get(getattr(flow, "id", ""))
        if state is not None and state.flow_ref() is flow:
            self._flows.pop(flow.id, None)

    def _flow_state(self, flow: http.HTTPFlow) -> _FlowState:
        state = self._flows.get(flow.id)
        if state is None or state.flow_ref() is not flow:
            state = _FlowState(weakref.ref(flow))
            self._flows[flow.id] = state
        self._flows.move_to_end(flow.id)
        while len(self._flows) > self.max_flows:
            self._flows.popitem(last=False)
        return state

    def _snapshot(
        self,
        flow: http.HTTPFlow,
        result: bool,
    ) -> _LeafState | None:
        body_signatures = _body_signatures(flow)
        shape = _websocket_shape(flow)
        if body_signatures is None or shape is None:
            return None
        websocket, messages = shape
        return _LeafState(
            flow_ref=weakref.ref(flow),
            request=body_signatures[0],
            response=body_signatures[1],
            websocket=websocket,
            messages=messages,
            message_count=len(messages),
            newest_message=messages[-1] if messages else None,
            result=result,
        )

    def _can_extend(
        self,
        flow: http.HTTPFlow,
        state: _LeafState,
        note: _AppendNote | None,
    ) -> tuple[list[Any], tuple[_HTTPBodySignature | None, _HTTPBodySignature | None]] | None:
        if note is None or note.flow_ref() is not flow or state.flow_ref() is not flow:
            return None
        body_signatures = _body_signatures(flow)
        shape = _websocket_shape(flow)
        if body_signatures is None or shape is None:
            return None
        websocket, messages = shape
        if (
            body_signatures != (state.request, state.response)
            or websocket is not state.websocket
            or messages is not state.messages
            or websocket is not note.websocket
            or messages is not note.messages
            or len(messages) != note.message_count
            or note.message_count != state.message_count + 1
            or (messages and messages[-1] is not note.newest_message)
            or (state.message_count and messages[state.message_count - 1] is not state.newest_message)
        ):
            return None
        return messages, body_signatures

    @staticmethod
    def _match_new_message(original: flowfilter.TFilter, message: Any) -> bool:
        node_type = type(original)
        if node_type is _FBOD:
            return message.content is not None and bool(original.re.search(message.content))
        if node_type is _FBOD_REQUEST:
            return message.from_client and bool(original.re.search(message.content))
        if node_type is _FBOD_RESPONSE:
            return not message.from_client and bool(original.re.search(message.content))
        raise TypeError("unsupported body filter leaf")

    def match_body_leaf(
        self,
        leaf_id: int,
        original: flowfilter.TFilter,
        flow: Any,
    ) -> bool:
        if not isinstance(flow, http.HTTPFlow) or _websocket_shape(flow) is None:
            return bool(original(flow))

        flow_state = self._flow_state(flow)
        prior = flow_state.leaves.get(leaf_id)
        extended = None
        if prior is not None:
            extended = self._can_extend(
                flow,
                prior,
                self.lifecycle.append_note(flow, self),
            )
        if prior is not None and extended is not None:
            messages, body_signatures = extended
            result = prior.result or self._match_new_message(original, messages[-1])
            flow_state.leaves[leaf_id] = _LeafState(
                flow_ref=weakref.ref(flow),
                request=body_signatures[0],
                response=body_signatures[1],
                websocket=prior.websocket,
                messages=prior.messages,
                message_count=len(messages),
                newest_message=messages[-1],
                result=result,
            )
            return result

        result = bool(original(flow))
        snapshot = self._snapshot(flow, result)
        if snapshot is None:
            flow_state.leaves.pop(leaf_id, None)
        else:
            flow_state.leaves[leaf_id] = snapshot
        return result


class WebSocketBodyFilterCache:
    """Lifecycle evidence and bounded caches for the active view filter."""

    name = "safeyolo-websocket-body-filter-cache"

    def __init__(self, master: Any) -> None:
        self.master = master
        self.view = master.view
        self._append_notes: dict[str, _AppendNote] = {}
        self._current_filter: _OptimizedFilter | None = None
        self._original_set_filter = self.view.set_filter
        self._installed_set_filter: types.MethodType | None = None
        self._trusted_chain: tuple[int, ...] | None = None

    def install(self) -> None:
        if not callable(self._original_set_filter):
            raise TypeError("View.set_filter is unavailable")
        for signal_name in ("sig_store_remove", "sig_store_refresh"):
            signal = getattr(self.view, signal_name, None)
            if signal is None or not callable(getattr(signal, "connect", None)):
                raise TypeError(f"View.{signal_name} is unavailable")

        def set_filter(view: Any, flt: flowfilter.TFilter | None) -> None:
            if view is not self.view:
                raise TypeError("body-filter cache installed on a different View")
            if isinstance(flt, _OptimizedFilter):
                active_filter = flt
                installed_filter: flowfilter.TFilter | None = flt
            elif flt is None:
                active_filter = None
                installed_filter = None
            else:
                candidate = _OptimizedFilter(flt, self)
                active_filter = candidate if candidate.enabled else None
                installed_filter = active_filter or flt
            if self._current_filter is not None and self._current_filter is not active_filter:
                self._current_filter.clear()
            self._current_filter = active_filter
            self._append_notes.clear()
            self._original_set_filter(installed_filter)

        self._installed_set_filter = types.MethodType(set_filter, self.view)
        self.view.set_filter = self._installed_set_filter
        self.view.sig_store_remove.connect(self._store_remove)
        self.view.sig_store_refresh.connect(self._store_refresh)
        self.view.set_filter(self.view.filter)

    def rollback_install(self) -> None:
        """Restore stock filtering if guarded installation fails part-way."""
        current = getattr(self.view, "filter", None)
        if isinstance(current, _OptimizedFilter):
            current = current.original
        if getattr(self.view, "set_filter", None) is self._installed_set_filter:
            self.view.set_filter = self._original_set_filter
        for signal_name, receiver in (
            ("sig_store_remove", self._store_remove),
            ("sig_store_refresh", self._store_refresh),
        ):
            signal = getattr(self.view, signal_name, None)
            disconnect = getattr(signal, "disconnect", None)
            if callable(disconnect):
                disconnect(receiver)
        if callable(self._original_set_filter):
            self._original_set_filter(current)
        self.clear()

    def append_note(
        self,
        flow: http.HTTPFlow,
        owner: _OptimizedFilter,
    ) -> _AppendNote | None:
        if self._current_filter is not owner or self.view.filter is not owner:
            return None
        note = self._append_notes.get(flow.id)
        if note is not None and note.flow_ref() is flow:
            return note
        return None

    def mark_installed(self) -> None:
        chain = getattr(getattr(self.master, "addons", None), "chain", None)
        self._trusted_chain = tuple(map(id, chain)) if isinstance(chain, list) else None

    def _runtime_is_trustworthy(self) -> bool:
        """Reject append evidence if unreviewed message mutators are present."""
        chain = getattr(getattr(self.master, "addons", None), "chain", None)
        options = getattr(self.master, "options", None)
        scripts = getattr(options, "scripts", None)
        return (
            _MITMPROXY_VERSION_SUPPORTED
            and isinstance(chain, list)
            and self._trusted_chain is not None
            and tuple(map(id, chain)) == self._trusted_chain
            and bool(chain)
            and chain[-1] is self
            and isinstance(scripts, (list, tuple))
            and not scripts
        )

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        if not self._runtime_is_trustworthy():
            self._append_notes.pop(flow.id, None)
            return
        shape = _websocket_shape(flow)
        if shape is None:
            self._append_notes.pop(flow.id, None)
            return
        websocket, messages = shape
        if not messages:
            self._append_notes.pop(flow.id, None)
            return
        if flow.id not in self._append_notes and len(self._append_notes) >= WEBSOCKET_BODY_FILTER_MAX_FLOWS:
            self._append_notes.pop(next(iter(self._append_notes)))
        self._append_notes[flow.id] = _AppendNote(
            flow_ref=weakref.ref(flow),
            websocket=websocket,
            messages=messages,
            message_count=len(messages),
            newest_message=messages[-1],
        )

    def update(self, flows: Sequence[Any]) -> None:
        for flow in flows:
            self._append_notes.pop(getattr(flow, "id", ""), None)

    def _store_remove(self, flow: Any) -> None:
        self._append_notes.pop(getattr(flow, "id", ""), None)
        if self._current_filter is not None:
            self._current_filter.evict(flow)

    def _store_refresh(self) -> None:
        self.clear()

    def clear(self) -> None:
        self._append_notes.clear()
        if self._current_filter is not None:
            self._current_filter.clear()

    def done(self) -> None:
        self.clear()


def install_websocket_body_filter_cache(master: Any) -> WebSocketBodyFilterCache | None:
    """Install the guarded View integration, falling back to stock on drift."""
    existing = getattr(master, "_safeyolo_websocket_body_filter_cache", None)
    if isinstance(existing, WebSocketBodyFilterCache):
        return existing
    if not _MITMPROXY_VERSION_SUPPORTED:
        log.warning("WebSocket body-filter cache disabled: unsupported mitmproxy version")
        return None
    view = getattr(master, "view", None)
    addons = getattr(master, "addons", None)
    if view is None or addons is None or not callable(getattr(addons, "add", None)):
        log.warning("WebSocket body-filter cache disabled: TrafficMaster shape changed")
        return None
    try:
        cache = WebSocketBodyFilterCache(master)
        cache.install()
        addons.add(cache)
        cache.mark_installed()
    except Exception:
        if "cache" in locals():
            cache.rollback_install()
        log.warning(
            "WebSocket body-filter cache disabled: mitmproxy View shape changed",
            exc_info=True,
        )
        return None
    master._safeyolo_websocket_body_filter_cache = cache
    return cache
