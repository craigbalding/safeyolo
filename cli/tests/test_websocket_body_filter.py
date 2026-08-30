"""Contracts for incremental active body filters on live WebSockets."""

from __future__ import annotations

import asyncio
import re
import time
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from mitmproxy import flowfilter, options
from mitmproxy.test import tflow
from mitmproxy.tools.web import app
from mitmproxy.websocket import WebSocketMessage
from wsproto.frame_protocol import Opcode

from safeyolo.traffic_master import TrafficMaster
from safeyolo.websocket_body_filter import (
    WebSocketBodyFilterCache,
    install_websocket_body_filter_cache,
)


async def _construct_master() -> TrafficMaster:
    return TrafficMaster(options.Options())


def _master() -> TrafficMaster:
    return asyncio.run(_construct_master())


def _message(content: bytes, *, from_client: bool = True) -> WebSocketMessage:
    return WebSocketMessage(Opcode.TEXT, from_client, content)


def _flow(*messages: WebSocketMessage):
    flow = tflow.twebsocketflow(messages=False)
    assert flow.websocket is not None
    flow.websocket.messages = list(messages)
    flow.request.raw_content = b"request body"
    assert flow.response is not None
    flow.response.raw_content = b"response body"
    return flow


def _cache(master: TrafficMaster) -> WebSocketBodyFilterCache:
    cache = master.addons.get("safeyolo-websocket-body-filter-cache")
    assert isinstance(cache, WebSocketBodyFilterCache)
    return cache


def _body_leaves(node):
    if type(node) in (
        flowfilter.FBod,
        flowfilter.FBodRequest,
        flowfilter.FBodResponse,
    ):
        return [node]
    if type(node) in (flowfilter.FAnd, flowfilter.FOr):
        result = []
        for child in node.lst:
            result.extend(_body_leaves(child))
        return result
    if type(node) is flowfilter.FNot:
        return _body_leaves(node.itm)
    return []


def _count_searches(filter_ast):
    counters = []
    for leaf in _body_leaves(filter_ast):
        leaf.re = Mock(spec=leaf.re, wraps=leaf.re)
        counters.append(leaf.re.search)
    return counters


def _set_filter(master: TrafficMaster, expression: str):
    filter_ast = flowfilter.parse(expression)
    counters = _count_searches(filter_ast)
    master.view.set_filter(filter_ast)
    return filter_ast, counters


def _append(
    master: TrafficMaster,
    flow,
    content: bytes,
    *,
    from_client: bool = True,
) -> None:
    assert flow.websocket is not None
    flow.websocket.messages.append(_message(content, from_client=from_client))
    cache = _cache(master)
    cache.websocket_message(flow)
    master.view.update([flow])
    cache.update([flow])


def test_incremental_composite_and_negated_filter_preserves_old_matches() -> None:
    master = _master()
    flow = _flow(_message(b"old miss"))
    master.view.add([flow])
    _ast, (search,) = _set_filter(master, "~m GET & !(~b needle)")
    activation_calls = search.call_count
    assert flow in master.view

    _append(master, flow, b"new miss")
    assert flow in master.view
    assert search.call_count == activation_calls + 1

    _append(master, flow, b"needle in new frame")
    assert flow not in master.view
    assert search.call_count == activation_calls + 2

    _append(master, flow, b"later miss")
    assert flow not in master.view
    assert search.call_count == activation_calls + 2


def test_or_filter_can_become_true_from_one_new_message() -> None:
    master = _master()
    flow = _flow(_message(b"old miss"))
    master.view.add([flow])
    _ast, (search,) = _set_filter(master, "~m POST | ~b needle")
    activation_calls = search.call_count
    assert flow not in master.view

    _append(master, flow, b"needle")

    assert flow in master.view
    assert search.call_count == activation_calls + 1


def test_request_and_response_body_semantics_and_changes() -> None:
    master = _master()
    flow = _flow(_message(b"websocket miss"))
    flow.request.raw_content = b"request needle"
    assert flow.response is not None
    flow.response.raw_content = b"response needle"
    master.view.add([flow])

    _set_filter(master, "~bq request\\s+needle")
    assert flow in master.view
    _set_filter(master, "~bs response\\s+needle")
    assert flow in master.view
    _set_filter(master, "~bq response\\s+needle")
    assert flow not in master.view

    _set_filter(master, "~bq request\\s+needle")
    flow.request.raw_content = b"clean"
    master.view.update([flow])
    assert flow not in master.view

    flow.request.raw_content = b"request needle again"
    _append(master, flow, b"append miss")
    assert flow in master.view


@pytest.mark.parametrize(
    ("expression", "from_client", "expected"),
    [
        ("~bq directional-needle", True, True),
        ("~bq directional-needle", False, False),
        ("~bs directional-needle", True, False),
        ("~bs directional-needle", False, True),
    ],
)
def test_directional_body_filters_apply_to_new_websocket_messages(
    expression: str,
    from_client: bool,
    expected: bool,
) -> None:
    master = _master()
    flow = _flow(_message(b"old miss", from_client=not from_client))
    master.view.add([flow])
    _set_filter(master, expression)

    _append(master, flow, b"directional-needle", from_client=from_client)

    assert (flow in master.view) is expected


@pytest.mark.parametrize("mutation", ["edit", "replace", "remove"])
def test_arbitrary_message_mutations_force_a_full_recheck(mutation: str) -> None:
    master = _master()
    flow = _flow(_message(b"needle"), _message(b"miss"))
    master.view.add([flow])
    _ast, (search,) = _set_filter(master, "~b needle")
    activation_calls = search.call_count
    assert flow in master.view
    assert flow.websocket is not None

    if mutation == "edit":
        flow.websocket.messages[0].content = b"edited miss"
    elif mutation == "replace":
        flow.websocket.messages[0] = _message(b"replacement miss")
    else:
        flow.websocket.messages.pop(0)
    master.view.update([flow])

    assert flow not in master.view
    assert search.call_count > activation_calls


def test_reorder_is_not_mistaken_for_an_append() -> None:
    master = _master()
    flow = _flow(_message(b"first"), _message(b"second"))
    master.view.add([flow])
    _ast, (search,) = _set_filter(master, "~b absent")
    activation_calls = search.call_count
    assert flow.websocket is not None

    flow.websocket.messages.reverse()
    master.view.update([flow])

    assert flow not in master.view
    # request + response + the complete two-message transcript were searched.
    assert search.call_count == activation_calls + 4


def test_custom_script_shape_disables_append_trust() -> None:
    master = _master()
    flow = _flow(_message(b"old miss"))
    master.view.add([flow])
    _set_filter(master, "~b needle")
    assert flow not in master.view
    assert flow.websocket is not None

    # A user script may edit any older message inside websocket_message. With
    # scripts active, the lifecycle marker is deliberately not append evidence.
    master.options._options["scripts"].set(["custom-addon.py"])
    flow.websocket.messages[0].content = b"old message now has needle"
    _append(master, flow, b"new miss")

    assert flow in master.view


def test_filter_ast_change_invalidates_an_append_candidate() -> None:
    master = _master()
    flow = _flow(_message(b"old needle"))
    master.view.add([flow])
    filter_ast = flowfilter.parse("~b needle")
    master.view.set_filter(filter_ast)
    assert flow in master.view

    filter_ast.expr = "replacement"
    filter_ast.re = re.compile(b"replacement", re.DOTALL | re.IGNORECASE)
    _append(master, flow, b"new miss")
    assert flow not in master.view

    master.view.set_filter(flowfilter.parse("~b old"))
    assert flow in master.view
    master.view.set_filter(flowfilter.parse("~b replacement"))
    assert flow not in master.view


def test_flow_replacement_and_store_cleanup_cannot_reuse_stale_results() -> None:
    master = _master()
    first = _flow(_message(b"needle"))
    master.view.add([first])
    _set_filter(master, "~b needle")
    optimized = master.view.filter
    optimized.max_flows = 2
    assert optimized(first)

    replacement = _flow(_message(b"miss"))
    replacement.id = first.id
    assert not optimized(replacement)

    second = _flow(_message(b"miss"))
    third = _flow(_message(b"miss"))
    optimized(second)
    optimized(third)
    assert len(optimized._flows) == 2

    master.view.sig_store_remove.send(flow=third)
    assert third.id not in optimized._flows
    master.view.sig_store_refresh.send()
    assert not optimized._flows

    optimized(first)
    assert optimized._flows
    master.view.set_filter(flowfilter.parse("~m GET"))
    assert not optimized._flows


def test_filtering_never_changes_the_full_websocket_model() -> None:
    master = _master()
    flow = _flow(*(_message(f"message-{index}".encode()) for index in range(50)))
    assert flow.websocket is not None
    original_messages = tuple(flow.websocket.messages)
    original_content = tuple(message.content for message in original_messages)
    master.view.add([flow])
    _set_filter(master, "~b absent")

    for index in range(10):
        _append(master, flow, f"new-{index}".encode())

    assert tuple(flow.websocket.messages[:50]) == original_messages
    assert tuple(message.content for message in flow.websocket.messages[:50]) == original_content
    assert app.flow_to_json(flow)["websocket"]["messages_meta"]["count"] == 60


def test_four_thousand_live_misses_are_linear_and_return_control_promptly() -> None:
    master = _master()
    flow = _flow()
    master.view.add([flow])
    _ast, (search,) = _set_filter(master, "~b SAFETY_NEVER_MATCH")
    activation_calls = search.call_count
    callbacks: list[str] = []

    async def exercise() -> float:
        loop = asyncio.get_running_loop()
        for component in ("console", "mitmweb", "proxy", "admin"):
            loop.call_soon(callbacks.append, component)
        started = time.perf_counter()
        for index in range(4_000):
            _append(master, flow, f"{index:04d}".encode() + b"x" * 896)
        elapsed = time.perf_counter() - started
        await asyncio.sleep(0)
        return elapsed

    elapsed = asyncio.run(exercise())

    assert search.call_count == activation_calls + 4_000
    assert callbacks == ["console", "mitmweb", "proxy", "admin"]
    assert elapsed < 2.0


def test_first_activation_and_full_invalidation_are_single_bounded_scans() -> None:
    master = _master()
    flow = _flow(*(_message(b"x" * 900) for _index in range(4_000)))
    master.view.add([flow])
    filter_ast = flowfilter.parse("~b SAFETY_NEVER_MATCH")
    (search,) = _count_searches(filter_ast)

    started = time.perf_counter()
    master.view.set_filter(filter_ast)
    activation_elapsed = time.perf_counter() - started
    activation_calls = search.call_count

    assert activation_calls == 4_002
    assert activation_elapsed < 2.0
    assert flow.websocket is not None
    flow.websocket.messages.reverse()
    started = time.perf_counter()
    master.view.update([flow])
    invalidation_elapsed = time.perf_counter() - started
    assert search.call_count == activation_calls + 4_002
    assert invalidation_elapsed < 2.0


def test_private_view_integration_is_idempotent_and_guarded() -> None:
    master = _master()
    assert master.view.filter is flowfilter.match_all
    installed = install_websocket_body_filter_cache(master)
    assert installed is _cache(master)
    assert master.addons.chain[-1] is installed

    incompatible = SimpleNamespace(view=SimpleNamespace(), addons=SimpleNamespace(add=lambda *_: None))
    with patch("safeyolo.websocket_body_filter.log.warning", autospec=True) as warning:
        assert install_websocket_body_filter_cache(incompatible) is None
    warning.assert_called_once()
