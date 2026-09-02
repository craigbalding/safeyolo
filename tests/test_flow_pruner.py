"""Tests for deterministic shared-view flow pruning."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from flow_pruner import FlowPruner, _all_stored_flows
from mitmproxy import exceptions


class FakeView:
    def __init__(self, stored, visible=None):
        self.stored = list(stored)
        self.visible = list(self.stored if visible is None else visible)

    def __iter__(self):
        return iter(self.visible)

    def __len__(self):
        return len(self.visible)

    def resolve(self, spec):
        assert spec == "@all"
        return list(self.stored)

    def remove(self, flows):
        for flow in flows:
            self.stored.remove(flow)
            if flow in self.visible:
                self.visible.remove(flow)


def make_flow(identifier, timestamp, *, live=False, intercepted=False, websocket=None):
    return SimpleNamespace(
        id=identifier,
        timestamp_created=timestamp,
        timestamp_end=None,
        live=live,
        intercepted=intercepted,
        request=SimpleNamespace(timestamp_start=timestamp, raw_content=b"request"),
        response=SimpleNamespace(timestamp_end=timestamp, raw_content=b"response"),
        error=None,
        websocket=websocket,
    )


def test_underlying_store_is_used_when_operator_filter_hides_flows():
    hidden = make_flow("hidden", 1)
    visible = make_flow("visible", 2)
    view = FakeView([hidden, visible], visible=[visible])

    assert _all_stored_flows(view) == [hidden, visible]


def test_prunes_oldest_terminal_flows_independent_of_view_order():
    newest = make_flow("newest", 30)
    oldest = make_flow("oldest", 10)
    middle = make_flow("middle", 20)
    view = FakeView([newest, oldest, middle], visible=[newest, middle, oldest])
    addon = FlowPruner()

    fake_ctx = SimpleNamespace(
        master=SimpleNamespace(view=view),
        options=SimpleNamespace(flow_pruner_max=2),
    )
    with patch("flow_pruner.ctx", fake_ctx):
        addon._prune(view, list(view.stored), 2)
        stats = addon.get_stats()

    assert [flow.id for flow in view.stored] == ["newest", "middle"]
    assert stats["pruned_total"] == 1


def test_active_intercepted_and_open_websocket_flows_are_preserved():
    active = make_flow("active", 1, live=True)
    intercepted = make_flow("intercepted", 2, intercepted=True)
    websocket = make_flow(
        "websocket",
        3,
        websocket=SimpleNamespace(timestamp_end=None, messages=[]),
    )
    terminal = make_flow("terminal", 4)
    view = FakeView([active, intercepted, websocket, terminal])
    addon = FlowPruner()

    with patch("flow_pruner.ctx", SimpleNamespace(master=SimpleNamespace(view=view))):
        addon._prune(view, list(view.stored), 3)

    assert [flow.id for flow in view.stored] == ["active", "intercepted", "websocket"]


def test_prunes_oldest_terminal_flows_to_retained_body_limit():
    oldest = make_flow("oldest", 10)
    middle = make_flow("middle", 20)
    newest = make_flow("newest", 30)
    for flow in (oldest, middle, newest):
        flow.request.raw_content = b"req1"
        flow.response.raw_content = b"resp"
    view = FakeView([newest, oldest, middle])
    addon = FlowPruner()

    with patch("flow_pruner.ctx", SimpleNamespace(master=SimpleNamespace(view=view))):
        addon._prune(
            view,
            list(view.stored),
            max_flows=10,
            max_body_bytes=16,
        )
        stats = addon.get_stats()

    assert [flow.id for flow in view.stored] == ["newest", "middle"]
    assert stats["retained_body_bytes"] == 16
    assert stats["pruned_total"] == 1


def test_trims_old_live_websocket_messages_but_keeps_newest_message():
    messages = [
        SimpleNamespace(timestamp=1, content=b"a" * 8),
        SimpleNamespace(timestamp=2, content=b"b" * 8),
        SimpleNamespace(timestamp=3, content=b"c" * 8),
    ]
    flow = make_flow(
        "websocket",
        1,
        websocket=SimpleNamespace(timestamp_end=None, messages=messages),
    )
    flow.request.raw_content = b""
    flow.response.raw_content = b""
    view = FakeView([flow])
    addon = FlowPruner()

    with patch("flow_pruner.ctx", SimpleNamespace(master=SimpleNamespace(view=view))):
        addon._prune(
            view,
            list(view.stored),
            max_flows=10,
            max_body_bytes=12,
        )
        stats = addon.get_stats()

    assert view.stored == [flow]
    assert [message.content for message in messages] == [b"c" * 8]
    assert stats["retained_body_bytes"] == 8
    assert stats["trimmed_websocket_messages"] == 2


def test_stats_include_count_and_retained_body_weight():
    flow = make_flow("one", 1)
    flow.websocket = SimpleNamespace(
        timestamp_end=2,
        messages=[SimpleNamespace(content=b"websocket")],
    )
    view = FakeView([flow])
    addon = FlowPruner()
    options = SimpleNamespace(
        flow_pruner_max=123,
        flow_pruner_max_body_bytes=456,
    )

    with patch(
        "flow_pruner.ctx",
        SimpleNamespace(master=SimpleNamespace(view=view), options=options),
    ):
        stats = addon.get_stats()

    assert stats == {
        "configured_max": 123,
        "configured_max_body_bytes": 456,
        "current_retained": 1,
        "retained_body_bytes": len(b"requestresponsewebsocket"),
        "pruned_total": 0,
        "trimmed_websocket_messages": 0,
    }


@pytest.mark.parametrize("value", [0, -1])
def test_non_positive_mitmproxy_option_is_rejected(value):
    addon = FlowPruner()
    with patch("flow_pruner.ctx", SimpleNamespace(options=SimpleNamespace(flow_pruner_max=value))):
        with pytest.raises(exceptions.OptionsError, match="positive integer"):
            addon.configure({"flow_pruner_max"})


@pytest.mark.parametrize("value", [0, -1])
def test_non_positive_retained_body_limit_is_rejected(value):
    addon = FlowPruner()
    options = SimpleNamespace(
        flow_pruner_max=1,
        flow_pruner_max_body_bytes=value,
    )
    with patch("flow_pruner.ctx", SimpleNamespace(options=options)):
        with pytest.raises(exceptions.OptionsError, match="positive integer"):
            addon.configure({"flow_pruner_max_body_bytes"})
