"""Tests for pinned SafeYolo scope composition."""

from types import SimpleNamespace
from unittest.mock import patch

from mitmproxy import flowfilter
from traffic_scope import TrafficScope


class FakeOptions:
    def __init__(self, view_filter=""):
        self.view_filter = view_filter

    def update(self, **values):
        for key, value in values.items():
            setattr(self, key, value)


def test_scope_and_user_filter_are_composed_separately():
    addon = TrafficScope()
    options = FakeOptions("~m GET")
    with patch("traffic_scope.ctx", SimpleNamespace(options=options)):
        addon.running()
        addon.set_scope(agent="cody", test_id="FLOW-05")

    assert addon.user_filter == "~m GET"
    assert addon.effective_filter() == (
        r'~meta "^agent:\ cody$" & ~meta "^test_id:\ FLOW\-05$" & (~m GET)'
    )
    assert flowfilter.parse(addon.effective_filter()) is not None

    scope_only = flowfilter.parse(" & ".join(addon._scope_parts()))
    assert flowfilter.match(
        scope_only,
        SimpleNamespace(metadata={"agent": "cody", "test_id": "FLOW-05"}),
    )
    assert not flowfilter.match(
        scope_only,
        SimpleNamespace(metadata={"agent": "alice", "test_id": "FLOW-05"}),
    )


def test_external_user_filter_edit_cannot_remove_pinned_scope():
    addon = TrafficScope()
    options = FakeOptions()
    fake_ctx = SimpleNamespace(options=options)
    with patch("traffic_scope.ctx", fake_ctx):
        addon.set_scope(agent="cody")
        options.view_filter = "~u example.com"
        addon.configure({"view_filter"})

    assert addon.user_filter == "~u example.com"
    assert "agent" in options.view_filter
    assert options.view_filter.endswith("(~u example.com)")


def test_scope_values_are_escaped_and_unattributed_is_distinct():
    addon = TrafficScope()
    options = FakeOptions()
    with patch("traffic_scope.ctx", SimpleNamespace(options=options)):
        addon.set_scope(agent='cody" | ~all')
        escaped = addon.effective_filter()
        addon.set_scope(unattributed=True)
        unattributed = addon.effective_filter()

    assert flowfilter.parse(escaped) is not None
    assert "\\\"" in escaped
    assert unattributed == "!(~meta ^agent:)"


def test_setting_new_scope_clears_omitted_dimensions():
    addon = TrafficScope()
    options = FakeOptions()
    with patch("traffic_scope.ctx", SimpleNamespace(options=options)):
        addon.set_scope(agent="cody", test_id="FLOW-05", intent="forge")
        result = addon.set_scope(agent="alice")

    assert result["agent"] == "alice"
    assert result["test_id"] is None
    assert result["intent"] is None
