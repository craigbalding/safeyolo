"""Tests for pinned SafeYolo scope composition."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from mitmproxy import exceptions, flowfilter
from traffic_scope import TrafficScope


class FakeOptions:
    def __init__(self, view_filter=""):
        self.view_filter = view_filter

    def update(self, **values):
        for key, value in values.items():
            setattr(self, key, value)


class FakeView:
    def __init__(self, flows):
        self.flows = flows

    def resolve(self, selector):
        assert selector == "@all"
        return self.flows


def fake_flow(agent, test_id=None, *, timestamp=0, intent=None, role=None, expect=None):
    metadata = {"agent": agent}
    for key, value in (
        ("test_id", test_id),
        ("test_intent", intent),
        ("test_role", role),
        ("test_expect", expect),
    ):
        if value is not None:
            metadata[key] = value
    return SimpleNamespace(
        metadata=metadata,
        request=SimpleNamespace(timestamp_start=timestamp),
        response=None,
    )


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


def test_malformed_user_filter_does_not_poison_scope_shortcuts():
    addon = TrafficScope()
    options = FakeOptions("~m GET")
    master = SimpleNamespace(
        view=FakeView([fake_flow("alice"), fake_flow("claude")]),
        addons=SimpleNamespace(get=lambda _name: None),
    )
    with patch("traffic_scope.ctx", SimpleNamespace(options=options, master=master)):
        addon.running()
        addon.set_scope(agent="alice")
        options.view_filter = '~meta "unterminated'
        with pytest.raises(exceptions.OptionsError):
            addon.configure({"view_filter"})

        assert addon.user_filter == "~m GET"
        assert addon.next_agent() is None

    assert addon.agent == "claude"
    assert flowfilter.parse(options.view_filter) is not None


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


def test_key_bound_scope_actions_do_not_return_modal_output():
    addon = TrafficScope()
    options = FakeOptions()
    master = SimpleNamespace(
        view=FakeView([fake_flow("alice")]),
        addons=SimpleNamespace(get=lambda _name: None),
    )
    with patch("traffic_scope.ctx", SimpleNamespace(options=options, master=master)):
        assert addon.select_agent("alice") is None
        assert addon.all_agents() is None
        assert addon.unattributed_only() is None
        assert addon.clear_test() is None
        assert addon.clear_scope() is None


def test_seven_agent_cycle_uses_canonical_store_and_keeps_user_filter():
    addon = TrafficScope()
    options = FakeOptions("~m GET")
    agents = [f"agent-{number}" for number in range(7)]
    master = SimpleNamespace(
        view=FakeView([fake_flow(agent) for agent in reversed(agents)]),
        addons=SimpleNamespace(get=lambda _name: None),
    )
    with patch("traffic_scope.ctx", SimpleNamespace(options=options, master=master)):
        addon.running()
        selected = []
        for _ in agents:
            assert addon.next_agent() is None
            selected.append(addon.agent)
        assert addon.next_agent() is None
        wrapped = addon.agent
        assert addon.previous_agent() is None
        previous = addon.agent

    assert selected == agents
    assert wrapped == "agent-0"
    assert previous == "agent-6"
    assert addon.user_filter == "~m GET"
    assert options.view_filter.endswith("(~m GET)")


def test_test_chooser_has_context_count_and_recency_and_clear_retains_agent():
    addon = TrafficScope()
    options = FakeOptions()
    flows = [
        fake_flow("alice", "FLOW-05", timestamp=990, intent="forge", expect="blocked"),
        fake_flow("alice", "FLOW-05", timestamp=995, intent="forge", expect="blocked"),
        fake_flow("bob", "FLOW-06", timestamp=999, intent="read", expect="allowed"),
    ]
    master = SimpleNamespace(
        view=FakeView(flows),
        addons=SimpleNamespace(get=lambda _name: None),
    )
    with (
        patch("traffic_scope.ctx", SimpleNamespace(options=options, master=master)),
        patch("traffic_scope.time.time", return_value=1000),
    ):
        addon.set_scope(agent="alice")
        choices = addon.test_options()
        addon.select_test(choices[0])
        selected = addon.get_stats()
        addon.clear_test()

    assert choices == ["FLOW-05 · forge · blocked · 2 flows · 5s ago"]
    assert selected["agent"] == "alice"
    assert selected["test_id"] == "FLOW-05"
    assert selected["intent"] == "forge"
    assert selected["expect"] == "blocked"
    assert addon.agent == "alice"
    assert addon.test_id is None


def test_running_agents_are_available_before_they_have_flows():
    addon = TrafficScope()
    options = FakeOptions()
    discovery = SimpleNamespace(
        get_agents=lambda: {"agents": {"running-no-traffic": {"ip": "10.0.0.8"}}}
    )
    master = SimpleNamespace(
        view=FakeView([fake_flow("observed")]),
        addons=SimpleNamespace(get=lambda name: discovery if name == "service-discovery" else None),
    )
    with patch("traffic_scope.ctx", SimpleNamespace(options=options, master=master)):
        assert addon.agent_options() == ["observed", "running-no-traffic"]


def test_web_facets_offer_seven_agents_and_only_relevant_test_contexts():
    addon = TrafficScope()
    options = FakeOptions()
    agents = [f"agent-{number}" for number in range(7)]
    flows = [
        fake_flow(agent, f"TEST-{number}", timestamp=number)
        for number, agent in enumerate(agents)
    ]
    master = SimpleNamespace(
        view=FakeView(flows),
        addons=SimpleNamespace(get=lambda _name: None),
    )
    with patch("traffic_scope.ctx", SimpleNamespace(options=options, master=master)):
        all_facets = addon.facet_values()
        addon.set_scope(agent="agent-4")
        narrowed = addon.facet_values()

    assert [item["value"] for item in all_facets["agent"]] == agents
    assert narrowed["test_id"] == [{"value": "TEST-4", "count": 1}]
