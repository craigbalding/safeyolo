"""The observer long-polls; it does not sleep-poll read_room.

read_room opens and deletes its own ephemeral pull consumer per call, so a
0.5s poll loop cost roughly two consumer create/delete cycles a second for as
long as an observer ran. These pin the loop's shape rather than its plumbing.
"""
from __future__ import annotations

import pytest

from safeyolo.commands import coord


class _Runtime:
    """Stands in for _ChatRuntime; the fakes below are plain callables."""

    def run(self, value):
        return value


@pytest.fixture
def fake_api(monkeypatch):
    calls: list[tuple] = []

    class FakeAPI:
        READ_PAGE_MAX = 200
        GrantError = RuntimeError

        def __init__(self):
            self.wakes = []
            self.pages = []

        def wait_for_message(self, room, kind, pid, **kw):
            calls.append(("wait", kw))
            if not self.wakes:
                raise KeyboardInterrupt
            return self.wakes.pop(0)

        def read_room(self, room, kind, pid, **kw):
            calls.append(("read", kw))
            return self.pages.pop(0) if self.pages else {
                "messages": [], "next_cursor": kw["since_sequence"],
                "has_more": False,
            }

    api = FakeAPI()
    monkeypatch.setattr(coord, "api", api)
    monkeypatch.setattr(coord, "_render_message", lambda m: None)
    return api, calls


def test_observer_waits_instead_of_polling_read_room(fake_api):
    api, calls = fake_api
    api.wakes = [{"messages": [{"sequence": 7}], "next_cursor": 7}]
    api.pages = [{"messages": [{"sequence": 6}, {"sequence": 7}],
                  "next_cursor": 7, "has_more": False}]

    coord._observe_loop(_Runtime(), "r", 5)

    kinds = [c[0] for c in calls]
    assert kinds[0] == "wait", f"observer polled before waiting: {kinds}"
    # One read per wake, not a read per tick.
    assert kinds.count("read") == 1, f"read_room called {kinds.count('read')}x"


def test_observer_sees_operator_traffic(fake_api):
    """exclude_self would filter the operator's own messages -- which is
    exactly the traffic an operator is watching for."""
    api, calls = fake_api
    api.wakes = []
    coord._observe_loop(_Runtime(), "r", 0)
    wait_kwargs = [kw for kind, kw in calls if kind == "wait"]
    assert wait_kwargs, "never waited"
    assert wait_kwargs[0]["exclude_self"] is False


def test_observer_catches_up_from_its_own_cursor_not_the_wake_edge(fake_api):
    """The wake edge can sit past messages this observer has not rendered."""
    api, calls = fake_api
    api.wakes = [{"messages": [{"sequence": 12}], "next_cursor": 12}]
    api.pages = [{"messages": [{"sequence": 11}, {"sequence": 12}],
                  "next_cursor": 12, "has_more": False}]

    coord._observe_loop(_Runtime(), "r", 10)

    reads = [kw for kind, kw in calls if kind == "read"]
    assert reads[0]["since_sequence"] == 10, (
        f"caught up from the wake edge, not the held cursor: {reads[0]}")


def test_an_expired_wake_window_re_arms_without_reading(fake_api):
    api, calls = fake_api
    api.wakes = [{"messages": [], "next_cursor": 3}]   # window expired, nothing
    coord._observe_loop(_Runtime(), "r", 3)
    assert [c[0] for c in calls] == ["wait", "wait"], [c[0] for c in calls]
    assert not any(kind == "read" for kind, _ in calls), (
        "an empty wake still triggered a catch-up read")
