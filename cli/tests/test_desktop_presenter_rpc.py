"""Protocol tests for the native desktop presenter owner."""

from __future__ import annotations

import io
import json
import sys
import types
from types import SimpleNamespace

from safeyolo import desktop_presenter_rpc


def test_daemon_keeps_one_presenter_owner_until_shutdown(monkeypatch):
    class PresentationError(RuntimeError):
        pass

    class Presenter:
        instances = []

        def __init__(self):
            self.calls = []
            self.closed = False
            self.instances.append(self)

        def present(self, agent_id):
            self.calls.append(agent_id)
            return SimpleNamespace(
                to_dict=lambda: {
                    "agent_id": agent_id,
                    "agent": "alice",
                    "url": "http://127.0.0.1:12345/vnc.html",
                    "unlock_code": "1234-5678",
                    "reused": bool(len(self.calls) > 1),
                }
            )

        def close_all(self):
            self.closed = True

    presenter_module = types.ModuleType("safeyolo.desktop_presenter")
    presenter_module.DesktopPresentationError = PresentationError
    presenter_module.DesktopPresenter = Presenter
    agents_module = types.ModuleType("safeyolo.agents_store")
    agents_module.get_or_mint_agent_id = lambda agent_id: agent_id
    monkeypatch.setitem(sys.modules, "safeyolo.desktop_presenter", presenter_module)
    monkeypatch.setitem(sys.modules, "safeyolo.agents_store", agents_module)

    output = io.StringIO()
    assert (
        desktop_presenter_rpc.daemon_main(
            io.StringIO(
                '{"agent_id":"alice"}\n'
                '{"agent_id":"alice"}\n'
                '{"shutdown":true}\n'
            ),
            output,
        )
        == 0
    )

    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    assert [response["reused"] for response in responses[:2]] == [False, True]
    assert responses[2] == {"status": "stopped"}
    assert len(Presenter.instances) == 1
    assert Presenter.instances[0].calls == ["alice", "alice"]
    assert Presenter.instances[0].closed
