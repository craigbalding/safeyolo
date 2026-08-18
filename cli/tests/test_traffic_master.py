"""Composition tests for the shared console and web master."""

import asyncio
import errno
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from mitmproxy import flowfilter, options
from mitmproxy.test import tflow

from safeyolo.traffic_master import (
    _SCOPE_SCRIPT,
    _SCOPE_STYLE,
    SafeYoloStatusBar,
    TrafficMaster,
    WebFrontend,
    _scope_toolbar,
)


def make_master() -> TrafficMaster:
    async def construct() -> TrafficMaster:
        return TrafficMaster(options.Options())

    return asyncio.run(construct())


def test_hybrid_master_has_one_canonical_view_and_proxyserver(monkeypatch):
    monkeypatch.delenv("SAFEYOLO_WEB_PASSWORD_FILE", raising=False)
    master = make_master()
    chain = list(master.addons.chain)

    assert sum(addon.__class__.__name__ == "Proxyserver" for addon in chain) == 1
    assert sum(addon is master.view for addon in chain) == 1
    assert master.addons.get("safeyolo-web-frontend") is not None
    assert master.web_app.master is master


def test_normal_console_exit_prompt_does_not_shutdown_data_plane(monkeypatch):
    monkeypatch.delenv("SAFEYOLO_WEB_PASSWORD_FILE", raising=False)
    master = make_master()

    assert master.keymap.get("global", "Q") is None

    with (
        patch.object(master, "shutdown") as shutdown,
        patch("safeyolo.traffic_master.console_signals.status_message.send") as status,
    ):
        master.prompt_for_exit()

    shutdown.assert_not_called()
    assert "safeyolo stop" in status.call_args.kwargs["message"]


def test_web_bind_failure_is_written_at_source_to_structured_event_log():
    master = SimpleNamespace(
        web_app=object(),
        options=SimpleNamespace(web_host="127.0.0.1", web_port=8081),
    )
    frontend = WebFrontend.__new__(WebFrontend)
    frontend.master = master
    frontend.server = None
    server = MagicMock()
    server.listen.side_effect = OSError(errno.EADDRINUSE, "Address already in use")

    with (
        patch("safeyolo.traffic_master.tornado.httpserver.HTTPServer", return_value=server),
        patch("safeyolo.traffic_master.write_event") as write_event,
        pytest.raises(OSError, match="127.0.0.1:8081"),
    ):
        asyncio.run(frontend.running())

    assert write_event.call_args.args[0] == "ops.proxy_start_failed"
    assert "127.0.0.1:8081" in write_event.call_args.kwargs["summary"]
    assert write_event.call_args.kwargs["details"]["port"] == 8081


def test_native_scope_keys_do_not_replace_stock_bindings(monkeypatch):
    monkeypatch.delenv("SAFEYOLO_WEB_PASSWORD_FILE", raising=False)
    master = make_master()

    assert master.keymap.get("global", "q").command == "console.view.pop"
    assert master.keymap.get("global", "]").command == "safeyolo.traffic.agent.next"
    assert "safeyolo.traffic.test.options" in master.keymap.get("global", "}").command
    assert master.keymap.get("global", "ctrl 0").command == "safeyolo.traffic.scope.clear"


def test_status_bar_leads_with_host_and_pinned_evidence_scope():
    scope = SimpleNamespace(
        get_stats=lambda: {
            "agent": "alice",
            "unattributed": False,
            "test_id": "FLOW-05",
            "intent": "forge",
            "role": None,
            "expect": "blocked",
        }
    )
    bar = SafeYoloStatusBar.__new__(SafeYoloStatusBar)
    bar.master = SimpleNamespace(addons=SimpleNamespace(get=lambda _name: scope))

    with (
        patch("safeyolo.traffic_master.socket.gethostname", return_value="workstation"),
        patch(
            "safeyolo.traffic_master.statusbar.StatusBar.get_status",
            return_value=["[stock]"],
        ),
    ):
        result = bar.get_status()

    assert result == [
        ("heading_key", "[SafeYolo workstation · alice · FLOW-05 · forge · blocked]"),
        "[stock]",
    ]


def test_web_scope_has_explicit_modes_and_responsive_pinned_summary():
    toolbar = _scope_toolbar("workstation")

    assert "SafeYolo Traffic — workstation" in toolbar
    assert "Pinned: all agents · no test context" in toolbar
    assert 'aria-label="Pinned agent"' in toolbar
    assert "Unattributed traffic" in _SCOPE_SCRIPT
    assert "All agents" in _SCOPE_SCRIPT
    assert "No restriction" in _SCOPE_SCRIPT
    assert "Search preserved" in _SCOPE_SCRIPT
    assert "@media (max-width:600px)" in _SCOPE_STYLE
    assert "flex-wrap:wrap" in _SCOPE_STYLE


def test_websocket_broadcasts_only_flows_in_composed_live_view(monkeypatch):
    monkeypatch.delenv("SAFEYOLO_WEB_PASSWORD_FILE", raising=False)
    master = make_master()
    matching = tflow.tflow(resp=True)
    matching.metadata["agent"] = "alice"
    hidden = tflow.tflow(resp=True)
    hidden.metadata["agent"] = "bob"
    master.view.filter = flowfilter.parse('~meta "^agent: alice$" & (~m GET)')

    with patch("safeyolo.traffic_master.app.ClientConnection.broadcast_flow") as broadcast:
        master.view.add([matching, hidden])

    broadcast.assert_called_once_with("flows/add", matching)
