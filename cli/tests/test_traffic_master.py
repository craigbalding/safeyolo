"""Composition tests for the shared console and web master."""

import asyncio
from unittest.mock import patch

from mitmproxy import options

from safeyolo.traffic_master import TrafficMaster


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
