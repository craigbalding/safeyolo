"""Composition tests for the shared console and web master."""

import asyncio
import errno
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import create_autospec, patch

import pytest
from argon2 import PasswordHasher
from mitmproxy import flowfilter, options
from mitmproxy.test import tflow
from tornado.httpserver import HTTPServer

from safeyolo.tailnet import TailnetServeSession
from safeyolo.traffic_master import (
    _SCOPE_SCRIPT,
    _SCOPE_STYLE,
    SafeYoloStatusBar,
    TrafficMaster,
    WebFrontend,
    WebTailnetShare,
    _initial_proxy_modes,
    _scope_toolbar,
)


def _tailnet_session(url: str, exposed_port: int, *, pid: int):
    process = SimpleNamespace(pid=pid, poll=lambda: None)
    real = TailnetServeSession(
        process=process,
        dns_name="host.example.ts.net",
        exposed_port=exposed_port,
        target="http://127.0.0.1:8081",
    )
    session = create_autospec(real, spec_set=True)
    session.url.return_value = url
    session.target = real.target
    session.process.pid = pid
    session.process.poll.return_value = None
    return session


def make_master() -> TrafficMaster:
    async def construct() -> TrafficMaster:
        return TrafficMaster(options.Options())

    return asyncio.run(construct())


def test_initial_proxy_options_accepts_only_a_json_string_list(monkeypatch):
    modes = ["unix:/tmp/10.200.0.1_alice/proxy.sock"]
    monkeypatch.setenv("SAFEYOLO_INITIAL_MODES", '["unix:/tmp/10.200.0.1_alice/proxy.sock"]')
    assert _initial_proxy_modes() == modes

    monkeypatch.setenv("SAFEYOLO_INITIAL_MODES", '{"mode": []}')
    with pytest.raises(ValueError, match="JSON list of strings"):
        _initial_proxy_modes()


def test_hybrid_master_has_one_canonical_view_and_proxyserver(monkeypatch):
    monkeypatch.delenv("SAFEYOLO_WEB_PASSWORD_FILE", raising=False)
    master = make_master()
    chain = list(master.addons.chain)

    assert sum(addon.__class__.__name__ == "Proxyserver" for addon in chain) == 1
    assert sum(addon is master.view for addon in chain) == 1
    assert master.addons.get("safeyolo-web-frontend") is not None
    assert master.addons.get("safeyolo-web-tailnet-share") is not None
    assert master.web_app.master is master


def test_production_addons_keep_script_hook_order_without_watchers(monkeypatch):
    """Direct registration preserves hook order without Script wrappers."""
    from mitmproxy.addonmanager import traverse
    from mitmproxy.addons.script import Script

    monkeypatch.delenv("SAFEYOLO_WEB_PASSWORD_FILE", raising=False)
    master = make_master()
    chain = list(master.addons.chain)
    script_loader = master.addons.get("scriptloader")
    production = master.addons.get("safeyolo-production-addons")

    assert production is not None
    assert chain[chain.index(script_loader) + 1] is production
    assert master.options.scripts == []
    assert master.addons.get("agent-api") in production.addons
    assert not any(isinstance(addon, Script) for addon in traverse(chain))


def test_agent_api_and_coord_dependency_change_only_as_one_process_generation(
    tmp_path,
    monkeypatch,
):
    """The selected checkout changes only as one process generation."""
    project_root = Path(__file__).resolve().parents[2]
    copied_root = tmp_path / "repo"
    copied_cli_src = copied_root / "cli" / "src"
    copied_cli_src.mkdir(parents=True)
    shutil.copytree(
        project_root / "cli" / "src" / "safeyolo",
        copied_cli_src / "safeyolo",
    )
    shutil.copytree(project_root / "pdp", copied_root / "pdp")

    agent_api_path = copied_cli_src / "safeyolo" / "mitm_addons" / "agent_api.py"
    coord_api_path = copied_cli_src / "safeyolo" / "coord" / "api.py"

    def set_generation(path: Path, generation: str) -> None:
        source = path.read_text()
        marker = "\nISSUE_397_GENERATION = "
        if marker in source:
            source = source[: source.index(marker)]
        path.write_text(f'{source}{marker}{generation!r}\n')

    set_generation(agent_api_path, "generation-one")
    set_generation(coord_api_path, "generation-one")

    probe = """
import json
import sys
from pathlib import Path

from safeyolo.mitm_addons import ProductionAddons

ProductionAddons()
from safeyolo.coord import api as coord_api
from safeyolo.mitm_addons import agent_api

def snapshot():
    return {
        "agent_api": agent_api.ISSUE_397_GENERATION,
        "coord_api": coord_api.ISSUE_397_GENERATION,
        "agent_api_file": str(Path(agent_api.__file__).resolve()),
        "coord_api_file": str(Path(coord_api.__file__).resolve()),
    }

print(json.dumps(snapshot()), flush=True)
for _ in sys.stdin:
    print(json.dumps(snapshot()), flush=True)
"""
    from safeyolo.proxy import _child_pythonpath, _find_addons_dir

    monkeypatch.setenv("SAFEYOLO_ADDONS_DIR", str(agent_api_path.parent))
    selected_addons = _find_addons_dir()
    assert selected_addons == agent_api_path.parent

    env = os.environ.copy()
    env["PYTHONPATH"] = _child_pythonpath(
        selected_addons,
        copied_root / "pdp",
        env.get("PYTHONPATH", ""),
    )

    def start_probe() -> subprocess.Popen[str]:
        return subprocess.Popen(
            [sys.executable, "-c", probe],
            cwd=copied_root,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    process = start_probe()
    assert process.stdout is not None
    assert process.stdin is not None
    first = json.loads(process.stdout.readline())

    set_generation(agent_api_path, "generation-two-longer")
    set_generation(coord_api_path, "generation-two-longer")
    process.stdin.write("source changed\n")
    process.stdin.flush()
    after_edit = json.loads(process.stdout.readline())
    process.stdin.close()
    assert process.wait(timeout=10) == 0

    restarted = start_probe()
    assert restarted.stdout is not None
    assert restarted.stdin is not None
    after_restart = json.loads(restarted.stdout.readline())
    restarted.stdin.close()
    assert restarted.wait(timeout=10) == 0

    assert first["agent_api"] == "generation-one"
    assert first["coord_api"] == "generation-one"
    assert first["agent_api_file"] == str(agent_api_path.resolve())
    assert first["coord_api_file"] == str(coord_api_path.resolve())
    assert after_edit == first
    assert after_restart["agent_api"] == "generation-two-longer"
    assert after_restart["coord_api"] == "generation-two-longer"
    assert after_restart["agent_api_file"] == str(agent_api_path.resolve())
    assert after_restart["coord_api_file"] == str(coord_api_path.resolve())


def test_live_traffic_defaults_show_and_follow_newest_flows(monkeypatch):
    monkeypatch.delenv("SAFEYOLO_WEB_PASSWORD_FILE", raising=False)

    master = make_master()

    assert master.options.view_order == "time"
    assert master.options.view_order_reversed is True
    assert master.options.console_focus_follow is True


def test_web_flow_columns_follow_native_chronological_order(monkeypatch):
    monkeypatch.delenv("SAFEYOLO_WEB_PASSWORD_FILE", raising=False)

    master = make_master()

    assert master.options.web_columns == [
        "timestamp",
        "tls",
        "icon",
        "method",
        "version",
        "path",
        "status",
        "size",
        "time",
    ]


def test_web_password_is_hashed_in_option_state(tmp_path, monkeypatch):
    password_file = tmp_path / "admin_token"
    password_file.write_text("operator-secret")
    monkeypatch.setenv("SAFEYOLO_WEB_PASSWORD_FILE", str(password_file))

    master = make_master()

    assert master.options.web_password.startswith("$argon2")
    assert "operator-secret" not in master.options.web_password
    assert PasswordHasher().verify(master.options.web_password, "operator-secret")


def test_normal_console_exit_prompt_does_not_shutdown_data_plane(monkeypatch):
    monkeypatch.delenv("SAFEYOLO_WEB_PASSWORD_FILE", raising=False)
    master = make_master()

    assert master.keymap.get("global", "Q") is None

    with (
        patch.object(master, "shutdown", autospec=True,) as shutdown,
        patch("safeyolo.traffic_master.console_signals.status_message.send", autospec=True,) as status,
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
    server = create_autospec(HTTPServer, instance=True, spec_set=True)
    server.listen.side_effect = OSError(errno.EADDRINUSE, "Address already in use")

    with (
        patch("safeyolo.traffic_master.tornado.httpserver.HTTPServer", return_value=server, autospec=True,),
        patch("safeyolo.traffic_master.write_event", autospec=True,) as write_event,
        pytest.raises(OSError, match="127.0.0.1:8081"),
    ):
        asyncio.run(frontend.running())

    assert write_event.call_args.args[0] == "ops.proxy_start_failed"
    assert "127.0.0.1:8081" in write_event.call_args.kwargs["summary"]
    assert write_event.call_args.kwargs["details"]["port"] == 8081


def test_web_tailnet_share_owns_foreground_session(tmp_path, monkeypatch):
    state_path = tmp_path / "web-tailnet-status.json"
    monkeypatch.setenv("SAFEYOLO_WEB_TAILNET_ENABLED", "1")
    monkeypatch.setenv("SAFEYOLO_WEB_TAILNET_PORT", "8445")
    monkeypatch.setenv("SAFEYOLO_WEB_TAILNET_STATUS_FILE", str(state_path))
    master = SimpleNamespace(
        options=SimpleNamespace(web_host="127.0.0.1", web_port=8081)
    )
    session = _tailnet_session("https://host.example.ts.net:8445/", 8445, pid=1234)
    share = WebTailnetShare(master)

    with (
        patch("safeyolo.traffic_master.start_tailnet_serve", return_value=session, autospec=True,) as start,
        patch.object(share, "_watch_session", autospec=True,) as watch,
        patch("safeyolo.traffic_master.write_event", autospec=True,) as write_event,
    ):
        asyncio.run(share.running())
        assert '"state": "healthy"' in state_path.read_text()
        asyncio.run(share.done())

    start.assert_called_once_with(8081, 8445)
    watch.assert_called_once_with(session, "https://host.example.ts.net:8445/", 8445)
    session.close.assert_called_once_with()
    events = [call.args[0] for call in write_event.call_args_list]
    assert events == [
        "ops.web_tailnet_share_started",
        "ops.web_tailnet_share_stopped",
    ]
    assert '"state": "disabled"' in state_path.read_text()


def test_web_tailnet_share_failure_blocks_proxy_readiness(tmp_path, monkeypatch):
    state_path = tmp_path / "web-tailnet-status.json"
    monkeypatch.setenv("SAFEYOLO_WEB_TAILNET_ENABLED", "1")
    monkeypatch.setenv("SAFEYOLO_WEB_TAILNET_PORT", "443")
    monkeypatch.setenv("SAFEYOLO_WEB_TAILNET_STATUS_FILE", str(state_path))
    share = WebTailnetShare(
        SimpleNamespace(
            options=SimpleNamespace(web_host="127.0.0.1", web_port=8081)
        )
    )

    with (
        patch(
            "safeyolo.traffic_master.start_tailnet_serve",
            side_effect=RuntimeError("port already mapped"),
        autospec=True,
        ),
        patch("safeyolo.traffic_master.write_event", autospec=True,) as write_event,
        pytest.raises(RuntimeError, match="port already mapped"),
    ):
        asyncio.run(share.running())

    events = [call.args[0] for call in write_event.call_args_list]
    assert events == [
        "ops.web_tailnet_share_failed",
        "ops.proxy_start_failed",
    ]
    assert '"state": "error"' in state_path.read_text()


def test_web_tailnet_live_port_change_preserves_old_share_until_ready(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SAFEYOLO_WEB_TAILNET_ENABLED", "1")
    monkeypatch.setenv("SAFEYOLO_WEB_TAILNET_PORT", "8445")
    monkeypatch.setenv(
        "SAFEYOLO_WEB_TAILNET_STATUS_FILE",
        str(tmp_path / "web-tailnet-status.json"),
    )
    share = WebTailnetShare(
        SimpleNamespace(
            options=SimpleNamespace(web_host="127.0.0.1", web_port=8081)
        )
    )
    old = _tailnet_session("https://host.example.ts.net:8445/", 8445, pid=1234)
    replacement = _tailnet_session(
        "https://host.example.ts.net:8446/", 8446, pid=4321
    )
    share.session = old

    with (
        patch(
            "safeyolo.traffic_master.start_tailnet_serve",
            return_value=replacement,
        autospec=True,
        ) as start,
        patch.object(share, "_watch_session", autospec=True,),
        patch("safeyolo.traffic_master.write_event", autospec=True,),
    ):
        result = asyncio.run(share.reconcile(True, 8446))

    start.assert_called_once_with(8081, 8446)
    old.close.assert_called_once_with()
    assert share.session is replacement
    assert result["state"] == "healthy"
    assert result["port"] == 8446


def test_web_tailnet_live_failure_keeps_existing_healthy_share(
    tmp_path, monkeypatch
):
    state_path = tmp_path / "web-tailnet-status.json"
    monkeypatch.setenv("SAFEYOLO_WEB_TAILNET_ENABLED", "1")
    monkeypatch.setenv("SAFEYOLO_WEB_TAILNET_PORT", "8445")
    monkeypatch.setenv("SAFEYOLO_WEB_TAILNET_STATUS_FILE", str(state_path))
    share = WebTailnetShare(
        SimpleNamespace(
            options=SimpleNamespace(web_host="127.0.0.1", web_port=8081)
        )
    )
    old = _tailnet_session("https://host.example.ts.net:8445/", 8445, pid=1234)
    share.session = old

    with (
        patch(
            "safeyolo.traffic_master.start_tailnet_serve",
            side_effect=RuntimeError("serve denied"),
        autospec=True,
        ),
        patch("safeyolo.traffic_master.write_event", autospec=True,),
        pytest.raises(RuntimeError, match="serve denied"),
    ):
        asyncio.run(share.reconcile(True, 8446))

    assert share.session is old
    old.close.assert_not_called()
    assert '"state": "healthy"' in state_path.read_text()
    assert '"port": 8445' in state_path.read_text()


def test_native_scope_keys_do_not_replace_stock_bindings(monkeypatch):
    monkeypatch.delenv("SAFEYOLO_WEB_PASSWORD_FILE", raising=False)
    master = make_master()

    assert master.keymap.get("global", "q").command == "console.view.pop"
    assert master.keymap.get("global", "]").command == "safeyolo.traffic.agent.next"
    assert (
        master.keymap.get("global", "}").command
        == "safeyolo.traffic.test.choose"
    )
    assert master.keymap.get("global", "ctrl 0").command == "safeyolo.traffic.scope.clear"


def test_filter_key_edits_only_the_user_owned_filter(monkeypatch):
    monkeypatch.delenv("SAFEYOLO_WEB_PASSWORD_FILE", raising=False)
    master = make_master()

    assert master.keymap.get("flowlist", "f").command == "safeyolo.traffic.filter.edit"


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
    bar.master = SimpleNamespace(
        addons=SimpleNamespace(get=lambda _name: scope),
        options=SimpleNamespace(
            mode=["unix:/long/private/socket.sock"],
            scripts=["one.py", "two.py"],
            stream_large_bodies="10m",
        ),
    )

    with (
        patch("safeyolo.traffic_master.socket.gethostname", return_value="workstation", autospec=True,),
        patch(
            "safeyolo.traffic_master.statusbar.StatusBar.get_status",
            return_value=[
                "[stock]",
                "[unix:/long/private/socket.sock]",
                "[scripts:2]",
                "[10m]",
            ],
        autospec=True,
        ),
    ):
        result = bar.get_status()

    assert result == [
        ("heading_key", "[SafeYolo · alice · FLOW-05 · forge · blocked]"),
        "[stock]",
        "[stream≥10 MiB]",
    ]


def test_status_bar_extracts_stream_threshold_from_combined_stock_modes():
    scope = SimpleNamespace(
        get_stats=lambda: {
            "agent": None,
            "unattributed": False,
            "test_id": None,
            "intent": None,
            "role": None,
            "expect": None,
        }
    )
    bar = SafeYoloStatusBar.__new__(SafeYoloStatusBar)
    bar.master = SimpleNamespace(
        addons=SimpleNamespace(get=lambda _name: scope),
        options=SimpleNamespace(
            mode=["regular"], scripts=[], stream_large_bodies="1g"
        ),
    )

    with patch(
        "safeyolo.traffic_master.statusbar.StatusBar.get_status",
        return_value=["[anticache:1g]"],
    autospec=True,
    ):
        result = bar.get_status()

    assert result == [
        ("heading_key", "[SafeYolo · all agents]"),
        "[anticache]",
        "[stream≥1 GiB]",
    ]


def test_status_bar_redraw_omits_raw_listener_addresses():
    bar = SafeYoloStatusBar.__new__(SafeYoloStatusBar)
    bar.ib = SimpleNamespace(_w=None)
    bar.master = SimpleNamespace(
        commands=SimpleNamespace(
            execute=lambda command: {
                "view.properties.length": 3,
                "view.properties.marked": False,
            }[command]
        ),
        options=SimpleNamespace(view_order_reversed=False),
        view=SimpleNamespace(focus=SimpleNamespace(index=0)),
    )
    bar.get_status = lambda: [("heading_key", "[SafeYolo · alice]")]  # type: ignore[method-assign]

    bar.redraw()

    rendered = bar.ib._w.original_widget.text
    assert "SafeYolo · alice" in rendered
    assert "/sockets/" not in rendered


def test_web_scope_has_explicit_modes_and_responsive_pinned_summary():
    toolbar = _scope_toolbar("workstation")

    assert "SafeYolo Traffic — workstation" in toolbar
    assert "Pinned: all agents · no test context" in toolbar
    assert 'aria-label="Pinned agent"' in toolbar
    assert "Unattributed traffic" in _SCOPE_SCRIPT
    assert "All agents" in _SCOPE_SCRIPT
    assert "No restriction" in _SCOPE_SCRIPT
    assert "Search preserved" in _SCOPE_SCRIPT
    assert "response.status === 403" in _SCOPE_SCRIPT
    assert "window.location.assign('/')" in _SCOPE_SCRIPT
    assert "<header>" not in toolbar
    assert 'class="safeyolo-scope-heading"' in toolbar
    assert "background:#fff" in _SCOPE_STYLE
    assert "border-bottom:1px solid #a6a6a6" in _SCOPE_STYLE
    assert "border:1px solid #ccc" in _SCOPE_STYLE
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

    with patch("safeyolo.traffic_master.app.ClientConnection.broadcast_flow", autospec=True,) as broadcast:
        master.view.add([matching, hidden])

    broadcast.assert_called_once_with("flows/add", matching)
