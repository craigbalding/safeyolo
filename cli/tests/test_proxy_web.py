"""Tests for persistent WebMITM Tailnet sharing."""

from __future__ import annotations

from unittest.mock import patch

import httpx
import yaml

from safeyolo.cli import app
from safeyolo.commands.proxy import _web_tailnet_runtime
from safeyolo.config import load_config
from safeyolo.proxy import sync_web_tailnet


def test_share_persists_for_next_start(cli_runner, tmp_config_dir):
    with (
        patch("safeyolo.commands.proxy.is_proxy_running", return_value=False, autospec=True,),
        patch(
            "safeyolo.commands.proxy.preflight_tailnet_serve",
            return_value="host.example.ts.net",
        autospec=True,
        ),
        patch(
            "safeyolo.commands.proxy._web_tailnet_runtime",
            return_value={"url": None, "state": "inactive", "enabled": True},
        autospec=True,
        ),
        patch("safeyolo.commands.proxy.write_event", autospec=True,) as write_event,
    ):
        result = cli_runner.invoke(app, ["proxy", "web", "share", "--tailnet", "--port", "8445"])

    assert result.exit_code == 0
    assert "applies on next SafeYolo start" in result.output
    assert "https://host.example.ts.net:8445/" in result.output
    config = yaml.safe_load((tmp_config_dir / "config.yaml").read_text())
    assert config["proxy"]["web_tailnet"] == {"enabled": True, "port": 8445}
    assert write_event.call_args.args[0] == "ops.web_tailnet_share_enabled"


def test_share_requires_explicit_boundary(cli_runner, tmp_config_dir):
    result = cli_runner.invoke(app, ["proxy", "web", "share"])

    assert result.exit_code == 2
    assert "--tailnet" in result.output


def test_share_collision_does_not_change_config(cli_runner, tmp_config_dir):
    from safeyolo.tailnet import TailnetServeError

    before = (tmp_config_dir / "config.yaml").read_text()
    with (
        patch("safeyolo.commands.proxy.is_proxy_running", return_value=False, autospec=True,),
        patch(
            "safeyolo.commands.proxy.preflight_tailnet_serve",
            side_effect=TailnetServeError("port 443 already has a mapping"),
        autospec=True,
        ),
    ):
        result = cli_runner.invoke(app, ["proxy", "web", "share", "--tailnet"])

    assert result.exit_code == 1
    assert "already has a mapping" in result.output
    assert (tmp_config_dir / "config.yaml").read_text() == before


def test_share_live_reconciles_running_proxy(cli_runner, tmp_config_dir):
    with (
        patch("safeyolo.commands.proxy.is_proxy_running", return_value=True, autospec=True,),
        patch(
            "safeyolo.commands.proxy.preflight_tailnet_serve",
            return_value="host.example.ts.net",
        autospec=True,
        ),
        patch(
            "safeyolo.commands.proxy.sync_web_tailnet",
            return_value=(True, {"state": "healthy"}),
        autospec=True,
        ) as reconcile,
        patch(
            "safeyolo.commands.proxy._web_tailnet_runtime",
            return_value={
                "url": "https://host.example.ts.net/",
                "state": "healthy",
                "enabled": True,
            },
        autospec=True,
        ),
        patch("safeyolo.commands.proxy.write_event", autospec=True,),
    ):
        result = cli_runner.invoke(app, ["proxy", "web", "share", "--tailnet"])

    assert result.exit_code == 0
    assert "applied to running proxy" in result.output
    reconcile.assert_called_once_with(True, 443, admin_port=9090)


def test_share_recovers_configured_but_degraded_mapping(cli_runner, tmp_config_dir):
    config_path = tmp_config_dir / "config.yaml"
    config = yaml.safe_load(config_path.read_text())
    config["proxy"]["web_tailnet"] = {"enabled": True, "port": 8445}
    config_path.write_text(yaml.safe_dump(config, sort_keys=False))

    with (
        patch("safeyolo.commands.proxy.is_proxy_running", return_value=True, autospec=True,),
        patch(
            "safeyolo.commands.proxy._web_tailnet_runtime",
            side_effect=[
                {"enabled": True, "state": "degraded", "url": None},
                {
                    "enabled": True,
                    "state": "healthy",
                    "url": "https://host.example.ts.net:8445/",
                },
            ],
        autospec=True,
        ),
        patch(
            "safeyolo.commands.proxy.preflight_tailnet_serve",
            return_value="host.example.ts.net",
        autospec=True,
        ) as preflight,
        patch(
            "safeyolo.commands.proxy.sync_web_tailnet",
            return_value=(True, {"state": "healthy"}),
        autospec=True,
        ) as reconcile,
        patch("safeyolo.commands.proxy.write_event", autospec=True,),
    ):
        result = cli_runner.invoke(
            app,
            ["proxy", "web", "share", "--tailnet", "--port", "8445"],
        )

    assert result.exit_code == 0
    assert "applied to running proxy" in result.output
    assert "already active" not in result.output
    assert preflight.call_args.kwargs["allow_target"] is None
    reconcile.assert_called_once_with(True, 8445, admin_port=9090)


def test_share_is_idempotent_only_when_exact_mapping_is_healthy(
    cli_runner, tmp_config_dir
):
    config_path = tmp_config_dir / "config.yaml"
    config = yaml.safe_load(config_path.read_text())
    config["proxy"]["web_tailnet"] = {"enabled": True, "port": 8445}
    config_path.write_text(yaml.safe_dump(config, sort_keys=False))

    with (
        patch("safeyolo.commands.proxy.is_proxy_running", return_value=True, autospec=True,),
        patch(
            "safeyolo.commands.proxy._web_tailnet_runtime",
            return_value={
                "enabled": True,
                "state": "healthy",
                "url": "https://host.example.ts.net:8445/",
            },
        autospec=True,
        ),
        patch(
            "safeyolo.commands.proxy.preflight_tailnet_serve",
            return_value="host.example.ts.net",
        autospec=True,
        ) as preflight,
        patch("safeyolo.commands.proxy.sync_web_tailnet", autospec=True,) as reconcile,
    ):
        result = cli_runner.invoke(
            app,
            ["proxy", "web", "share", "--tailnet", "--port", "8445"],
        )

    assert result.exit_code == 0
    assert "already active" in result.output
    assert preflight.call_args.kwargs["allow_target"] == "http://127.0.0.1:8081"
    reconcile.assert_not_called()


def test_failed_live_reconcile_rolls_back_config_and_live_state(
    cli_runner, tmp_config_dir
):
    before = load_config()
    with (
        patch("safeyolo.commands.proxy.is_proxy_running", return_value=True, autospec=True,),
        patch(
            "safeyolo.commands.proxy.preflight_tailnet_serve",
            return_value="host.example.ts.net",
        autospec=True,
        ),
        patch(
            "safeyolo.commands.proxy.sync_web_tailnet",
            side_effect=[
                (False, {"error": "serve denied"}),
                (True, {"state": "disabled"}),
            ],
        autospec=True,
        ) as reconcile,
        patch("safeyolo.commands.proxy.write_event", autospec=True,),
    ):
        result = cli_runner.invoke(app, ["proxy", "web", "share", "--tailnet"])

    assert result.exit_code == 1
    assert "previous configuration" in result.output
    assert "state restored: serve denied" in result.output
    assert load_config() == before
    assert reconcile.call_count == 2
    assert reconcile.call_args_list[0].args == (True, 443)
    assert reconcile.call_args_list[1].args == (False, 443)


def test_unshare_persists_without_resetting_other_serve_mappings(cli_runner, tmp_config_dir):
    config_path = tmp_config_dir / "config.yaml"
    config = yaml.safe_load(config_path.read_text())
    config["proxy"]["web_tailnet"] = {"enabled": True, "port": 8445}
    config_path.write_text(yaml.safe_dump(config, sort_keys=False))

    with (
        patch("safeyolo.commands.proxy.is_proxy_running", return_value=False, autospec=True,),
        patch("safeyolo.commands.proxy.run_tailscale_json", autospec=True,) as tailscale,
        patch("safeyolo.commands.proxy.write_event", autospec=True,),
    ):
        result = cli_runner.invoke(app, ["proxy", "web", "unshare"])

    assert result.exit_code == 0
    updated = yaml.safe_load(config_path.read_text())
    assert updated["proxy"]["web_tailnet"] == {"enabled": False, "port": 8445}
    tailscale.assert_not_called()


def test_unshare_live_reconciles_without_proxy_restart(cli_runner, tmp_config_dir):
    config_path = tmp_config_dir / "config.yaml"
    config = yaml.safe_load(config_path.read_text())
    config["proxy"]["web_tailnet"] = {"enabled": True, "port": 8445}
    config_path.write_text(yaml.safe_dump(config, sort_keys=False))

    with (
        patch("safeyolo.commands.proxy.is_proxy_running", return_value=True, autospec=True,),
        patch(
            "safeyolo.commands.proxy.sync_web_tailnet",
            return_value=(True, {"state": "disabled"}),
        autospec=True,
        ) as reconcile,
        patch("safeyolo.commands.proxy.write_event", autospec=True,),
    ):
        result = cli_runner.invoke(app, ["proxy", "web", "unshare"])

    assert result.exit_code == 0
    assert "applied to running proxy" in result.output
    reconcile.assert_called_once_with(False, 8445, admin_port=9090)


def test_sync_web_tailnet_uses_authenticated_operator_endpoint(tmp_config_dir):
    (tmp_config_dir / "data" / "admin_token").write_text("operator-token")
    response = httpx.Response(
        200,
        json={
            "status": "updated",
            "enabled": True,
            "port": 8446,
            "state": "healthy",
        },
    )
    with patch("httpx.put", return_value=response, autospec=True,) as put:
        ok, payload = sync_web_tailnet(True, 8446, admin_port=9191)

    assert ok is True
    assert payload["state"] == "healthy"
    put.assert_called_once_with(
        "http://127.0.0.1:9191/admin/proxy/web-tailnet",
        json={"enabled": True, "port": 8446},
        headers={"Authorization": "Bearer operator-token"},
        timeout=42.0,
    )


def test_runtime_status_requires_exact_target(tmp_config_dir):
    config = yaml.safe_load((tmp_config_dir / "config.yaml").read_text())
    config["proxy"]["web_tailnet"] = {"enabled": True, "port": 8445}
    status = {
        "TCP": {"8445": {"HTTPS": True}},
        "Web": {"host.example.ts.net:8445": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8081"}}}},
    }
    with (
        patch(
            "safeyolo.commands.proxy.tailnet_identity",
            return_value="host.example.ts.net",
        autospec=True,
        ),
        patch("safeyolo.commands.proxy.run_tailscale_json", return_value=status, autospec=True,),
    ):
        runtime = _web_tailnet_runtime(config)

    assert runtime["state"] == "healthy"
    assert runtime["url"] == "https://host.example.ts.net:8445/"


def test_open_uses_healthy_tailnet_url(cli_runner, tmp_config_dir):
    with (
        patch("safeyolo.commands.proxy.is_proxy_running", return_value=True, autospec=True,),
        patch(
            "safeyolo.commands.proxy._web_tailnet_runtime",
            return_value={
                "enabled": True,
                "state": "healthy",
                "url": "https://host.example.ts.net:8445/",
            },
        autospec=True,
        ),
        patch("safeyolo.commands.proxy.webbrowser.open", autospec=True,) as browser_open,
    ):
        result = cli_runner.invoke(app, ["proxy", "web", "open"])

    assert result.exit_code == 0
    browser_open.assert_called_once_with("https://host.example.ts.net:8445/")
