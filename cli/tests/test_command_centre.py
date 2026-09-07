"""Command Centre host configuration and native macOS launch tests."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

from typer.testing import CliRunner

from safeyolo.commands.command_centre import command_centre_app
from safeyolo.config import load_config


def test_enable_and_disable_are_explicit_config_changes(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    runner = CliRunner()

    enabled = runner.invoke(command_centre_app, ["enable", "--events-port", "9191"])
    assert enabled.exit_code == 0, enabled.output
    assert "Restart SafeYolo" in enabled.output
    assert load_config()["command_centre"] == {
        "enabled": True,
        "events_port": 9191,
        "share": "local",
        "tailnet_admin_port": 9443,
        "tailnet_events_port": 9444,
    }

    disabled = runner.invoke(command_centre_app, ["disable"])
    assert disabled.exit_code == 0, disabled.output
    assert load_config()["command_centre"]["enabled"] is False


def test_enable_tailnet_records_explicit_transport(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    runner = CliRunner()

    enabled = runner.invoke(
        command_centre_app,
        [
            "enable",
            "--share",
            "tailnet",
            "--tailnet-admin-port",
            "10443",
            "--tailnet-events-port",
            "10444",
        ],
    )

    assert enabled.exit_code == 0, enabled.output
    assert "explicit Tailnet publication" in enabled.output
    assert load_config()["command_centre"] == {
        "enabled": True,
        "events_port": 9091,
        "share": "tailnet",
        "tailnet_admin_port": 10443,
        "tailnet_events_port": 10444,
    }

    state_path = tmp_path / "data" / "command-centre-tailnet-status.json"
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(
            {
                "state": "healthy",
                "admin_url": "https://dev.example.ts.net:10443/",
                "events_url": "wss://dev.example.ts.net:10444/admin/events",
            }
        )
    )
    status = runner.invoke(command_centre_app, ["status"])
    assert status.exit_code == 0, status.output
    assert "Tailnet publication: healthy" in status.output
    assert "https://dev.example.ts.net:10443/" in status.output
    assert "wss://dev.example.ts.net:10444/admin/events" in status.output


def test_run_opens_installed_native_macos_app(monkeypatch):
    monkeypatch.setattr("safeyolo.commands.command_centre.sys.platform", "darwin")
    with patch("safeyolo.commands.command_centre.subprocess.run", autospec=True) as run:
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        result = CliRunner().invoke(command_centre_app, ["run"])
    assert result.exit_code == 0, result.output
    run.assert_called_once_with(
        ["/usr/bin/open", "-b", "io.safeyolo.command-centre"],
        capture_output=True,
        text=True,
        check=False,
    )


def test_run_reports_missing_native_app(monkeypatch):
    monkeypatch.setattr("safeyolo.commands.command_centre.sys.platform", "darwin")
    with patch("safeyolo.commands.command_centre.subprocess.run", autospec=True) as run:
        run.return_value = subprocess.CompletedProcess([], 1, "", "Application not found")
        result = CliRunner().invoke(command_centre_app, ["run"])
    assert result.exit_code == 1
    assert "Install the native macOS app first" in result.output
    assert "Application not found" in result.output


def test_run_on_linux_explains_where_the_ui_runs(monkeypatch):
    monkeypatch.setattr("safeyolo.commands.command_centre.sys.platform", "linux")
    with patch("safeyolo.commands.command_centre.subprocess.run", autospec=True) as run:
        result = CliRunner().invoke(command_centre_app, ["run"])
    assert result.exit_code == 1
    assert "Run Command Centre on your Mac" in result.output
    run.assert_not_called()
