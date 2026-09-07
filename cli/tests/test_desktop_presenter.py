"""Tests for typed, managed desktop presentation."""

from __future__ import annotations

from unittest.mock import create_autospec

import pytest

from safeyolo.agents_store import (
    reserve_agent_tailnet_port_change,
    restore_agent_tailnet_port,
)
from safeyolo.desktop_presenter import DesktopPresentationError, DesktopPresenter
from safeyolo.preview import start_managed_preview
from safeyolo.vm import stage_guest_desktop_launcher


class FakePlatform:
    def __init__(self, *, running: bool = True, exit_code: int = 0) -> None:
        self.running = running
        self.exit_code = exit_code
        self.commands = []

    def is_sandbox_running(self, name: str) -> bool:
        return self.running

    def exec_in_sandbox(self, name, command, *, user, interactive):
        self.commands.append((name, command, user, interactive))
        return self.exit_code


class FakePreview:
    url = "http://127.0.0.1:12345/vnc.html"
    unlock_code = "1234-5678"
    is_running = True

    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True

    def issue_unlock_code(self) -> str:
        self.unlock_code = "8765-4321"
        return self.unlock_code


def test_present_starts_desktop_once_and_reuses_preview(monkeypatch):
    monkeypatch.delenv("SAFEYOLO_COMMAND_CENTRE_SHARE", raising=False)
    platform = FakePlatform()
    preview = FakePreview()
    staged = create_autospec(stage_guest_desktop_launcher, spec_set=True)
    start_preview = create_autospec(start_managed_preview, spec_set=True, return_value=preview)
    monkeypatch.setattr(
        "safeyolo.desktop_presenter.get_agent_by_id",
        lambda agent_id: ("forge", {"agent_id": agent_id}),
    )
    monkeypatch.setattr("safeyolo.desktop_presenter.get_platform", lambda: platform)
    monkeypatch.setattr("safeyolo.desktop_presenter.get_desktop_size", lambda: "1280x800")
    monkeypatch.setattr(
        "safeyolo.desktop_presenter.resolve_vnc_geometry",
        lambda size: (size, None),
    )
    monkeypatch.setattr("safeyolo.desktop_presenter.stage_guest_desktop_launcher", staged)
    monkeypatch.setattr("safeyolo.desktop_presenter.start_managed_preview", start_preview)
    presenter = DesktopPresenter()

    first = presenter.present("ag-forge")
    second = presenter.present("ag-forge")

    assert first.reused is False
    assert second.reused is True
    assert first.url == "http://127.0.0.1:12345/vnc.html"
    assert first.unlock_code == "1234-5678"
    assert second.unlock_code == "8765-4321"
    assert platform.commands == [
        (
            "forge",
            "SAFEYOLO_PREVIEW_MANAGED=1 /safeyolo/guest-desktop start 1280x800",
            "agent",
            False,
        )
    ]
    staged.assert_called_once_with("forge", preferred_size="1280x800")
    start_preview.assert_called_once()
    assert start_preview.call_args.args[0].tailnet_port is None

    presenter.close_all()
    assert preview.closed


def test_present_publishes_preview_to_tailnet_for_remote_command_centre(monkeypatch):
    monkeypatch.setenv("SAFEYOLO_COMMAND_CENTRE_SHARE", "tailnet")
    platform = FakePlatform()
    preview = FakePreview()
    preview.url = "https://host.example.ts.net:8443/vnc.html"
    reserve = create_autospec(
        reserve_agent_tailnet_port_change,
        spec_set=True,
        return_value=(8443, None),
    )
    start_preview = create_autospec(
        start_managed_preview,
        spec_set=True,
        return_value=preview,
    )
    monkeypatch.setattr(
        "safeyolo.desktop_presenter.get_agent_by_id",
        lambda agent_id: ("forge", {"agent_id": agent_id}),
    )
    monkeypatch.setattr("safeyolo.desktop_presenter.get_platform", lambda: platform)
    monkeypatch.setattr("safeyolo.desktop_presenter.get_desktop_size", lambda: "1280x800")
    monkeypatch.setattr(
        "safeyolo.desktop_presenter.resolve_vnc_geometry",
        lambda size: (size, None),
    )
    monkeypatch.setattr(
        "safeyolo.desktop_presenter.stage_guest_desktop_launcher",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "safeyolo.desktop_presenter.reserve_agent_tailnet_port_change",
        reserve,
    )
    monkeypatch.setattr("safeyolo.desktop_presenter.start_managed_preview", start_preview)

    result = DesktopPresenter().present("ag-forge")

    assert result.url == "https://host.example.ts.net:8443/vnc.html"
    reserve.assert_called_once_with("forge")
    assert start_preview.call_args.args[0].tailnet_port == 8443


def test_present_rolls_back_new_tailnet_port_when_preview_start_fails(monkeypatch):
    monkeypatch.setenv("SAFEYOLO_COMMAND_CENTRE_SHARE", "tailnet")
    platform = FakePlatform(exit_code=1)
    restore = create_autospec(
        restore_agent_tailnet_port,
        spec_set=True,
    )
    monkeypatch.setattr(
        "safeyolo.desktop_presenter.get_agent_by_id",
        lambda agent_id: ("forge", {"agent_id": agent_id}),
    )
    monkeypatch.setattr("safeyolo.desktop_presenter.get_platform", lambda: platform)
    monkeypatch.setattr("safeyolo.desktop_presenter.get_desktop_size", lambda: "1280x800")
    monkeypatch.setattr(
        "safeyolo.desktop_presenter.resolve_vnc_geometry",
        lambda size: (size, None),
    )
    monkeypatch.setattr(
        "safeyolo.desktop_presenter.stage_guest_desktop_launcher",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "safeyolo.desktop_presenter.reserve_agent_tailnet_port_change",
        lambda _agent: (8443, None),
    )
    monkeypatch.setattr(
        "safeyolo.desktop_presenter.restore_agent_tailnet_port",
        restore,
    )

    with pytest.raises(DesktopPresentationError, match="failed to start"):
        DesktopPresenter().present("ag-forge")

    restore.assert_called_once_with("forge", 8443, None)


def test_present_requires_configured_running_agent(monkeypatch):
    presenter = DesktopPresenter()
    monkeypatch.setattr("safeyolo.desktop_presenter.get_agent_by_id", lambda _id: None)
    with pytest.raises(DesktopPresentationError, match="Agent not found"):
        presenter.present("ag-missing")

    monkeypatch.setattr(
        "safeyolo.desktop_presenter.get_agent_by_id",
        lambda agent_id: ("forge", {"agent_id": agent_id}),
    )
    monkeypatch.setattr(
        "safeyolo.desktop_presenter.get_platform",
        lambda: FakePlatform(running=False),
    )
    with pytest.raises(DesktopPresentationError, match="not running"):
        presenter.present("ag-forge")
