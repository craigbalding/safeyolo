"""Tests for typed, managed desktop presentation."""

from __future__ import annotations

from unittest.mock import create_autospec

import pytest

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

    presenter.close_all()
    assert preview.closed


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
