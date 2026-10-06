"""Tests for retained tmux status and agent-window integration."""

import subprocess
from unittest.mock import patch

from typer.testing import CliRunner

from safeyolo.cli import app
from safeyolo.commands.tmux import (
    TMUX_CONFIG_SNIPPET,
    associate_agent_pane,
    rename_window_for_agent,
)


def completed(args, *, stdout="", returncode=0):
    return subprocess.CompletedProcess(args=args, returncode=returncode, stdout=stdout, stderr="")


def test_agent_pane_association_is_noop_outside_tmux(monkeypatch):
    monkeypatch.delenv("TMUX", raising=False)
    monkeypatch.delenv("TMUX_PANE", raising=False)

    with patch("safeyolo.commands.tmux.tmux_cmd", autospec=True,) as command:
        assert associate_agent_pane("alice") is False

    command.assert_not_called()


def test_agent_pane_association_uses_pane_local_option(monkeypatch):
    monkeypatch.setenv("TMUX", "/tmp/tmux/default,1,0")
    monkeypatch.setenv("TMUX_PANE", "%7")

    with patch("safeyolo.commands.tmux.tmux_cmd", autospec=True,) as command:
        assert associate_agent_pane("alice") is True

    command.assert_called_once_with(
        ["set-option", "-p", "-t", "%7", "@safeyolo-agent", "alice"]
    )


def test_tmux_entries_and_configuration_retire_the_python_traffic_ui():
    for command in ("traffic", "return-to-agent"):
        result = CliRunner().invoke(app, ["tmux", command])
        assert result.exit_code == 2
        assert "No such command" in result.output
        assert f"safeyolo tmux {command}" not in TMUX_CONFIG_SNIPPET
    assert 'bind-key S display-popup -E "safeyolo watch"' in TMUX_CONFIG_SNIPPET


# ---------------------------------------------------------------------------
# rename_window_for_agent: ownership rule + failure modes (issue #330)
# ---------------------------------------------------------------------------


def _rename_recorder(state):
    """Build a tmux_cmd fake that answers from `state` and records calls."""
    calls: list[list[str]] = []

    def cmd(args, check=True):
        calls.append(list(args))
        if args[0] == "show-options" and args[-1] == "automatic-rename":
            return completed(args, stdout=state.get("automatic_rename", "") + "\n")
        if args[0] == "show-options" and args[-1] == "@safeyolo-window-name":
            return completed(args, stdout=state.get("marker", "") + "\n")
        if args[0] == "display-message" and args[-1] == "#{window_name}":
            return completed(args, stdout=state.get("window_name", "") + "\n")
        return completed(args)

    return cmd, calls


def _rename_calls(calls):
    return [c for c in calls if c and c[0] == "rename-window"]


def _marker_writes(calls):
    return [c for c in calls if c[:1] == ["set-option"] and "@safeyolo-window-name" in c]


def test_rename_is_noop_outside_tmux(monkeypatch):
    monkeypatch.delenv("TMUX", raising=False)
    monkeypatch.delenv("TMUX_PANE", raising=False)

    with patch("safeyolo.commands.tmux.tmux_cmd", autospec=True,) as command:
        assert rename_window_for_agent("alice") is False

    command.assert_not_called()


def test_rename_when_automatic_rename_local_unset(monkeypatch):
    monkeypatch.setenv("TMUX", "/tmp/tmux/default,1,0")
    monkeypatch.setenv("TMUX_PANE", "%3")
    cmd, calls = _rename_recorder({"automatic_rename": ""})

    with patch("safeyolo.commands.tmux.tmux_cmd", side_effect=cmd, autospec=True,):
        assert rename_window_for_agent("alice") is True

    assert _rename_calls(calls) == [["rename-window", "-t", "%3", "alice"]]
    assert _marker_writes(calls) == [
        ["set-option", "-w", "-t", "%3", "@safeyolo-window-name", "alice"]
    ]


def test_rename_when_automatic_rename_local_on(monkeypatch):
    monkeypatch.setenv("TMUX", "/tmp/tmux/default,1,0")
    monkeypatch.setenv("TMUX_PANE", "%3")
    cmd, calls = _rename_recorder({"automatic_rename": "on"})

    with patch("safeyolo.commands.tmux.tmux_cmd", side_effect=cmd, autospec=True,):
        assert rename_window_for_agent("alice") is True

    assert _rename_calls(calls) == [["rename-window", "-t", "%3", "alice"]]


def test_rename_when_marker_matches_current_name(monkeypatch):
    """Second SafeYolo rename in same window: automatic-rename=off (from the
    first rename), marker equals the current window name → we own it, rename."""
    monkeypatch.setenv("TMUX", "/tmp/tmux/default,1,0")
    monkeypatch.setenv("TMUX_PANE", "%3")
    cmd, calls = _rename_recorder(
        {"automatic_rename": "off", "window_name": "alice", "marker": "alice"}
    )

    with patch("safeyolo.commands.tmux.tmux_cmd", side_effect=cmd, autospec=True,):
        assert rename_window_for_agent("bob") is True

    assert _rename_calls(calls) == [["rename-window", "-t", "%3", "bob"]]
    assert _marker_writes(calls) == [
        ["set-option", "-w", "-t", "%3", "@safeyolo-window-name", "bob"]
    ]


def test_preserve_when_marker_differs_from_current_name(monkeypatch):
    """Manual rename-window after a SafeYolo rename: current name diverged
    from the marker → user has claimed the name, preserve it."""
    monkeypatch.setenv("TMUX", "/tmp/tmux/default,1,0")
    monkeypatch.setenv("TMUX_PANE", "%3")
    cmd, calls = _rename_recorder(
        {"automatic_rename": "off", "window_name": "my-work", "marker": "alice"}
    )

    with patch("safeyolo.commands.tmux.tmux_cmd", side_effect=cmd, autospec=True,):
        assert rename_window_for_agent("bob") is False

    assert _rename_calls(calls) == []
    assert _marker_writes(calls) == []


def test_preserve_when_marker_unset_but_automatic_rename_off(monkeypatch):
    """User ran rename-window manually before any SafeYolo run in this window:
    off + no marker → preserve."""
    monkeypatch.setenv("TMUX", "/tmp/tmux/default,1,0")
    monkeypatch.setenv("TMUX_PANE", "%3")
    cmd, calls = _rename_recorder(
        {"automatic_rename": "off", "window_name": "my-work", "marker": ""}
    )

    with patch("safeyolo.commands.tmux.tmux_cmd", side_effect=cmd, autospec=True,):
        assert rename_window_for_agent("bob") is False

    assert _rename_calls(calls) == []


def test_rename_when_global_off_but_local_unset(monkeypatch):
    """User sets `set -g automatic-rename off` globally but hasn't touched
    this window. Local-scope query returns empty → treated as safe."""
    monkeypatch.setenv("TMUX", "/tmp/tmux/default,1,0")
    monkeypatch.setenv("TMUX_PANE", "%3")
    cmd, calls = _rename_recorder({"automatic_rename": ""})

    with patch("safeyolo.commands.tmux.tmux_cmd", side_effect=cmd, autospec=True,):
        assert rename_window_for_agent("alice") is True

    assert _rename_calls(calls) == [["rename-window", "-t", "%3", "alice"]]


def test_rename_window_failure_warns_and_is_nonfatal(monkeypatch, capsys):
    monkeypatch.setenv("TMUX", "/tmp/tmux/default,1,0")
    monkeypatch.setenv("TMUX_PANE", "%3")

    def cmd(args, check=True):
        if args[0] == "show-options" and args[-1] == "automatic-rename":
            return completed(args, stdout="on\n")
        if args[0] == "rename-window":
            raise subprocess.CalledProcessError(1, args, stderr="tmux boom")
        return completed(args)

    with patch("safeyolo.commands.tmux.tmux_cmd", side_effect=cmd, autospec=True,):
        assert rename_window_for_agent("alice") is False

    assert "could not rename tmux window" in capsys.readouterr().out


def test_marker_write_failure_leaves_rename_in_place(monkeypatch, capsys):
    """rename-window succeeded, set-option failed. Function returns True
    (rename did happen); the next invocation will observe off + unset
    marker and correctly fall into the preserve branch."""
    monkeypatch.setenv("TMUX", "/tmp/tmux/default,1,0")
    monkeypatch.setenv("TMUX_PANE", "%3")

    def cmd(args, check=True):
        if args[0] == "show-options" and args[-1] == "automatic-rename":
            return completed(args, stdout="on\n")
        if args[:1] == ["set-option"] and "@safeyolo-window-name" in args:
            raise subprocess.CalledProcessError(1, args)
        return completed(args)

    with patch("safeyolo.commands.tmux.tmux_cmd", side_effect=cmd, autospec=True,):
        assert rename_window_for_agent("alice") is True

    assert "could not record SafeYolo marker" in capsys.readouterr().out


def test_show_options_failure_bails_out(monkeypatch, capsys):
    monkeypatch.setenv("TMUX", "/tmp/tmux/default,1,0")
    monkeypatch.setenv("TMUX_PANE", "%3")

    def cmd(args, check=True):
        if args[0] == "show-options" and args[-1] == "automatic-rename":
            raise subprocess.CalledProcessError(1, args, stderr="unknown option")
        return completed(args)

    with patch("safeyolo.commands.tmux.tmux_cmd", side_effect=cmd, autospec=True,):
        assert rename_window_for_agent("alice") is False

    assert "could not query tmux automatic-rename" in capsys.readouterr().out
