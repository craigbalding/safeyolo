"""Tests for the optional outer-tmux traffic-console adapter."""

import subprocess
from unittest.mock import call, create_autospec, patch

from typer.testing import CliRunner

from safeyolo.cli import app
from safeyolo.api import AdminAPI
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


def test_unassociated_pane_does_not_open_unscoped_traffic(monkeypatch):
    monkeypatch.setenv("TMUX", "/tmp/tmux/default,1,0")
    monkeypatch.setenv("TMUX_PANE", "%2")

    with (
        patch(
            "safeyolo.commands.tmux.tmux_cmd",
            return_value=completed([], stdout="\n"),
        autospec=True,
        ),
        patch("safeyolo.commands.tmux.get_api", autospec=True,) as api,
    ):
        result = CliRunner().invoke(app, ["tmux", "traffic"])

    assert result.exit_code == 1
    assert "not associated" in result.output
    api.assert_not_called()


def test_seven_agents_reuse_one_owned_traffic_window(monkeypatch):
    monkeypatch.setenv("TMUX", "/tmp/tmux/default,1,0")
    monkeypatch.setenv("TMUX_PANE", "%2")
    api = create_autospec(AdminAPI, instance=True, spec_set=True)
    state = {"agent": "agent-0", "window": None}
    calls = []

    def command(args, check=True):
        calls.append(args)
        if args[:3] == ["display-message", "-p", "-t"]:
            if args[-1] == "#{@safeyolo-agent}":
                return completed(args, stdout=state["agent"] + "\n")
            if args[-1] == "#{session_id}":
                return completed(args, stdout="$1\n")
        if args[0] == "list-windows":
            output = "" if state["window"] is None else "@9\tsafeyolo-traffic\t0\t1\n"
            return completed(args, stdout=output)
        if args[0] == "new-window":
            state["window"] = "@9"
            return completed(args, stdout="@9\n")
        return completed(args)

    with (
        patch("safeyolo.commands.tmux.tmux_cmd", side_effect=command, autospec=True,),
        patch("safeyolo.commands.tmux.get_api", return_value=api, autospec=True,),
    ):
        for number in range(7):
            state["agent"] = f"agent-{number}"
            result = CliRunner().invoke(app, ["tmux", "traffic"])
            assert result.exit_code == 0

    assert sum(args[0] == "new-window" for args in calls) == 1
    assert sum(args[0] == "select-window" for args in calls) == 7
    assert all("display-popup" not in args for args in calls)
    assert api.set_traffic_scope.call_args_list == [
        call(
            agent=f"agent-{number}",
            unattributed=False,
            test_id=None,
            intent=None,
            role=None,
            expect=None,
        )
        for number in range(7)
    ]


def test_return_command_selects_recorded_origin(monkeypatch):
    monkeypatch.setenv("TMUX", "/tmp/tmux/default,1,0")
    monkeypatch.setenv("TMUX_PANE", "%9")

    def command(args, check=True):
        if args[0] == "display-message":
            return completed(args, stdout="$1\n")
        if args[0] == "show-option":
            return completed(args, stdout="%2\n")
        return completed(args)

    with patch("safeyolo.commands.tmux.tmux_cmd", side_effect=command, autospec=True,) as command_mock:
        result = CliRunner().invoke(app, ["tmux", "return-to-agent"])

    assert result.exit_code == 0
    assert command_mock.call_args_list[-2:] == [
        call(["select-window", "-t", "%2"]),
        call(["select-pane", "-t", "%2"]),
    ]


def test_generated_config_documents_bindings_and_preserves_existing_keys():
    assert "prefix + T already bound; traffic binding skipped" in TMUX_CONFIG_SNIPPET
    assert "safeyolo tmux traffic" in TMUX_CONFIG_SNIPPET
    assert "safeyolo tmux return-to-agent" in TMUX_CONFIG_SNIPPET
    assert "display-popup" not in "\n".join(
        line for line in TMUX_CONFIG_SNIPPET.splitlines() if "tmux traffic" in line
    )


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
