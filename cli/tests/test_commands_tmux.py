"""Tests for the optional outer-tmux traffic-console adapter."""

import subprocess
from unittest.mock import MagicMock, call, patch

from typer.testing import CliRunner

from safeyolo.cli import app
from safeyolo.commands.tmux import TMUX_CONFIG_SNIPPET, associate_agent_pane


def completed(args, *, stdout="", returncode=0):
    return subprocess.CompletedProcess(args=args, returncode=returncode, stdout=stdout, stderr="")


def test_agent_pane_association_is_noop_outside_tmux(monkeypatch):
    monkeypatch.delenv("TMUX", raising=False)
    monkeypatch.delenv("TMUX_PANE", raising=False)

    with patch("safeyolo.commands.tmux.tmux_cmd") as command:
        assert associate_agent_pane("alice") is False

    command.assert_not_called()


def test_agent_pane_association_uses_pane_local_option(monkeypatch):
    monkeypatch.setenv("TMUX", "/tmp/tmux/default,1,0")
    monkeypatch.setenv("TMUX_PANE", "%7")

    with patch("safeyolo.commands.tmux.tmux_cmd") as command:
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
        ),
        patch("safeyolo.commands.tmux.get_api") as api,
    ):
        result = CliRunner().invoke(app, ["tmux", "traffic"])

    assert result.exit_code == 1
    assert "not associated" in result.output
    api.assert_not_called()


def test_seven_agents_reuse_one_owned_traffic_window(monkeypatch):
    monkeypatch.setenv("TMUX", "/tmp/tmux/default,1,0")
    monkeypatch.setenv("TMUX_PANE", "%2")
    api = MagicMock()
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
        patch("safeyolo.commands.tmux.tmux_cmd", side_effect=command),
        patch("safeyolo.commands.tmux.get_api", return_value=api),
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

    with patch("safeyolo.commands.tmux.tmux_cmd", side_effect=command) as command_mock:
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
