"""Tests for the shared traffic console command."""

from unittest.mock import create_autospec, patch

from typer.testing import CliRunner

from safeyolo.cli import app
from safeyolo.api import AdminAPI


def test_traffic_updates_scope_before_attaching():
    api = create_autospec(AdminAPI, instance=True, spec_set=True)
    api.set_traffic_scope.return_value = {"effective_filter": "agent cody"}

    with (
        patch("safeyolo.commands.traffic.get_api", return_value=api, autospec=True,),
        patch("safeyolo.commands.traffic.session_exists", return_value=True, autospec=True,),
        patch("safeyolo.commands.traffic.attach_session", return_value=0, autospec=True,) as attach,
    ):
        result = CliRunner().invoke(
            app,
            ["traffic", "--agent", "cody", "--test", "FLOW-05"],
        )

    assert result.exit_code == 0
    api.set_traffic_scope.assert_called_once_with(
        agent="cody",
        unattributed=False,
        test_id="FLOW-05",
        intent=None,
        role=None,
        expect=None,
    )
    attach.assert_called_once()


def test_traffic_can_update_scope_without_terminal_attach():
    api = create_autospec(AdminAPI, instance=True, spec_set=True)
    api.set_traffic_scope.return_value = {"effective_filter": ""}

    with (
        patch("safeyolo.commands.traffic.get_api", return_value=api, autospec=True,),
        patch("safeyolo.commands.traffic.attach_session", autospec=True,) as attach,
    ):
        result = CliRunner().invoke(app, ["traffic", "--no-attach"])

    assert result.exit_code == 0
    attach.assert_not_called()


def test_agent_and_unattributed_are_rejected():
    result = CliRunner().invoke(
        app,
        ["traffic", "--agent", "cody", "--unattributed"],
    )

    assert result.exit_code == 2
