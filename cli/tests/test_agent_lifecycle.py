"""Tests for the typed agent lifecycle used by operator clients."""

from unittest.mock import create_autospec, patch

import pytest

from safeyolo.agent_lifecycle import AgentLifecycleError, start_agent, stop_agent
from safeyolo.platform import AgentPlatform


def test_start_agent_uses_only_fixed_configured_options():
    platform = create_autospec(AgentPlatform, instance=True, spec_set=True)
    platform.is_sandbox_running.side_effect = [False, True, True]
    with (
        patch(
            "safeyolo.agent_lifecycle.get_agent_by_id",
            return_value=("probe", {"agent_id": "ag-probe"}),
            autospec=True,
        ),
        patch("safeyolo.platform.get_platform", return_value=platform, autospec=True),
        patch(
            "safeyolo.commands.agent._run_agent",
            return_value=0,
            autospec=True,
        ) as run,
    ):
        result = start_agent("ag-probe")

    assert result.to_dict() == {
        "agent_id": "ag-probe",
        "name": "probe",
        "state": "running",
    }
    run.assert_called_once_with(
        name="probe",
        yolo=True,
        detach=True,
        no_snapshot=True,
        rename_tmux_window=False,
    )


def test_start_agent_rejects_unknown_identity():
    with patch(
        "safeyolo.agent_lifecycle.get_agent_by_id",
        return_value=None,
        autospec=True,
    ):
        with pytest.raises(AgentLifecycleError, match="Agent not found") as caught:
            start_agent("ag-missing")
    assert caught.value.status_code == 404


def test_start_agent_preserves_failure_detail_for_operator():
    platform = create_autospec(AgentPlatform, instance=True, spec_set=True)
    platform.is_sandbox_running.return_value = False
    with (
        patch(
            "safeyolo.agent_lifecycle.get_agent_by_id",
            return_value=("probe", {"agent_id": "ag-probe"}),
            autospec=True,
        ),
        patch("safeyolo.platform.get_platform", return_value=platform, autospec=True),
        patch(
            "safeyolo.commands.agent._run_agent",
            side_effect=RuntimeError("configured workspace is unavailable"),
            autospec=True,
        ),
        pytest.raises(
            AgentLifecycleError,
            match=(
                "Agent start failed: RuntimeError: "
                "configured workspace is unavailable"
            ),
        ),
    ):
        start_agent("ag-probe")


def test_stop_agent_stops_supervisor_and_running_sandbox():
    platform = create_autospec(AgentPlatform, instance=True, spec_set=True)
    platform.is_sandbox_running.side_effect = [True, False]
    with (
        patch(
            "safeyolo.agent_lifecycle.get_agent_by_id",
            return_value=("probe", {"agent_id": "ag-probe"}),
            autospec=True,
        ),
        patch(
            "safeyolo.agent_command_supervisor.request_command_supervisor_stop",
            return_value=True,
            autospec=True,
        ) as stop_supervisor,
        patch("safeyolo.platform.get_platform", return_value=platform, autospec=True),
        patch("safeyolo.proxy.is_proxy_running", return_value=False, autospec=True),
        patch("safeyolo.events.write_event", autospec=True) as write_event,
    ):
        result = stop_agent("ag-probe")

    stop_supervisor.assert_called_once_with("probe")
    platform.stop_sandbox.assert_called_once_with("probe")
    assert result.state == "stopped"
    assert write_event.call_args.args[0] == "agent.stopped"
