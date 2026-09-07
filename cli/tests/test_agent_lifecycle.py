"""Tests for the typed agent lifecycle used by operator clients."""

from unittest.mock import create_autospec, patch

import pytest

from safeyolo.agent_lifecycle import AgentLifecycleError, list_agent_runtimes, start_agent, stop_agent
from safeyolo.platform import AgentPlatform


@pytest.mark.parametrize(("script", "expected"), [
    ("codex-host-setup.sh", "codex"),
    ("codex-coord-host-setup.sh", "codex"),
    ("pi-host-setup.sh", "pi"),
    ("pi-coord-host-setup.sh", "pi"),
    ("claude-host-setup.sh", "claude"),
    ("mise-shell-host-setup.sh", "shell"),
    ("custom-codex-wrapper.sh", None),
    (None, None),
])
def test_inventory_reports_configured_harness_without_probing_guest(script, expected):
    platform = create_autospec(AgentPlatform, instance=True, spec_set=True)
    platform.is_sandbox_running.return_value = False
    metadata = {"agent_id": "ag-probe"}
    if script:
        metadata["host_script"] = f"/installed/contrib/{script}"
    with (
        patch("safeyolo.agent_lifecycle.load_all_agents", return_value={"probe": metadata}, autospec=True),
        patch("safeyolo.agent_lifecycle.load_agent", autospec=True) as reload_metadata,
        patch("safeyolo.platform.get_platform", return_value=platform, autospec=True),
        patch("safeyolo.agent_launchers.observe_launch", return_value={"agent_state": "stopped"}, autospec=True),
    ):
        runtime, = list_agent_runtimes()
    assert runtime.to_dict()["harness"] == expected
    assert runtime.agent_state == "stopped"
    reload_metadata.assert_not_called()
    platform.exec_in_sandbox.assert_not_called()


def test_start_agent_uses_only_fixed_configured_options():
    platform = create_autospec(AgentPlatform, instance=True, spec_set=True)
    platform.is_sandbox_running.return_value = True
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

    assert result.agent_id == "ag-probe"
    assert result.name == "probe"
    assert result.sandbox_state == "ready"
    # A successful launch request is not proof of a live coding-agent session.
    assert result.agent_state == "stopped"
    run.assert_called_once_with(
        name="probe",
        yolo=True,
        launch_mode="background",
        interactive=False,
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


def test_start_agent_preserves_failure_detail_for_operator(caplog):
    platform = create_autospec(AgentPlatform, instance=True, spec_set=True)
    platform.is_sandbox_running.return_value = False
    with (
        patch(
            "safeyolo.agent_lifecycle.get_agent_by_id",
            return_value=("probe\r\n\x1b[31m\u202e", {"agent_id": "ag-probe"}),
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

    record = caplog.records[-1]
    assert record.getMessage() == "Agent probe? failed to start"
    assert record.exc_info is not None
    assert str(record.exc_info[1]) == "configured workspace is unavailable"


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
    assert result.sandbox_state == "stopped"
    assert result.agent_state == "stopped"
    assert write_event.call_args.args[0] == "agent.stopped"
