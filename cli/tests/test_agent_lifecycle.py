"""Tests for the remaining Python workflow lifecycle helpers."""

from unittest.mock import create_autospec, patch

import pytest

from safeyolo.agent_lifecycle import list_agent_runtimes, stop_agent_by_name
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


def test_stop_agent_stops_supervisor_and_running_sandbox():
    platform = create_autospec(AgentPlatform, instance=True, spec_set=True)
    platform.is_sandbox_running.side_effect = [True, False]
    with (
        patch(
            "safeyolo.agent_command_supervisor.request_command_supervisor_stop",
            return_value=True,
            autospec=True,
        ) as stop_supervisor,
        patch("safeyolo.platform.get_platform", return_value=platform, autospec=True),
        patch("safeyolo.proxy.is_proxy_running", return_value=False, autospec=True),
        patch("safeyolo.events.write_event", autospec=True) as write_event,
    ):
        result = stop_agent_by_name("probe", agent_id="ag-probe")

    stop_supervisor.assert_called_once_with("probe")
    platform.stop_sandbox.assert_called_once_with("probe")
    assert result.sandbox_state == "stopped"
    assert result.agent_state == "stopped"
    assert write_event.call_args.args[0] == "agent.stopped"
