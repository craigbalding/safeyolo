"""Launch selection, current-session identity, and host/guest separation."""

import json
import os
import subprocess
from dataclasses import asdict
from unittest.mock import create_autospec, patch

import pytest

from safeyolo import agent_launchers as launchers
from safeyolo.agents_store import save_agent
from safeyolo.platform import AgentPlatform


@pytest.fixture
def agent(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path / "logs"))
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    save_agent("probe", {"agent_id": "ag-probe", "folder": str(workspace)})
    return workspace


@pytest.mark.parametrize(("metadata", "defaults", "mode", "kind", "source"), [
    ({}, {}, "foreground", "interactive", "built-in"),
    ({}, {}, "background", "tmux-window", "built-in"),
    ({"launcher": "supervisor"}, {"default": "tmux-pane"}, "background", "supervisor", "agent"),
    ({"launcher": "interactive"}, {"default": "tmux-pane"}, "foreground", "interactive", "agent"),
    ({}, {"default": "tmux-pane"}, "background", "tmux-pane", "host default"),
    ({"launcher": "supervisor"}, {}, "sandbox", "sandbox", "requested"),
])
def test_resolve_precedence(metadata, defaults, mode, kind, source):
    selected = launchers.resolve_launcher(metadata, {"agent_launcher": defaults}, mode)
    assert (selected.kind, selected.source) == (kind, source)


def test_managed_debug_override_does_not_modify_configuration():
    metadata = {"launcher": "supervisor"}
    assert launchers.resolve_launcher(metadata, {}, "background", interactive=True).kind == "tmux-window"
    assert metadata == {"launcher": "supervisor"}


def test_custom_launcher_cannot_be_in_guest_workspace_or_home(agent):
    script = agent / "launcher.sh"
    script.write_text("#!/bin/bash\nexit 0\n")
    script.chmod(0o755)
    with pytest.raises(RuntimeError, match="agent-writable"):
        launchers.validate_script(launchers.Launcher("script", "agent", str(script)))


def test_current_launch_retains_original_launcher_after_default_change(agent, monkeypatch):
    selected = launchers.resolve_launcher({}, {}, "background")
    record = launchers.prepare_launch("probe", selected, "background", "exec /bin/bash")
    launchers.update_launch("probe", record["launch_id"], state="exited", exit_code=7)
    monkeypatch.setattr(launchers, "load_config", lambda: {"agent_launcher": {"default": "tmux-pane"}})
    observed = launchers.observe_launch("probe", sandbox_ready=True)
    assert observed["launcher"] == asdict(selected)
    assert observed["agent_state"] == "exited"
    assert observed["exit_code"] == 7


def test_exited_harness_does_not_claim_agent_running_in_ready_sandbox(agent):
    record = launchers.prepare_launch("probe", launchers.Launcher("interactive", "agent"), "foreground", "exit 0")
    launchers.update_launch("probe", record["launch_id"], state="running", pid=os.getpid(), process_token="stale")
    assert launchers.observe_launch("probe", sandbox_ready=True)["agent_state"] == "exited"


def test_old_run_cannot_overwrite_new_launch(agent):
    old = launchers.prepare_launch("probe", launchers.Launcher("interactive", "agent"), "foreground", "exit 0")
    new = launchers.prepare_launch("probe", launchers.Launcher("interactive", "agent"), "foreground", "exit 0")
    with pytest.raises(RuntimeError, match="another run"):
        launchers.update_launch("probe", old["launch_id"], state="exited")
    assert launchers.read_launch("probe")["launch_id"] == new["launch_id"]


def test_script_zero_exit_does_not_claim_live_agent(agent, tmp_path):
    script = tmp_path / "launcher.sh"
    script.write_text("#!/bin/bash\nexit 0\n")
    script.chmod(0o755)
    record = launchers.prepare_launch("probe", launchers.Launcher("script", "agent", str(script)), "background", "unused")
    assert launchers.invoke_launcher(record) == 0
    assert launchers.observe_launch("probe", sandbox_ready=True)["agent_state"] == "unknown"


def test_attach_absent_session_does_not_launch(agent):
    platform = create_autospec(AgentPlatform, instance=True, spec_set=True)
    platform.is_sandbox_running.return_value = True
    with patch("safeyolo.platform.get_platform", return_value=platform, autospec=True):
        with pytest.raises(RuntimeError, match="no live session"):
            launchers.attach_agent("probe")
    platform.exec_in_sandbox.assert_not_called()


def test_entrypoint_hooks_follow_actual_process_exit(agent, tmp_path):
    markers = tmp_path / "hooks.jsonl"
    script = tmp_path / "launcher.sh"
    script.write_text('#!/bin/bash\nprintf \'%s:%s\\n\' "$1" "$SAFEYOLO_AGENT_EXIT_CODE" >> "' + str(markers) + '"\n')
    script.chmod(0o755)
    record = launchers.prepare_launch("probe", launchers.Launcher("script", "agent", str(script)), "foreground", "guest command")
    platform = create_autospec(AgentPlatform, instance=True, spec_set=True)
    platform.is_sandbox_running.return_value = True

    def execute(name, command, *, on_start, **kwargs):
        # A real host process supplies identity. Guest execution is asserted
        # at this unit boundary; real gVisor/VZ acceptance is separate.
        with subprocess.Popen(["/bin/sh", "-c", "exit 7"]) as process:
            on_start(process)
            assert markers.read_text().splitlines() == ["pre_launch:", "post_launch:"]
            return process.wait()

    platform.exec_in_sandbox.side_effect = execute
    with patch("safeyolo.platform.get_platform", return_value=platform, autospec=True):
        assert launchers.run_entrypoint("probe", record["launch_id"]) == 7
    assert markers.read_text().splitlines() == ["pre_launch:", "post_launch:", "on_exit:7"]
    assert launchers.read_launch("probe")["exit_code"] == 7


def test_context_values_are_data_not_command_source(agent):
    record = launchers.prepare_launch("probe", launchers.Launcher("interactive", "agent"), "foreground", "exit 0")
    environment = launchers.launch_environment(record)
    assert environment["SAFEYOLO_AGENT_NAME"] == "probe"
    assert environment["SAFEYOLO_AGENT_ID"] == "ag-probe"
    assert environment["SAFEYOLO_LAUNCH_ID"] == record["launch_id"]
    assert json.loads(launchers._path("probe").read_text())["command"] == "exit 0"


@pytest.mark.parametrize("failed_hook", ["pre_launch", "post_launch", "on_exit"])
def test_hook_failure_has_its_own_result(agent, tmp_path, failed_hook):
    script = tmp_path / "launcher.sh"
    script.write_text(f'#!/bin/bash\nif [ "$1" = "{failed_hook}" ]; then echo "hook failed" >&2; exit 42; fi\n')
    script.chmod(0o755)
    record = launchers.prepare_launch("probe", launchers.Launcher("script", "agent", str(script)), "foreground", "guest")
    platform = create_autospec(AgentPlatform, instance=True, spec_set=True)
    platform.is_sandbox_running.return_value = True

    def execute(name, command, *, on_start, **kwargs):
        with subprocess.Popen(["/bin/sh", "-c", "exit 7"]) as process:
            on_start(process)
            return process.wait()

    platform.exec_in_sandbox.side_effect = execute
    with patch("safeyolo.platform.get_platform", return_value=platform, autospec=True):
        code = launchers.run_entrypoint("probe", record["launch_id"])
    current = launchers.read_launch("probe")
    if failed_hook == "pre_launch":
        assert code == 42
        platform.exec_in_sandbox.assert_not_called()
        assert current["state"] == "failed"
    else:
        assert code == current["exit_code"] == 7
        assert current["state"] == "exited"
    assert current["hook_errors"][0]["hook"] == failed_hook
    assert current["hook_errors"][0]["exit_code"] == 42


def test_custom_script_can_return_before_its_entrypoint_claims_run(agent, tmp_path):
    script = tmp_path / "launcher.sh"
    script.write_text("#!/bin/bash\nexit 0\n")
    script.chmod(0o755)
    record = launchers.prepare_launch("probe", launchers.Launcher("script", "agent", str(script)), "background", "guest")
    launchers.invoke_launcher(record)
    assert launchers.read_launch("probe")["state"] == "unknown"
    platform = create_autospec(AgentPlatform, instance=True, spec_set=True)
    platform.is_sandbox_running.return_value = True
    platform.exec_in_sandbox.return_value = 0
    with patch("safeyolo.platform.get_platform", return_value=platform, autospec=True):
        assert launchers.run_entrypoint("probe", record["launch_id"]) == 0
        with pytest.raises(RuntimeError, match="No matching"):
            launchers.run_entrypoint("probe", record["launch_id"])
    assert platform.exec_in_sandbox.call_count == 1


def test_stopped_sandbox_does_not_hide_live_exit_callback(agent):
    record = launchers.prepare_launch("probe", launchers.Launcher("interactive", "agent"), "foreground", "guest")
    launchers.update_launch("probe", record["launch_id"], state="finishing", runner_pid=os.getpid(),
                           runner_token=launchers.process_start_token(os.getpid()))
    assert launchers.observe_launch("probe", sandbox_ready=False)["agent_state"] == "finishing"


def test_custom_script_symlink_into_workspace_is_rejected(agent, tmp_path):
    guest_script = agent / "script.sh"
    guest_script.write_text("#!/bin/bash\nexit 0\n")
    guest_script.chmod(0o755)
    host_link = tmp_path / "launcher.sh"
    host_link.symlink_to(guest_script)
    with pytest.raises(RuntimeError, match="agent-writable"):
        launchers.validate_script(launchers.Launcher("script", "agent", str(host_link)))


def test_boot_context_retains_actual_workspace_and_transient_mounts(agent, tmp_path):
    from safeyolo.vm import get_agent_config_share_dir

    override = tmp_path / "actual-workspace"
    override.mkdir()
    transient = tmp_path / "one-off-mount"
    transient.mkdir()
    share = get_agent_config_share_dir("probe")
    share.mkdir(parents=True)
    (share / "host-launch-context.json").write_text(json.dumps({
        "workspace": str(override), "writable_mounts": [str(transient)],
    }))
    record = launchers.prepare_launch("probe", launchers.Launcher("interactive", "agent"), "foreground", "guest")
    assert launchers.launch_environment(record)["SAFEYOLO_WORKSPACE"] == str(override)
    for directory in (override, transient):
        script = directory / "launcher.sh"
        script.write_text("#!/bin/sh\nexit 0\n")
        script.chmod(0o755)
        with pytest.raises(RuntimeError, match="agent-writable"):
            launchers.validate_script(launchers.Launcher("script", "agent", str(script)))
