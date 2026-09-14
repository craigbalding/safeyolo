"""Manual launch liveness with real guest-style processes and stale records."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import create_autospec

import pytest

from safeyolo import agent_launchers as launchers
from safeyolo.agents_store import save_agent
from safeyolo.platform import AgentPlatform
from safeyolo.runtime_identity import process_start_token
from safeyolo.vm import get_agent_home_dir, get_agent_status_dir, stage_guest_command_observation

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Guest process identity requires Linux /proc")


@pytest.fixture
def guest(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path / "logs"))
    save_agent("probe", {"agent_id": "ag-probe", "folder": str(tmp_path)})
    records = get_agent_status_dir("probe") / "guest-commands"
    records.mkdir(parents=True)
    context = tmp_path / "context.json"
    context.write_text(json.dumps({"generation": "boot-1"}))
    source = Path(launchers.__file__).with_name("guest-command-observation.py")
    bootstrap = (
        "import runpy, sys; from pathlib import Path; "
        f"ns = runpy.run_path({str(source)!r}); "
        "main = ns['main']; "
        f"main.__globals__.update(CONTEXT=Path({str(context)!r}), RECORDS=Path({str(records)!r})); "
        "sys.exit(main())"
    )
    command = [sys.executable, "-c", bootstrap]
    platform = create_autospec(AgentPlatform, instance=True, spec_set=True)
    platform.is_sandbox_running.return_value = True
    platform.agent_rootfs_path.return_value = tmp_path

    def check(name, command):
        assert name == "probe"
        assert command == "python3 /safeyolo/guest-command-observation.py --check"
        return subprocess.Popen([sys.executable, "-c", bootstrap, "--check"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    platform.popen_in_sandbox.side_effect = check
    monkeypatch.setattr("safeyolo.platform.get_platform", lambda: platform)
    return command, records, context, platform


def start_command(guest):
    command, records, _context, _platform = guest
    process = subprocess.Popen([*command, "/bin/sleep", "60"])
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and process.poll() is None:
        if (records / f"{process.pid}.json").exists():
            return process
        time.sleep(0.01)
    process.kill()
    process.wait()
    raise AssertionError("Configured command did not register")


@pytest.mark.parametrize("signal_name", ["terminate", "kill"])
def test_manual_command_runs_without_host_session_and_cannot_launch_twice(guest, signal_name):
    from safeyolo.commands.agent import _run_agent

    assert launchers.observe_launch("probe", sandbox_ready=True)["agent_state"] == "stopped"
    process = start_command(guest)
    try:
        observed = launchers.observe_launch("probe", sandbox_ready=True)
        assert observed == {"agent_state": "running", "launcher": {"kind": "manual", "source": "guest"},
                            "attachable": False}
        assert _run_agent("probe", launch_mode="background") == 0
        guest[3].exec_in_sandbox.assert_not_called()
        with pytest.raises(RuntimeError, match="original terminal"):
            launchers.attach_agent("probe")
        assert launchers.observe_launch("probe", sandbox_ready=False)["agent_state"] == "stopped"
    finally:
        getattr(process, signal_name)()
        process.wait(timeout=5)
    assert launchers.observe_launch("probe", sandbox_ready=True)["agent_state"] == "stopped"


@pytest.mark.parametrize("stale", ["generation", "token", "invalid-json"])
def test_stale_record_does_not_claim_running(guest, stale):
    process = start_command(guest)
    try:
        path = guest[1] / f"{process.pid}.json"
        if stale == "invalid-json":
            path.write_text("{")
        else:
            record = json.loads(path.read_text())
            record[stale] = "stale"
            path.write_text(json.dumps(record))
        assert launchers.observe_launch("probe", sandbox_ready=True)["agent_state"] == "stopped"
    finally:
        process.kill()
        process.wait(timeout=5)


def test_live_host_session_takes_precedence_over_guest_record(guest):
    record = launchers.prepare_launch("probe", launchers.Launcher("interactive", "agent"), "foreground", "command")
    launchers.update_launch("probe", record["launch_id"], state="running",
                            pid=os.getpid(), process_token=process_start_token(os.getpid()))
    (guest[1] / "stale.json").write_text("{}")
    observed = launchers.observe_launch("probe", sandbox_ready=True)
    assert observed["agent_state"] == "running"
    assert observed["launcher"]["kind"] == "interactive"
    guest[3].popen_in_sandbox.assert_not_called()


@pytest.mark.parametrize("code", [0, 1, 255])
def test_transport_failure_or_missing_reply_does_not_claim_stopped(guest, code):
    process = start_command(guest)
    guest[3].popen_in_sandbox.side_effect = lambda *_: subprocess.Popen(
        [sys.executable, "-c", f"raise SystemExit({code})"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        assert launchers.observe_launch("probe", sandbox_ready=True)["agent_state"] == "unknown"
    finally:
        process.kill()
        process.wait(timeout=5)


def test_custom_script_without_shebang_preserves_arguments_and_exit_code(guest, tmp_path):
    script = tmp_path / "custom-command"
    script.write_text('printf "%s\\n" "$1"\nexit 7\n')
    script.chmod(0o755)
    result = subprocess.run([*guest[0], str(script), "argument with spaces"], capture_output=True, text=True)
    assert result.returncode == 7, result.stderr
    assert result.stdout == "argument with spaces\n"


def test_boot_wraps_both_configured_entrypoints_and_reapplied_setup(guest):
    home = get_agent_home_dir("probe")
    home.mkdir(parents=True)
    for name in (".safeyolo-command", ".safeyolo-interactive-command"):
        path = home / name
        path.write_text('#!/bin/sh\nexec custom-agent "$@"\n')
        path.chmod(0o755)
    stage_guest_command_observation(home)
    stage_guest_command_observation(home)
    for name in (".safeyolo-command", ".safeyolo-interactive-command"):
        assert (home / f"{name}.payload").read_text() == '#!/bin/sh\nexec custom-agent "$@"\n'
    entry = home / ".safeyolo-command"
    entry.write_text("#!/bin/sh\nexec replacement\n")
    stage_guest_command_observation(home)
    assert (home / ".safeyolo-command.payload").read_text() == "#!/bin/sh\nexec replacement\n"
