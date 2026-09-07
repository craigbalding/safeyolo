"""Persistent operator shell routing and real tmux disconnect/reconnect behavior."""

import json
import os
import pty
import select
import shutil
import signal
import subprocess
import sys
import time
from unittest.mock import create_autospec, patch

import pytest
from typer.testing import CliRunner

from safeyolo import shell_sessions
from safeyolo.agents_store import save_agent
from safeyolo.commands.agent import agent_app
from safeyolo.platform import AgentPlatform


@pytest.fixture
def shell_instance(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path / "operator's config"))
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path / "operator's logs"))
    save_agent("probe", {"agent_id": "ag-probe", "folder": str(tmp_path)})
    return tmp_path


@pytest.mark.parametrize("root", [False, True])
def test_persistent_cli_uses_operator_shell_not_coding_agent(shell_instance, root):
    platform = create_autospec(AgentPlatform, instance=True, spec_set=True)
    platform.is_sandbox_running.return_value = True
    with (
        patch("safeyolo.platform.get_platform", autospec=True, return_value=platform),
        patch.object(shell_sessions, "open_persistent_shell", autospec=True, return_value=7) as opened,
    ):
        result = CliRunner().invoke(agent_app, ["shell", "probe", "--persistent", *(["--root"] if root else [])])
    assert result.exit_code == 7, result.output
    opened.assert_called_once_with("probe", root=root)
    platform.exec_in_sandbox.assert_not_called()


@pytest.mark.parametrize("args", [[], ["--command", "printf ok"], ["--root"]])
def test_plain_cli_shell_keeps_existing_behavior(shell_instance, args):
    platform = create_autospec(AgentPlatform, instance=True, spec_set=True)
    platform.is_sandbox_running.return_value = True
    platform.exec_in_sandbox.return_value = 0
    with (
        patch("safeyolo.platform.get_platform", autospec=True, return_value=platform),
        patch.object(shell_sessions, "open_persistent_shell", autospec=True) as opened,
    ):
        result = CliRunner().invoke(agent_app, ["shell", "probe", *args])
    assert result.exit_code == 0, result.output
    opened.assert_not_called()
    platform.exec_in_sandbox.assert_called_once_with(
        "probe", "printf ok" if "--command" in args else None,
        user="root" if "--root" in args else "agent", interactive="--command" not in args,
    )


@pytest.mark.parametrize("args", [["--command", ""], ["--agent-command"], ["--launch-id", "launch-test"]])
def test_persistent_flag_rejects_noninteractive_or_launcher_commands(args):
    result = CliRunner().invoke(agent_app, ["shell", "probe", "--persistent", *args])
    assert result.exit_code == 2
    assert "interactive operator shell" in result.output


def test_stopped_sandbox_does_not_create_session(shell_instance):
    platform = create_autospec(AgentPlatform, instance=True, spec_set=True)
    platform.is_sandbox_running.return_value = False
    with (
        patch("safeyolo.platform.get_platform", autospec=True, return_value=platform),
        patch.object(shell_sessions, "open_persistent_shell", autospec=True) as opened,
    ):
        result = CliRunner().invoke(agent_app, ["shell", "probe", "--persistent"])
    assert result.exit_code == 1
    opened.assert_not_called()


def test_missing_tmux_does_not_fall_back_to_unprotected_shell(shell_instance, monkeypatch):
    monkeypatch.setattr(shell_sessions.shutil, "which", lambda _: None)
    with pytest.raises(RuntimeError, match="Install tmux there and retry"):
        shell_sessions.open_persistent_shell("probe")


def test_child_argv_preserves_instance_python_and_shell_role(shell_instance, monkeypatch):
    python = "/opt/operator's venv/bin/python"
    monkeypatch.setattr(shell_sessions.sys, "executable", python)
    config = shell_instance / "operator's config"
    logs = shell_instance / "operator's logs"
    assert shell_sessions._shell_command("probe", root=False) == [
        "env", f"SAFEYOLO_CONFIG_DIR={config}", f"SAFEYOLO_LOGS_DIR={logs}",
        python, "-m", "safeyolo.cli", "agent", "shell", "--", "probe",
    ]
    root_command = shell_sessions._shell_command("probe", root=True)
    assert root_command[-3:] == ["--root", "--", "probe"]
    assert "--persistent" not in root_command, "The inner shell must not recurse"


def test_session_identity_separates_instance_agent_and_user(shell_instance, monkeypatch):
    original = shell_sessions._session_target("probe", root=False)
    assert shell_sessions._session_target("probe", root=True) != original
    save_agent("probe", {"agent_id": "ag-recreated"})
    assert shell_sessions._session_target("probe", root=False) != original
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(shell_instance / "other-instance"))
    save_agent("probe", {"agent_id": "ag-probe"})
    assert shell_sessions._session_target("probe", root=False)[0] != original[0]


@pytest.fixture
def real_shell(shell_instance):
    if not shutil.which("tmux"):
        pytest.skip("persistent shell acceptance requires real tmux")
    tmux, session = shell_sessions._session_target("probe", root=False)
    env = dict(os.environ, TERM="xterm-256color", TMUX_TMPDIR="/tmp")
    env.pop("TMUX", None)
    env.pop("TMUX_PANE", None)

    def query(*args, check=True):
        return subprocess.run([*tmux, *args], env=env, capture_output=True, text=True, check=check)

    started = shell_instance / "shell-starts"
    gate = shell_instance / "finish-work"
    completed = shell_instance / "completed"
    # Exercise real host tmux with a stateful process. This does not claim
    # to be a real gVisor/VZ sandbox integration test.
    program = """
import os, sys, time
from pathlib import Path
started, gate, completed = map(Path, sys.argv[1:])
with started.open('a') as handle:
    handle.write(str(os.getpid()) + '\\n')
count = 0
print('SHELL-READY', flush=True)
for line in sys.stdin:
    if line.strip() == 'work':
        print('WORK-STARTED', flush=True)
        while not gate.exists():
            time.sleep(0.01)
        count += 1
        completed.write_text(str(count))
        print('WORK-DONE', flush=True)
    elif line.strip() == 'read':
        print('RETAINED-COUNT:' + str(count), flush=True)
    elif line.strip() == 'exit':
        break
"""
    command = [sys.executable, "-u", "-c", program, str(started), str(gate), str(completed)]
    driver = """
import json, sys
from safeyolo import shell_sessions
shell_sessions._shell_command = lambda name, root: json.loads(sys.argv[1])
raise SystemExit(shell_sessions.open_persistent_shell('probe'))
"""
    viewers = []

    def open_viewer(*, other_tmux=False):
        master, slave = pty.openpty()
        viewer_env = dict(env)
        if other_tmux:
            viewer_env.update(TMUX="/tmp/unrelated-server,123,0", TMUX_PANE="%0", TMUX_TMPDIR="/not-used")
        viewer = subprocess.Popen(
            [sys.executable, "-c", driver, json.dumps(command)],
            stdin=slave, stdout=slave, stderr=slave, env=viewer_env, start_new_session=True,
        )
        os.close(slave)
        screen = bytearray()
        viewers.append((viewer, master))
        return viewer, master, screen

    try:
        yield query, session, open_viewer, started, gate, completed
    finally:
        for viewer, master in viewers:
            if viewer.poll() is None:
                os.killpg(viewer.pid, signal.SIGKILL)
            viewer.wait(timeout=5)
            os.close(master)
        # Only this fixture's unique configuration-derived server is targeted.
        query("kill-server", check=False)


def see(master, screen, marker):
    deadline = time.monotonic() + 5
    while marker not in screen and time.monotonic() < deadline:
        if select.select([master], [], [], 0.05)[0]:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                pytest.fail(f"Viewer closed before {marker!r}: {screen!r}")
            assert chunk, screen
            screen.extend(chunk)
    assert marker in screen, screen


def test_work_survives_killed_viewer_and_reopen_reuses_same_shell(real_shell):
    query, session, open_viewer, started, gate, completed = real_shell
    first, master, screen = open_viewer()
    see(master, screen, b"SHELL-READY")
    original_pid = started.read_text()
    os.write(master, b"work\n")
    see(master, screen, b"WORK-STARTED")
    # Abruptly kill the viewer rather than performing a clean tmux detach.
    os.killpg(first.pid, signal.SIGKILL)
    first.wait(timeout=5)
    deadline = time.monotonic() + 5
    while query("list-clients").stdout and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not query("list-clients").stdout, "No viewer may remain attached during the outage"
    gate.touch()
    deadline = time.monotonic() + 5
    while not completed.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert completed.read_text() == "1", "Work must complete without an attached viewer"
    _, master, screen = open_viewer(other_tmux=True)
    see(master, screen, b"WORK-DONE")
    os.write(master, b"read\n")
    see(master, screen, b"RETAINED-COUNT:1")
    assert started.read_text() == original_pid, "Reopen must not launch another shell"
    assert query("list-sessions", "-F", "#{session_name}").stdout.splitlines() == [session]


def test_concurrent_openers_share_one_shell(real_shell):
    _, _, open_viewer, started, _, _ = real_shell
    viewers = [open_viewer(), open_viewer()]
    for _, master, screen in viewers:
        see(master, screen, b"SHELL-READY")
    assert len(started.read_text().splitlines()) == 1


def test_explicit_shell_exit_allows_new_session(real_shell):
    query, session, open_viewer, started, _, _ = real_shell
    _, master, screen = open_viewer()
    see(master, screen, b"SHELL-READY")
    os.write(master, b"exit\n")
    deadline = time.monotonic() + 5
    while query("has-session", "-t", f"={session}", check=False).returncode == 0 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert query("has-session", "-t", f"={session}", check=False).returncode != 0
    _, master, screen = open_viewer()
    see(master, screen, b"SHELL-READY")
    assert len(started.read_text().splitlines()) == 2


def test_only_shell_session_options_override_destructive_global_defaults(real_shell):
    query, session, open_viewer, _, _, _ = real_shell
    # Keep this fixture server alive while changing its global defaults.
    query("-f", "/dev/null", "new-session", "-d", "-s", "unrelated", sys.executable, "-c", "import time; time.sleep(30)")
    query("set-option", "-t", "unrelated", "destroy-unattached", "off")
    query("set-option", "-g", "destroy-unattached", "on")
    query("set-window-option", "-g", "remain-on-exit", "on")
    _, master, screen = open_viewer()
    see(master, screen, b"SHELL-READY")
    assert query("show-options", "-v", "-t", session, "destroy-unattached").stdout.strip() == "off"
    assert query("show-window-options", "-v", "-t", session, "remain-on-exit").stdout.strip() == "off"
    assert query("show-options", "-gv", "destroy-unattached").stdout.strip() == "on"
    assert query("show-window-options", "-gv", "remain-on-exit").stdout.strip() == "on"


def test_session_creation_failure_is_reported(shell_instance):
    with pytest.raises(RuntimeError, match="Cannot create persistent sandbox shell"):
        shell_sessions._ensure_session(["false"], "shell-fixture", ["true"], dict(os.environ))
