"""Real tmux routing and viewer I/O; no guest runtime is mocked as acceptance."""

import importlib.util
import os
import pty
import select
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

probe_path = Path(__file__).resolve().parents[2] / "tests/nested-linux/launcher_acceptance.py"
spec = importlib.util.spec_from_file_location("launcher_acceptance", probe_path)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def tmux(socket, *args, check=True):
    return subprocess.run(["tmux", "-S", str(socket), *args], capture_output=True,
                          text=True, check=check)


@pytest.fixture
def servers(tmp_path, monkeypatch):
    installed_tmux = shutil.which("tmux")
    if not installed_tmux:
        pytest.skip("real tmux routing requires tmux")
    root = tmp_path / "config"
    (root / "bin").mkdir(parents=True)
    (root / "bin/tmux").symlink_to(installed_tmux)
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(root))
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path / "logs"))
    record = {"launch_id": "launch-preset-fixture", "pane_id": "%0",
              "launcher": {"script": str(Path(__file__).resolve().parents[1] / "src/safeyolo/launchers/tmux-window.sh")}}
    # Short, private socket paths also fit macOS's Unix socket path limit.
    parent = tempfile.gettempdir()
    if len(os.fsencode(str(Path(parent) / "sy-tmux-xxxxxxxx" / "agent's server"))) >= 104:
        parent = "/tmp"
    with tempfile.TemporaryDirectory(prefix="sy-tmux-", dir=parent) as directory:
        sockets = [Path(directory) / "agent's server", Path(directory) / "viewer"]
        assert all(len(os.fsencode(str(socket))) < 104 for socket in sockets)
        try:
            for index, socket in enumerate(sockets):
                marker = "AGENT-READY" if index == 0 else "WRONG-SERVER"
                command = f"printf '{marker}\\n'; while IFS= read -r line; do printf 'received:%s\\n' \"$line\"; done"
                created = tmux(socket, "-f", "/dev/null", "new-session", "-d", "-P", "-F", "#{pane_id}",
                               "-s", "agent", command)
                assert created.stdout.strip() == "%0", "both servers must have the same pane ID"
                identity = record["launch_id"] if index == 0 else "different-launch"
                tmux(socket, "set-option", "-p", "-t", "%0", "@safeyolo_launch_id", identity)
            record["tmux_socket"] = str(sockets[0])
            yield record, sockets
        finally:
            for socket in sockets:
                # These two test-owned servers contain only the fixture's panes.
                tmux(socket, "kill-server", check=False)


def viewer_environment(record, sockets, *, other_server):
    env = {**os.environ, "SAFEYOLO_AGENT_NAME": "probe", "SAFEYOLO_LAUNCH_ID": record["launch_id"],
           "SAFEYOLO_TMUX_SESSION": "agent", "SAFEYOLO_LAUNCH_PANE": record["pane_id"],
           "SAFEYOLO_TMUX_SOCKET": record["tmux_socket"]}
    env.update(TERM="xterm-256color")
    env.pop("TMUX", None)
    env.pop("TMUX_PANE", None)
    if other_server:
        pid = tmux(sockets[1], "display-message", "-p", "-t", "%0", "#{pid}").stdout.strip()
        env.update(TMUX=f"{sockets[1]},{pid},0", TMUX_PANE="%0")
    return env


def test_status_uses_recorded_server_not_callers_server(servers):
    record, sockets = servers
    result = subprocess.run([record["launcher"]["script"], "status"], text=True, capture_output=True,
                            env=viewer_environment(record, sockets, other_server=True))
    assert result.returncode == 0, result.stderr
    assert '"state":"running"' in result.stdout


def test_same_server_switches_existing_viewer(servers):
    record, sockets = servers
    waiting_pane = tmux(sockets[0], "new-session", "-d", "-P", "-F", "#{pane_id}",
                        "-s", "waiting", "printf 'WAITING-ROOM\\n'; read -r line").stdout.strip()
    master, slave = pty.openpty()
    env = viewer_environment(record, sockets, other_server=False)
    viewer = subprocess.Popen(["tmux", "-S", str(sockets[0]), "attach-session", "-t", "waiting"],
                              stdin=slave, stdout=slave, stderr=slave, env=env, start_new_session=True)
    os.close(slave)
    output = bytearray()
    try:
        deadline = time.monotonic() + 5
        while b"WAITING-ROOM" not in output and time.monotonic() < deadline:
            probe.read_terminal(master, output)
        assert b"WAITING-ROOM" in output
        pid = tmux(sockets[0], "display-message", "-p", "-t", waiting_pane, "#{pid}").stdout.strip()
        env.update(TMUX=f"{sockets[0]},{pid},1", TMUX_PANE=waiting_pane)
        result = subprocess.run([record["launcher"]["script"], "attach"],
                                env=env, capture_output=True, text=True, timeout=5)
        assert result.returncode == 0, result.stderr
        clients = tmux(sockets[0], "list-clients", "-F", "#{client_pid}:#{session_name}").stdout.splitlines()
        assert clients == [f"{viewer.pid}:agent"], "reuse the existing client, do not nest another viewer"
    finally:
        if viewer.poll() is None:
            os.write(master, b"\x02d")  # Detach through this owned viewer's PTY.
        probe.wait_terminal_exit(viewer, master, output, timeout=5)
        os.close(master)


@pytest.mark.parametrize("other_server", [False, True])
def test_attach_reads_writes_and_disconnects_from_recorded_server(servers, other_server):
    record, sockets = servers
    master, slave = pty.openpty()
    viewer = subprocess.Popen([record["launcher"]["script"], "attach"], stdin=slave, stdout=slave, stderr=slave,
                              env=viewer_environment(record, sockets, other_server=other_server), start_new_session=True)
    os.close(slave)
    output = bytearray()

    def see(marker):
        deadline = time.monotonic() + 5
        while marker not in output and time.monotonic() < deadline:
            if select.select([master], [], [], 0.05)[0]:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    pytest.fail(f"viewer closed before {marker!r}: {output!r}")
                assert chunk, output
                output.extend(chunk)
        assert marker in output, output

    try:
        see(b"AGENT-READY")
        assert b"WRONG-SERVER" not in output
        os.write(master, b"hello\n")
        see(b"received:hello")
        # Detach this viewer. The agent pane and the other server must survive.
        os.write(master, b"\x02d")
        assert probe.wait_terminal_exit(viewer, master, output, timeout=5) == 0
        assert tmux(sockets[0], "show-options", "-p", "-v", "-t", "%0", "@safeyolo_launch_id").stdout.strip() == record["launch_id"]
        assert "received:hello" in tmux(sockets[0], "capture-pane", "-p", "-t", "%0").stdout
        assert "WRONG-SERVER" in tmux(sockets[1], "capture-pane", "-p", "-t", "%0").stdout
    finally:
        os.close(master)
        if viewer.poll() is None:
            viewer.terminate()
        viewer.wait(timeout=5)


def test_missing_server_has_actionable_error_without_fallback(servers):
    record, sockets = servers
    tmux(sockets[0], "kill-server")
    result = subprocess.run([record["launcher"]["script"], "attach"], text=True, capture_output=True,
                            env=viewer_environment(record, sockets, other_server=True))
    assert result.returncode != 0
    assert f"Cannot reach agent pane %0 on tmux server {sockets[0]}" in result.stderr
    assert "WRONG-SERVER" in tmux(sockets[1], "capture-pane", "-p", "-t", "%0").stdout
