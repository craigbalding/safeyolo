"""The real-platform acceptance driver must behave like a reading terminal."""

import importlib.util
import json
import os
import pty
import subprocess
import sys
import threading
from pathlib import Path

import pytest

probe_path = Path(__file__).resolve().parents[2] / "tests/nested-linux/launcher_acceptance.py"
spec = importlib.util.spec_from_file_location("launcher_acceptance", probe_path)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


@pytest.mark.parametrize("duplicate_fresh_launch", [False, True])
def test_concurrent_command_creation_covers_absent_state(tmp_path, monkeypatch, duplicate_fresh_launch):
    """Drive the real scheduling and assertions with a controlled start consumer."""
    commit = "1" * 40
    (tmp_path / "config.toml").write_text("")
    states, workspaces, start_entries = {}, {}, []
    barrier, lock = threading.Barrier(2), threading.Lock()

    class ReachedViewers(Exception):
        """The focused check ends before opening a real terminal."""

    def version(command, **kwargs):
        return f"{Path(command[0]).name} 0.1.0 commit={commit} profile=production\n"

    def run(command, **kwargs):
        if command[0] == "tmux":
            return subprocess.CompletedProcess(command, 0, "controlled-socket\n", "")
        arguments = command[3:]
        if arguments == ["status"]:
            return subprocess.CompletedProcess(command, 0, json.dumps({"proxy_state": "running"}), "")
        action, selected = arguments[1:3]
        if action == "create":
            workspaces[selected] = Path(arguments[arguments.index("--workspace") + 1])
            states[selected] = {"agent_id": selected + "-agent", "run_id": selected + "-run", "runtime_state": "stopped",
                                "control_state": "ready", "agent_state": "stopped", "terminal_state": "absent"}
            directory = tmp_path / "agents" / selected
            directory.mkdir(parents=True)
            (directory / "runtime.json").write_text("{}")
        elif action == "configure":
            states[selected]["launcher"] = {"source": "agent"}
        elif action == "status":
            return subprocess.CompletedProcess(command, 0, json.dumps(states[selected]), "")
        elif action == "attach":
            return subprocess.CompletedProcess(command, 1, "", "terminal absent")
        elif action == "shell":
            return subprocess.CompletedProcess(command, 0, version(["safeyolo-guest"]), "")
        elif action == "start" and "--sandbox-only" in arguments:
            states[selected]["runtime_state"] = "running"
        elif action == "start":
            with lock:
                was_running = states[selected]["agent_state"] == "running"
                start_entries.append((selected, was_running))
            # Synchronize both callers before either can create a missing command.
            barrier.wait(timeout=5)
            with lock:
                if not was_running and (duplicate_fresh_launch or states[selected]["agent_state"] != "running"):
                    workspace = workspaces[selected]
                    starts = workspace / "starts"
                    number = len(starts.read_text().splitlines()) + 1 if starts.exists() else 1
                    with starts.open("a") as stream:
                        stream.write(f"command-{number}\n")
                    launch_id = selected + f"-launch-{number}"
                    states[selected].update(runtime_state="running", agent_state="running", launch_id=launch_id)
                    if states[selected].get("launcher", {}).get("source") != "agent":
                        states[selected]["launcher"] = {"source": "host default"}
                        hook_file = workspace.parent / "hooks"
                        with hook_file.open("a") as stream:
                            stream.write(f"{launch_id} pre_launch\n{launch_id} post_launch\n")
                    (tmp_path / "agents" / selected / "current-launch.json").write_text(
                        json.dumps({"tmux_socket": "controlled-socket", "pane_id": selected,
                                    "pid": number, "process_token": f"birth-{number}",
                                    "runner_pid": number + 10, "runner_token": f"runner-{number}"})
                    )
        elif action in ("stop", "cleanup"):
            states[selected].update(runtime_state="stopped", agent_state="stopped", run_id=None)
        else:
            raise AssertionError(f"unexpected controlled command: {command}")
        return subprocess.CompletedProcess(command, 0, "", "")

    def reached_viewers():
        raise ReachedViewers

    monkeypatch.setattr(sys, "argv", [str(probe_path), "--root", str(tmp_path),
                                     "--fixture-parent", str(tmp_path), "--commit", commit])
    monkeypatch.setattr(probe.shutil, "which", lambda _: "tmux")
    monkeypatch.setattr(probe.subprocess, "check_output", version)
    monkeypatch.setattr(probe.subprocess, "run", run)
    monkeypatch.setattr(probe.pty, "openpty", reached_viewers)
    if duplicate_fresh_launch:
        with pytest.raises(AssertionError, match="concurrent start duplicated the command"):
            probe.main()
    else:
        with pytest.raises(ReachedViewers):
            probe.main()
        main, peer = states
        assert sorted(start_entries[2:]) == sorted([(main, True), (peer, False)])
    main = next(iter(states))
    assert start_entries[:2] == [(main, False), (main, False)]


@pytest.mark.parametrize("output_size", [32, 256 * 1024])
def test_wait_drains_output_and_preserves_exit_code(tmp_path, output_size):
    master, slave = pty.openpty()
    marker = tmp_path / "drained"
    child = """
import sys, termios
from pathlib import Path
sys.stdout.write('x' * int(sys.argv[1]))
sys.stdout.flush()
termios.tcsetattr(0, termios.TCSADRAIN, termios.tcgetattr(0))
Path(sys.argv[2]).touch()
sys.exit(7)
"""
    process = subprocess.Popen([sys.executable, "-c", child, str(output_size), str(marker)],
                               stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
    os.close(slave)
    screen = bytearray()
    try:
        assert probe.wait_terminal_exit(process, master, screen, timeout=5) == 7
        assert screen == b"x" * output_size
        assert marker.is_file()
    finally:
        os.close(master)
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


def test_wait_does_not_mistake_output_for_exit():
    master, slave = pty.openpty()
    process = subprocess.Popen([sys.executable, "-c", "print('still running', flush=True); input()"],
                               stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
    os.close(slave)
    screen = bytearray()
    try:
        assert probe.read_terminal(master, screen, timeout=5)
        with pytest.raises(subprocess.TimeoutExpired):
            probe.wait_terminal_exit(process, master, screen, timeout=0.2)
        assert b"still running" in screen
        assert process.poll() is None
    finally:
        os.close(master)
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)


def test_probe_rejects_the_wrong_native_source_before_configuration_changes(native_agent):
    """A retained executable cannot be reported as a new journey candidate."""
    root = native_agent["root"]
    (root / "bin").mkdir()
    (root / "bin/safeyolo").symlink_to(native_agent["cli"].resolve())
    before = {path: path.read_bytes() for path in (root / "config.toml", root / "policy.toml")}
    result = subprocess.run(
        [sys.executable, str(probe_path), "--root", str(root), "--fixture-parent", str(root),
         "--commit", "0" * 40],
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode != 0 and "wrong installed source: bin/safeyolo" in result.stderr
    assert {path: path.read_bytes() for path in before} == before
    assert not list(root.glob("native-terminal-*"))
    assert not (root / "data/proxy-process.json").exists()


@pytest.mark.parametrize("different_profile", ["bin/safeyolo-proxy", "assets/guest/safeyolo-guest"])
def test_probe_rejects_mixed_installed_profiles_before_starting_an_agent(native_agent, different_profile):
    """Matching commits with different host/guest profiles are not one input."""
    root = native_agent["root"]
    cli = native_agent["cli"].resolve()
    version = subprocess.check_output([str(cli), "--version"], text=True).strip()
    identity = version.partition(" commit=")[2]
    commit = identity.split()[0]
    alternate = "production" if identity.endswith("profile=debug") else "debug"
    for relative in ("bin/safeyolo", "bin/safeyolo-proxy", "bin/safeyolo-coord",
                     "assets/guest/safeyolo-guest", "assets/guest/safeyolo-coord"):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative == "bin/safeyolo":
            path.symlink_to(cli)
            continue
        selected = f"{commit} profile={alternate}" if relative == different_profile else identity
        observed = f"{path.name} 0.1.0 commit={selected}"
        # Controlled version output tests the driver's input relationship;
        # no fake runtime is used as lifecycle acceptance.
        path.write_text(f"#!/bin/sh\nprintf '%s\\n' '{observed}'\n")
        path.chmod(0o755)
        path.with_suffix(".version").write_text(observed + "\n")
    before = {path: path.read_bytes() for path in (root / "config.toml", root / "policy.toml")}
    result = subprocess.run(
        [sys.executable, str(probe_path), "--root", str(root), "--fixture-parent", str(root), "--commit", commit],
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode != 0 and f"installed source/profile differs: {different_profile}" in result.stderr
    assert {path: path.read_bytes() for path in before} == before
    assert not list(root.glob("native-terminal-*"))
    assert not (root / "data/proxy-process.json").exists()
