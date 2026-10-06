"""Native shared-home recovery, deadlines and ownership at the host boundary.

The local result fixture executes the real native probe and supplies the guest
owner's terminal acknowledgement. Actual PID-1/systrap proof is a separate run.
"""

from __future__ import annotations

import fcntl
import json
import os
import signal
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GUEST = Path(os.environ.get("SAFEYOLO_GUEST_HELPER", ROOT / "guest/command/target/debug/safeyolo-guest"))
pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Selected native guest probe requires Linux")


def write_json(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value))
    temporary.chmod(0o600)
    temporary.replace(path)


@pytest.fixture
def staged_guest(native_agent):
    directory = native_agent["root"] / "agents/demo"
    home, share = directory / "home", directory / "config-share"
    home.mkdir(parents=True)
    share.mkdir()
    (share / "safeyolo-guest").write_bytes(GUEST.read_bytes())
    (share / "host-launch-context.json").write_text(json.dumps({"generation": "recovery-run"}))
    return {**native_agent, "directory": directory, "home": home, "share": share,
            "state": home / ".safeyolo-command-supervisor.json",
            "stop": home / ".safeyolo-command-supervisor.stop"}


def recover(guest, timeout=2):
    return subprocess.run([str(guest["cli"]), "--root", str(guest["root"]), "agent", "recover", "demo",
                           "--timeout", str(timeout)], capture_output=True, text=True, timeout=timeout + 3)


def published(guest):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if guest["state"].exists():
            state = json.loads(guest["state"].read_text())
            if state["command"].startswith("exec /safeyolo/safeyolo-guest probe "):
                return state
        time.sleep(0.01)
    raise AssertionError("host did not publish the recovery command")


@pytest.mark.parametrize("prior_terminal", [None, "stopped", "failed", "exited"])
def test_recipe_collects_real_probe_and_matching_guest_acknowledgement(staged_guest, prior_terminal):
    if prior_terminal:
        write_json(staged_guest["state"], {"schema_version": 1, "name": "demo", "command": "exec prior",
                                         "state": prior_terminal, "command_pid": None, "command_start_token": None})
        staged_guest["stop"].write_text("prior stop fence")
        (staged_guest["share"] / "command-supervisor-enabled").touch()
    with socket.socket() as listener, ThreadPoolExecutor(max_workers=1) as pool:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        future = pool.submit(recover, staged_guest)
        state = published(staged_guest)
        assert state["command"] == f"exec /safeyolo/safeyolo-guest probe {state['supervision_id']}"
        probe = subprocess.run([str(GUEST), "--stop", str(staged_guest["stop"]), "probe",
                                state["supervision_id"], "--ssh-port", str(listener.getsockname()[1])],
                               capture_output=True, text=True, timeout=3)
        assert probe.returncode == 0, probe.stderr
        result = json.loads(probe.stderr)
        assert result["sshd_loopback"]["received"] is False
        assert result["uid"] == os.getuid()
        state.update(state="stopped", last_stderr=probe.stderr,
                     last_stderr_truncated=False, last_exit_code=0, command_pid=None)
        write_json(staged_guest["state"], state)
        response = future.result(timeout=3)
    assert response.returncode == 0, response.stderr
    observed = json.loads(response.stdout)["guest_probe"]
    assert observed["generation"] == "recovery-run"
    assert observed["result"] == result
    assert staged_guest["state"].stat().st_mode & 0o777 == 0o600
    assert staged_guest["stop"].exists()
    assert not (staged_guest["share"] / "command-supervisor-enabled").exists()


@pytest.mark.parametrize("fenced", [False, True])
def test_recipe_refuses_occupied_supervisor_even_with_stop_fence(staged_guest, fenced):
    write_json(staged_guest["state"], {"schema_version": 1, "name": "demo", "command": "exec worker",
                                     "state": "running", "command_pid": 123})
    enabled = staged_guest["share"] / "command-supervisor-enabled"
    enabled.touch()
    if fenced:
        staged_guest["stop"].write_text("existing fence")
    original = staged_guest["state"].read_bytes()
    response = recover(staged_guest)
    assert response.returncode != 0 and "occupied or unverified" in response.stderr
    assert staged_guest["state"].read_bytes() == original
    assert enabled.exists()
    assert staged_guest["stop"].exists() is fenced


@pytest.mark.parametrize("terminal", ["stopped", "failed", "exited"])
@pytest.mark.parametrize(("pid", "token"), [
    (None, "retained-start-token"),
    (os.getpid(), None),
    (os.getpid(), "retained-start-token"),
    (0, "retained-start-token"),
    (-1, "retained-start-token"),
    (2**31, "retained-start-token"),
    (2**64 - 1, "retained-start-token"),
    (1.5, "retained-start-token"),
    (True, "retained-start-token"),
    ("123", "retained-start-token"),
    ([], "retained-start-token"),
    ({}, "retained-start-token"),
    (None, ""),
    (None, 123),
    (None, True),
    (None, []),
    (None, {}),
])
def test_recipe_preserves_unverified_terminal_identity_and_markers(staged_guest, terminal, pid, token):
    write_json(staged_guest["state"], {"schema_version": 1, "name": "demo", "command": "exec existing",
                                     "state": terminal, "command_pid": pid, "command_start_token": token})
    enabled = staged_guest["share"] / "command-supervisor-enabled"
    enabled.write_text("existing enabled marker")
    staged_guest["stop"].write_text("existing stop fence")
    original = staged_guest["state"].read_bytes()
    response = recover(staged_guest, timeout=0.2)
    assert response.returncode != 0 and "occupied or unverified" in response.stderr
    assert staged_guest["state"].read_bytes() == original
    assert enabled.read_text() == "existing enabled marker"
    assert staged_guest["stop"].read_text() == "existing stop fence"


def test_recipe_timeout_fences_its_command_without_claiming_termination(staged_guest):
    started = time.monotonic()
    response = recover(staged_guest, timeout=0.2)
    assert response.returncode != 0 and "completion is unverified" in response.stderr
    assert time.monotonic() - started < 1
    assert published(staged_guest)["state"] == "starting"
    assert staged_guest["stop"].exists()
    assert not (staged_guest["share"] / "command-supervisor-enabled").exists()


@pytest.mark.parametrize("lock", ["host-setup.lock", "current-launch.lock"])
def test_recipe_lock_wait_has_same_deadline(staged_guest, lock):
    path = staged_guest["directory"] / lock
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        started = time.monotonic()
        response = recover(staged_guest, timeout=0.2)
    assert response.returncode != 0 and "deadline expired" in response.stderr
    assert time.monotonic() - started < 1
    assert not staged_guest["state"].exists()


def test_recipe_preserves_replacement_owner(staged_guest):
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(recover, staged_guest)
        state = published(staged_guest)
        state.update(command="exec replacement", supervision_id="replacement-owner")
        write_json(staged_guest["state"], state)
        response = future.result(timeout=3)
    assert response.returncode != 0 and "ownership changed" in response.stderr
    assert json.loads(staged_guest["state"].read_text())["command"] == "exec replacement"
    assert not staged_guest["stop"].exists()
    assert (staged_guest["share"] / "command-supervisor-enabled").exists()


def test_terminal_label_does_not_hide_a_remaining_command(staged_guest):
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(recover, staged_guest)
        state = published(staged_guest)
        state.update(state="failed", command_pid=os.getpid(), command_start_token="still-occupied",
                     last_exit_code=0, last_stderr=json.dumps({"probe_id": state["supervision_id"]}))
        write_json(staged_guest["state"], state)
        response = future.result(timeout=3)
    assert response.returncode != 0 and "completion is unverified" in response.stderr
    assert json.loads(staged_guest["state"].read_text())["command_pid"] == os.getpid()
    assert staged_guest["stop"].exists()


def test_recipe_rejects_absent_guest_without_creating_supervisor(native_agent):
    directory = native_agent["root"] / "agents/demo"
    original_files = set(directory.iterdir())
    configuration = native_agent["root"] / "config.toml"
    original_configuration = configuration.read_bytes()
    assert not (directory / "home").exists()
    response = recover(native_agent)
    assert response.returncode != 0 and "boot this agent first" in response.stderr
    assert set(directory.iterdir()) == original_files
    assert configuration.read_bytes() == original_configuration


def test_probe_output_block_retains_its_hard_deadline(tmp_path):
    read_fd, write_fd = os.pipe()
    try:
        os.set_blocking(write_fd, False)
        with pytest.raises(BlockingIOError):
            while True:
                os.write(write_fd, b"x" * 4096)
        os.set_blocking(write_fd, True)
        started = time.monotonic()
        child = subprocess.Popen([str(GUEST), "--stop", str(tmp_path / "stop"), "probe", "a" * 32],
                                 stderr=write_fd)
        try:
            assert child.wait(timeout=3) == -signal.SIGALRM
            assert time.monotonic() - started < 3
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)
    finally:
        os.close(read_fd)
        os.close(write_fd)
