"""Execute the documented recovery recipe against the shipped PID-1 owner."""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest

from safeyolo import agent_command_supervisor as supervisor
from safeyolo.config import get_agent_command_supervisor_state_path, get_data_dir
from safeyolo.vm import get_agent_config_share_dir, get_agent_home_dir

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("vm_guest_probe_recipe", ROOT / "contrib/vm-guest-probe.py")
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)


@pytest.fixture
def staged_guest(tmp_config_dir, tmp_path):
    home = get_agent_home_dir("demo")
    home.mkdir(parents=True)
    config_share = get_agent_config_share_dir("demo")
    config_share.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source_dir = ROOT / "cli/src/safeyolo"
    artifact = config_share / "guest-command-supervisor.py"
    source = (source_dir / artifact.name).read_text()
    assert source.count('cwd="/workspace"') == 1
    artifact.write_text(source.replace('cwd="/workspace"', f"cwd={str(workspace)!r}"))
    artifact.chmod(0o755)
    state = get_agent_command_supervisor_state_path("demo")
    stop = state.with_name(".safeyolo-command-supervisor.stop")
    init = (source_dir / "guest-init-per-run.sh").read_text()
    owner = init[init.index("COMMAND_SUPERVISOR_PID="):init.index("# All per-run setup is complete.")]
    owner = owner.replace("/home/agent/.safeyolo-command-supervisor.json", str(state))
    owner = owner.replace("/home/agent/.safeyolo-command-supervisor.stop", str(stop))
    owner = owner.replace("/run/safeyolo/guest-command-supervisor.py", str(artifact))
    owner = owner.replace("/safeyolo/command-supervisor-enabled", str(config_share / "command-supervisor-enabled"))
    owner = owner.replace("setsid su agent -s /bin/bash -c", "setsid bash -c")
    script = tmp_path / "pid1-owner.sh"
    script.write_text(owner + "\nkeep_pid1_alive\n")
    return {"state": state, "stop": stop, "config": config_share, "script": script}


@pytest.fixture
def guest_owner(staged_guest):
    env = {**os.environ, "SAFEYOLO_COMMAND_SUPERVISOR_STATE": str(staged_guest["state"]),
           "SAFEYOLO_COMMAND_SUPERVISOR_STOP": str(staged_guest["stop"])}
    owner = subprocess.Popen(["/bin/bash", str(staged_guest["script"])], env=env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, start_new_session=True)
    try:
        yield owner
    finally:
        supervisor.request_command_supervisor_stop("demo")
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            state = supervisor.read_command_supervisor_state("demo")
            if not state or state["state"] in {"stopped", "failed"}:
                break
            time.sleep(0.05)
        os.killpg(owner.pid, signal.SIGTERM)
        owner.communicate(timeout=3)


def test_recipe_runs_once_through_guest_owner_without_shell(staged_guest, guest_owner):
    output = recipe.probe("demo")
    result = json.loads((output / "result.json").read_text())
    invocation = json.loads((output / "invocation.json").read_text())
    state = supervisor.read_command_supervisor_state("demo")
    assert result["uid"] == os.getuid()
    assert result["probe_id"] == invocation["probe_id"]
    assert "sshd_loopback" in result
    assert state["state"] == "stopped"
    assert state["restart_count"] == 0
    assert state["command_pid"] is None
    assert guest_owner.poll() is None
    assert staged_guest["stop"].exists()
    assert not (staged_guest["config"] / "command-supervisor-enabled").exists()
    assert output.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in output.iterdir())
    time.sleep(0.3)
    assert supervisor.read_command_supervisor_state("demo") == state


@pytest.mark.parametrize("fenced", [False, True])
def test_recipe_refuses_occupied_supervisor_even_with_stop_fence(staged_guest, fenced):
    supervisor.start_command_supervisor("demo", "exec worker --resume checkpoint")
    if fenced:
        staged_guest["stop"].write_text("existing fence")
    original = staged_guest["state"].read_bytes()
    with pytest.raises(RuntimeError, match="occupied or unverified"):
        recipe.probe("demo")
    assert staged_guest["state"].read_bytes() == original
    assert (staged_guest["config"] / "command-supervisor-enabled").exists()
    assert staged_guest["stop"].exists() is fenced


def test_recipe_timeout_fences_only_its_command_and_records_unverified_state(staged_guest):
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="completion is unverified"):
        recipe.probe("demo", timeout=0.2)
    assert time.monotonic() - started < 1
    output, = (get_data_dir() / "vm-recovery").iterdir()
    assert not (output / "result.json").exists()
    assert json.loads((output / "supervisor-state.json").read_text())["state"] == "starting"
    assert staged_guest["stop"].exists()
    assert not (staged_guest["config"] / "command-supervisor-enabled").exists()


def test_recipe_lock_wait_has_same_deadline(staged_guest):
    # The ordinary launcher uses this lock too. Hold it in another process
    # to prove the emergency command does not wait indefinitely on setup.
    script = "from safeyolo.commands.agent import _agent_host_setup_lock; import time; "
    script += "\nwith _agent_host_setup_lock('demo'):\n print('locked', flush=True)\n time.sleep(5)\n"
    child = subprocess.Popen([os.sys.executable, "-c", script], stdout=subprocess.PIPE)
    try:
        assert child.stdout.readline() == b"locked\n"
        started = time.monotonic()
        with pytest.raises(RuntimeError, match="deadline expired"):
            recipe.probe("demo", timeout=0.2)
        assert time.monotonic() - started < 1
        assert not staged_guest["state"].exists()
    finally:
        child.terminate()
        child.wait(timeout=3)


def test_recipe_preserves_replacement_owner(staged_guest, monkeypatch):
    def replaced(*_args):
        supervisor._write_json(staged_guest["state"], supervisor._base_state("demo", "exec replacement"))
        raise RuntimeError("supervisor ownership changed")

    monkeypatch.setattr(recipe, "wait_for_result", replaced)
    with pytest.raises(RuntimeError, match="ownership changed"):
        recipe.probe("demo")
    assert supervisor.read_command_supervisor_state("demo")["command"] == "exec replacement"
    assert not staged_guest["stop"].exists()


def test_recipe_rejects_absent_guest_without_creating_supervisor(tmp_config_dir):
    with pytest.raises(RuntimeError, match="boot this agent first"):
        recipe.probe("demo")
    assert not get_agent_command_supervisor_state_path("demo").exists()
