#!/usr/bin/env python3
"""Observe one installed native VZ setup, supervised marker and guest API exchange.

Run as the approved physical Mac account from this trusted checkout with
Python 3.11 or later. Supply a fresh, short disposable --root prepared by the
native installer, an empty owned --workspace, matching --commit/--profile
host and Linux guest artifacts, and owned pinned NATS inputs. No proxy or guest
may already be running in that root. Set the approved VZ test runner/deadline,
filtered-environment CA variables and SAFEYOLO_NATS_TEST_INSTANCE before
running. Reserve the approved NATS client/monitor ports 46370/46372 and prepare
the root's Admin API on 46371. The root's installation and setup script must be outside its
guest-writable workspace. This driver creates only g7 and one private fixture
room, boots that guest, checks actual native results, then stops and cleans
the owned guest, proxy and Coord. It neither launches a model nor proves G1
recovery or a final platform suite. Its nonsecret result is printed as JSON.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
import tomllib
import uuid
from pathlib import Path

if __package__:
    from .installed_host_smoke import _process_start_token
    from .installed_sections import owned_processes, surviving_processes
else:
    from installed_host_smoke import _process_start_token
    from installed_sections import owned_processes, surviving_processes


def setup_observation(root: Path) -> dict:
    home = root / "agents/g7/home"
    config = tomllib.loads((home / ".codex/config.toml").read_text())
    launcher = "/home/agent/.safeyolo/safeyolo-coord-mcp-launcher"
    assert config["mcp_servers"]["safeyolo-coord"]["command"] == launcher
    assert (home / ".safeyolo/AGENTS.md").read_bytes() == (root / "assets/docs/AGENTS.md").read_bytes()
    skill = home / ".agents/skills/safeyolo"
    assert skill.is_symlink() and os.readlink(skill) == "/safeyolo/skills/safeyolo"
    assert (home / ".g7-codex-command").read_bytes() == (root / "assets/contrib/codex-command.sh").read_bytes()
    assert not (home / ".codex/auth.json").exists(), "fixture must remain nonsecret"
    modes = {}
    for relative, expected in ((".codex", 0o700), (".codex/config.toml", 0o600),
                               (".g7-codex-command", 0o755), (".safeyolo-command", 0o755),
                               (".safeyolo/safeyolo-coord", 0o755),
                               (".safeyolo/safeyolo-coord-mcp-launcher", 0o755)):
        modes[relative] = (home / relative).stat().st_mode & 0o777
        assert modes[relative] == expected, (relative, modes[relative])
    staged = home / ".safeyolo/safeyolo-coord"
    with staged.open("rb") as stream:
        assert hashlib.file_digest(stream, "sha256").hexdigest() == (
            root / "assets/guest/safeyolo-coord.sha256").read_text().strip()
    return {"mcp_command": launcher, "modes": modes, "ordinary_command_preserved": True}


def observe(home: Path, status: dict, context: dict, grant: dict, instance: str,
            marker: str, history: list, identities: dict) -> dict:
    """Bind the live guest result to this run, executable and canonical caller."""
    output = home / ".g7"
    def load(name):
        return json.loads((output / name).read_text())

    assert (output / "complete").is_file()
    assert (output / "uid").read_text().strip() == "1000"
    assert int((output / "per-run-started").read_text()) > 0
    assert (output / "vm-status").read_text().strip() == "ready"
    for name in ("guest", "coord"):
        assert (output / f"{name}.version").read_text().strip() == identities[name]
    generation = status["run_id"]
    assert generation and status["runtime_state"] == "running" and status["control_state"] == "ready"
    assert status["agent_state"] == "running" and status["launcher"]["kind"] == "supervisor"
    assert context["generation"] == load("context.json")["generation"] == generation
    state = load("supervision.json")
    current = json.loads((home / ".safeyolo-command-supervisor.json").read_text())
    for key in ("generation", "supervision_id", "command_pid", "command_start_token",
                "supervisor_pid", "supervisor_start_token"):
        assert state[key] == current[key], (key, state, current)
    assert state["generation"] == generation and state["supervision_id"] == status["launch_id"]
    assert state["state"] == current["state"] == "running"
    assert state["supervisor_parent_pid"] == 1 and state["supervisor_uid"] == 1000
    assert state["guest_helper_version"] == identities["guest"]
    for subject in ("command", "supervisor"):
        assert type(state[subject + "_pid"]) is int and state[subject + "_pid"] > 1
        assert state[subject + "_start_token"]
    joined, sent, read = load("join.json"), load("send.json")["envelope"], load("read.json")
    assert joined["room_id"] == grant["room_id"]
    assert sent["body"] == marker and sent["sender_kind"] == "agent"
    assert sent["sender_agent_name"] == "g7" and sent["sender_agent_id"] == grant["agent_id"] == status["agent_id"]
    assert sent["origin_instance_id"] == instance and sent["content_type"] == "text/plain"
    assert sent["msg_id"] and sent["sequence"] == 1
    assert read["messages"] == history == [sent], "guest result and independent host history differ"
    return {"status": status, "supervision": state, "per_run_started": int((output / "per-run-started").read_text()),
            "executables": identities, "envelope": sent, "host_history": history}


def run(args) -> dict:
    assert sys.platform == "darwin" and platform.machine() == "arm64", "requires physical Apple Silicon"
    root, workspace = args.root.resolve(), args.workspace.resolve()
    assert len(os.fsencode(root / "agents/g7/vm-control.sock")) < 104, "use a short owned root"
    assert not list(root.glob("agents/*")), "use a fresh disposable root"
    assert workspace.is_dir() and not list(workspace.iterdir()), "use an empty owned workspace"
    assert not owned_processes(root), "the disposable root has live processes"
    assert os.environ["SAFEYOLO_NATS_TEST_INSTANCE"]
    assert int(os.environ["SAFEYOLO_VZ_TEST_TIMEOUT_SECONDS"]) > 0
    assert Path(os.environ["SAFEYOLO_VZ_TEST_RUNNER"]).is_file()
    nats = root / "data/coord/nats/bin/2.14.5/nats-server"
    assert nats.is_file(), "copy only the retained pinned NATS binary into the disposable root"
    os.environ["SAFEYOLO_COORD_DATA_DIR"] = str(root / "data/coord")
    os.environ["SAFEYOLO_LOGS_DIR"] = str(root / "logs")
    cli = root / "bin/safeyolo"

    def command(*parts, timeout=90):
        return subprocess.run([str(cli), "--root", str(root), *parts], check=True,
                              capture_output=True, text=True, timeout=timeout).stdout

    identities = {}
    for name in ("safeyolo", "safeyolo-proxy", "safeyolo-coord"):
        version = subprocess.check_output([str(root / "bin" / name), "--version"], text=True).strip()
        assert f"commit={args.commit} profile={args.profile}" in version, version
        identities[name] = version
    for label, name in (("guest", "safeyolo-guest"), ("coord", "safeyolo-coord")):
        binary = root / "assets/guest" / name
        version = binary.with_suffix(".version").read_text().strip()
        assert f"commit={args.commit} profile={args.profile}" in version, version
        with binary.open("rb") as stream:
            assert hashlib.file_digest(stream, "sha256").hexdigest() == binary.with_suffix(".sha256").read_text().strip()
        identities[label] = version
    room, marker = "g7-" + uuid.uuid4().hex, "G7:" + uuid.uuid4().hex
    result = None
    try:
        command("agent", "create", "g7", "--workspace", str(workspace), "--launcher", "supervisor",
                "--host-script", str(Path(__file__).with_name("g7-vz-host-setup.sh").resolve()))
        setup = setup_observation(root)
        command("coord", "start", "--binary", str(nats), "--client-port", "46370", "--monitor-port", "46372")
        command("coord", "room", "create", room)
        grant = json.loads(command("coord", "grant", room, "g7"))
        command("start")
        command("agent", "start", "g7", "--", room, marker, timeout=180)
        home = root / "agents/g7/home"
        deadline = time.monotonic() + 30
        while not (home / ".g7/complete").exists():
            assert time.monotonic() < deadline, "guest marker did not complete; inspect owned logs"
            time.sleep(0.1)
        status = json.loads(command("agent", "status", "g7"))
        context = json.loads((root / "agents/g7/config-share/host-launch-context.json").read_text())
        history = [json.loads(line) for line in command("coord", "history", room, "--since", "0").splitlines()]
        result = {"setup": setup, **observe(home, status, context, grant,
                  (root / "data/instance_id").read_text().strip(), marker, history, identities)}
        helper = json.loads(command("agent", "diagnostics", "g7", "dump"))
        assert helper["helper"]["git_sha"] == args.commit and helper["helper"]["architecture"] == "arm64"
        helper_birth = _process_start_token(helper["pid"])
        assert helper_birth, "owned VZ helper OS birth is unavailable"
        result["vz_helper"] = {"private_control": helper, "start_token": helper_birth}
    finally:
        original_error = sys.exc_info()[1]
        failures = []
        processes = []
        try:
            processes = owned_processes(root)
        except (OSError, ValueError, KeyError) as error:
            failures.append(f"owned process inspection: {error}")
        for parts in (("agent", "stop", "g7"), ("stop",), ("coord", "stop"), ("agent", "cleanup", "g7")):
            try:
                command(*parts)
            except (OSError, subprocess.SubprocessError) as error:
                failures.append(f"{' '.join(parts)}: {error}")
        try:
            failures.extend(surviving_processes(processes))
        except (OSError, ValueError) as error:
            failures.append(f"owned process cleanup inspection: {error}")
        for pattern in ("agents/g7/vm.pid", "agents/g7/vm-control.sock", "data/vm-control/g7.sock", "data/shell-sockets/g7.sock",
                        "data/ready.json", "data/sockets/*/proxy.sock", "data/coord/nats/process.json"):
            failures.extend(str(path) for path in root.glob(pattern))
        if failures:
            if original_error is None:
                raise AssertionError(failures)
            original_error.add_note(f"G7 owned cleanup also failed: {failures}")
    assert result is not None
    result["cleanup"] = {"owned_processes": processes, "survivors": [], "owned_sockets_absent": True}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--profile", required=True, choices=("debug", "production"))
    print(json.dumps(run(parser.parse_args())))


if __name__ == "__main__":
    main()
