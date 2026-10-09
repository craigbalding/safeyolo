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
If validation or cleanup fails, the JSON retains the captured operands and
cleanup observations, and the process exits nonzero.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shlex
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


def process_observation(raw: dict, boot_id: str) -> dict:
    """Read the same Linux birth operand as the native guest helper."""
    pid, tail = raw["stat"].rsplit(")", 1)
    fields = tail.split()
    status = dict(line.split(":", 1) for line in raw["status"].splitlines())
    return {"pid": int(pid.split("(", 1)[0]), "parent_pid": int(fields[1]),
            "state": fields[0], "start_token": f"{boot_id.strip()}:{fields[19]}",
            "start_ticks": int(fields[19]), "uids": [int(uid) for uid in status["Uid"].split()],
            "argv": raw["cmdline"].rstrip("\0").split("\0")}


def proc_command(pids: list[int], output: str = "/home/agent/.g7/proc") -> str:
    """Copy only the selected live process operands into the shared fixture home."""
    assert all(type(pid) is int and pid > 0 for pid in pids)
    return f"""out={shlex.quote(output)}
mkdir -p "$out" || exit 1
failed=0
cat /proc/sys/kernel/random/boot_id > "$out/boot_id" || failed=1
for pid in {' '.join(map(str, pids))}; do
    for file in stat status cmdline; do
        cat "/proc/$pid/$file" > "$out/$pid.$file" || failed=1
    done
done
exit "$failed"
"""


def observe(result: dict) -> None:
    """Bind the live guest result to this run, executable and canonical caller."""
    assert not result["capture_errors"], result["capture_errors"]
    files = result["guest_files"]
    status, context, grant = result["status"], result["context"], result["grant"]
    identities = result["executables"]

    def load(name):
        return json.loads(files[name])

    assert "complete" in files, "guest marker did not complete"
    assert files["uid"].strip() == "1000"
    assert int(files["per-run-started"]) > 0
    assert files["vm-status"].strip() == "ready"
    for name in ("guest", "coord"):
        assert files[f"{name}.version"].strip() == identities[name]
    generation = status["run_id"]
    assert generation and status["runtime_state"] == "running" and status["control_state"] == "ready"
    assert status["agent_state"] == "running" and status["launcher"]["kind"] == "supervisor", status
    assert context["generation"] == load("context.json")["generation"] == generation
    state = load("supervision.json")
    current = result["current_supervisor"]
    launch = result["current_launch"]
    assert launch["launch_id"] == status["launch_id"] and launch["agent_id"] == status["agent_id"]
    assert launch["launcher"]["kind"] == "supervisor"
    assert result["guest_checks"]["observe"]["exit_code"] == 0
    assert result["guest_checks"]["observe"]["stdout"].strip() == "running"
    assert result["guest_checks"]["supervise"]["exit_code"] == 0
    checked = json.loads(result["guest_checks"]["supervise"]["stdout"])
    for key in ("generation", "supervision_id", "command_pid", "command_start_token",
                "supervisor_pid", "supervisor_start_token", "supervisor_parent_pid", "supervisor_uid"):
        assert state[key] == current[key] == checked[key], (key, state, current, checked)
    assert state["generation"] == generation and state["supervision_id"] == status["launch_id"]
    assert state["state"] == current["state"] == checked["state"] == "running"
    assert state["runtime_owner"] == checked["runtime_owner"] == "guest-pid1"
    assert state["supervisor_uid"] == 1000
    assert state["guest_helper_version"] == identities["guest"]
    processes = result["guest_processes"]
    live = {pid: process_observation(raw, processes["boot_id"])
            for pid, raw in processes["processes"].items()}
    result["guest_ancestry"] = live
    for subject in ("command", "supervisor"):
        assert type(state[subject + "_pid"]) is int and state[subject + "_pid"] > 1
        process = live[str(state[subject + "_pid"])]
        assert process["pid"] == state[subject + "_pid"] and process["state"] not in ("Z", "X")
        assert process["start_token"] == state[subject + "_start_token"]
        assert process["uids"][:2] == [1000, 1000]
    supervisor = live[str(state["supervisor_pid"])]
    assert supervisor["parent_pid"] == state["supervisor_parent_pid"]
    helper_path = supervisor["argv"][0]
    assert helper_path in ("/run/safeyolo/safeyolo-guest", "/safeyolo/safeyolo-guest")
    assert supervisor["argv"][1:] == ["supervise"]
    parent, init = live[str(supervisor["parent_pid"])], live["1"]
    assert init["pid"] == 1 and init["parent_pid"] == 0 and init["uids"][:2] == [0, 0]
    assert init["state"] not in ("Z", "X")
    if parent["pid"] != 1:
        # Hardware PID 1 retains su; setpriv on gVisor execs the supervisor.
        assert parent["parent_pid"] == 1 and parent["uids"][:2] == [0, 0]
        assert parent["state"] not in ("Z", "X")
        assert Path(parent["argv"][0]).name == "su"
        assert parent["argv"][1:] == ["agent", "-s", "/bin/bash", "-c",
                                       f"exec '{helper_path}' supervise"]
    assert init["start_ticks"] <= parent["start_ticks"] <= supervisor["start_ticks"]
    command = live[str(state["command_pid"])]
    assert command["parent_pid"] == supervisor["pid"] and command["start_ticks"] >= supervisor["start_ticks"]
    joined, response, read = load("join.json"), load("send.json"), load("read.json")
    sent = response["envelope"]
    assert joined["room_id"] == grant["room_id"]
    assert joined["room_name"] == result["room"]
    assert sent["body"] == result["marker"] and sent["sender_kind"] == "agent"
    assert sent["sender_agent_name"] == "g7" and sent["sender_agent_id"] == grant["agent_id"] == status["agent_id"]
    assert sent["origin_instance_id"] == result["instance_id"] and sent["content_type"] == "text/plain"
    assert sent["msg_id"] and type(response["sequence"]) is int and response["sequence"] == 1
    assert response["attention_intent"] == {"mode": "none"}
    assert read["messages"] == result["host_history"], "guest result and independent host history differ"
    assert len(read["messages"]) == 1
    message = dict(read["messages"][0])
    assert message.pop("attention_intent") == {"mode": "none", "agent_ids": []}
    assert message == {**sent, "sequence": response["sequence"]}, "canonical message fields differ"
    result["envelope"] = sent
    helper = result["vz_helper"]
    assert helper["private_control"]["helper"]["git_sha"] == result["installed_commit"]
    assert helper["private_control"]["helper"]["architecture"] == "arm64"
    assert helper["start_token"], "owned VZ helper OS birth is unavailable"


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

    def command(*parts, timeout=90, check=True):
        return subprocess.run([str(cli), "--root", str(root), *parts], check=check,
                              capture_output=True, text=True, timeout=timeout)

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
    result = {"installed_commit": args.commit, "profile": args.profile,
              "room": room, "marker": marker, "executables": identities,
              "capture_errors": [], "commands": {}, "guest_files": {}, "guest_checks": {}}

    def capture_command(records, name, *parts, errors=None, timeout=30):
        errors = result["capture_errors"] if errors is None else errors
        record = records[name] = {"observed_at": time.time(), "command": list(parts)}
        try:
            completed = command(*parts, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as error:
            # TimeoutExpired retains bytes even when subprocess text mode is selected.
            record.update(exit_code=None, error=str(error),
                          stdout=(error.stdout or b"").decode(errors="replace"),
                          stderr=(error.stderr or b"").decode(errors="replace"))
            errors.append(f"{name}: {error}")
        except OSError as error:
            record.update(exit_code=None, error=str(error))
            errors.append(f"{name}: {error}")
        else:
            record.update(exit_code=completed.returncode, stdout=completed.stdout, stderr=completed.stderr)
            if completed.returncode:
                errors.append(f"{name}: exit {completed.returncode}")
        return record

    def capture_file(records, name, path, *, structured=False):
        try:
            records[name] = path.read_text()
            if structured:
                records[name] = json.loads(records[name])
        except (OSError, ValueError) as error:
            result["capture_errors"].append(f"{path}: {error}")

    def decode_command(name, record, *, lines=False):
        if "stdout" not in record:
            return
        try:
            result[name] = ([json.loads(line) for line in record["stdout"].splitlines()]
                            if lines else json.loads(record["stdout"]))
        except ValueError as error:
            result["capture_errors"].append(f"{name}: {error}")

    try:
        command("agent", "create", "g7", "--workspace", str(workspace), "--launcher", "supervisor",
                "--host-script", str(Path(__file__).with_name("g7-vz-host-setup.sh").resolve()))
        result["setup"] = setup_observation(root)
        command("coord", "start", "--binary", str(nats), "--client-port", "46370", "--monitor-port", "46372")
        command("coord", "room", "create", room)
        result["grant"] = json.loads(command("coord", "grant", room, "g7").stdout)
        command("start")
        command("agent", "start", "g7", "--", room, marker, timeout=180)
        home = root / "agents/g7/home"
        deadline = time.monotonic() + 30
        while not (home / ".g7/complete").exists():
            if time.monotonic() >= deadline:
                break  # Capture the live failure operands before validation and cleanup.
            time.sleep(0.1)
        result["capture_started_at"] = time.time()
        decode_command("status", capture_command(result["commands"], "status", "agent", "status", "g7"))
        for name, path in (("context", root / "agents/g7/config-share/host-launch-context.json"),
                           ("current_launch", root / "agents/g7/current-launch.json"),
                           ("current_supervisor", home / ".safeyolo-command-supervisor.json")):
            capture_file(result, name, path, structured=True)
        result["records_captured_at"] = time.time()
        capture_file(result, "instance_id", root / "data/instance_id")
        if "instance_id" in result:
            result["instance_id"] = result["instance_id"].strip()
        for name in ("complete", "uid", "per-run-started", "vm-status", "guest.version", "coord.version",
                     "context.json", "supervision.json", "join.json", "send.json", "read.json"):
            capture_file(result["guest_files"], name, home / ".g7" / name)
        decode_command("host_history", capture_command(result["commands"], "history", "coord", "history",
                                                        room, "--since", "0"), lines=True)
        helper = capture_command(result["commands"], "helper_dump", "agent", "diagnostics", "g7", "dump")
        decode_command("vz_helper", helper)
        if isinstance(result.get("vz_helper"), dict):
            helper = result["vz_helper"]
            pid = helper.get("pid")
            result["vz_helper"] = {"private_control": helper,
                                   "start_token": _process_start_token(pid) if type(pid) is int and pid > 1 else None,
                                   "observed_at": time.time()}
        for subject in ("observe", "supervise"):
            capture_command(result["guest_checks"], subject, "agent", "shell", "g7", "-c",
                            f"/safeyolo/safeyolo-guest {subject} check", timeout=10)
        state = result.get("current_supervisor")
        pids = [1]
        if isinstance(state, dict):
            pids.extend(state.get(key) for key in ("supervisor_pid", "supervisor_parent_pid", "command_pid")
                        if type(state.get(key)) is int and state[key] > 1)
        pids = list(dict.fromkeys(pids))
        capture_command(result["guest_checks"], "proc", "agent", "shell", "g7", "-c", proc_command(pids), timeout=10)
        processes = result["guest_processes"] = {"processes": {}}
        capture_file(processes, "boot_id", home / ".g7/proc/boot_id")
        for pid in pids:
            raw = processes["processes"][str(pid)] = {}
            for name in ("stat", "status", "cmdline"):
                capture_file(raw, name, home / ".g7/proc" / f"{pid}.{name}")
        result["capture_completed_at"] = time.time()
        observe(result)
    finally:
        original_error = sys.exc_info()[1]
        # Save checked command operands before cleanup runs other commands.
        command_failure = {}
        if isinstance(original_error, (subprocess.CalledProcessError, subprocess.TimeoutExpired)):
            command_failure.update(command=original_error.cmd,
                                   exit_code=getattr(original_error, "returncode", None))
            for stream in ("stdout", "stderr"):
                output = getattr(original_error, stream) or ""
                command_failure[stream] = output.decode(errors="replace") if isinstance(output, bytes) else output
            if isinstance(original_error, subprocess.TimeoutExpired):
                command_failure["timeout"] = original_error.timeout
        failures = []
        processes = []
        cleanup = result["cleanup"] = {"started_at": time.time(), "commands": {}}
        try:
            processes = owned_processes(root)
        except (OSError, ValueError, KeyError) as error:
            failures.append(f"owned process inspection: {error}")
        for parts in (("agent", "stop", "g7"), ("stop",), ("coord", "stop"), ("agent", "cleanup", "g7")):
            capture_command(cleanup["commands"], " ".join(parts), *parts, errors=failures, timeout=90)
        try:
            cleanup["survivors"] = surviving_processes(processes)
            failures.extend(cleanup["survivors"])
        except (OSError, ValueError) as error:
            failures.append(f"owned process cleanup inspection: {error}")
        remaining = []
        for pattern in ("agents/g7/vm.pid", "agents/g7/vm-control.sock", "data/vm-control/g7.sock", "data/shell-sockets/g7.sock",
                        "data/ready.json", "data/sockets/*/proxy.sock", "data/coord/nats/process.json"):
            remaining.extend(str(path) for path in root.glob(pattern))
        failures.extend(remaining)
        cleanup.update(owned_processes=processes, remaining_runtime_paths=remaining,
                       failures=failures, completed_at=time.time())
        if failures:
            if original_error is None:
                original_error = AssertionError(failures)
            else:
                original_error.add_note(f"G7 owned cleanup also failed: {failures}")
        if original_error is not None:
            result["failure"] = {"type": type(original_error).__name__, "message": str(original_error),
                                 **command_failure}
            print(json.dumps(result))
            if sys.exc_info()[1] is None:
                raise original_error
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
