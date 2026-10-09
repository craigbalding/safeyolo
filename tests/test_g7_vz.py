"""Challenge same-run native G7 observations before a physical witness is run."""

import copy
import hashlib
import json
import os
import subprocess
import sys
from argparse import Namespace
from pathlib import Path

import pytest

from tests.blackbox import installed_g7_vz
from tests.blackbox.installed_g7_vz import observe, proc_command, process_observation


def proc_row(pid, parent, uid, ticks, argv, *, comm="fixture"):
    fields = ["S", str(parent), str(pid), *(["0"] * 16), str(ticks), *(["0"] * 30)]
    return {"stat": f"{pid} ({comm}) {' '.join(fields)}\n",
            "status": f"Name:\t{comm}\nPid:\t{pid}\nPPid:\t{parent}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n",
            "cmdline": "\0".join(argv) + "\0"}


@pytest.fixture
def observation():
    identities = {"guest": "safeyolo-guest 0.1.0 commit=fixture profile=debug",
                  "coord": "safeyolo-coord 0.1.0 commit=fixture profile=debug"}
    state = {"state": "running", "generation": "run-current", "supervision_id": "launch-current",
             "command_pid": 1001, "command_start_token": "boot:185",
             "supervisor_pid": 1000, "supervisor_start_token": "boot:184",
             "supervisor_parent_pid": 997, "supervisor_uid": 1000,
             "runtime_owner": "guest-pid1", "guest_helper_version": identities["guest"]}
    context = {"generation": "run-current", "agent_id": "ag-g7", "workspace": "/owned/workspace"}
    envelope = {"msg_id": "msg-marker", "sent_at": 1791572062947, "origin_instance_id": "sy-instance",
                "sender_kind": "agent", "sender_agent_name": "g7", "sender_agent_id": "ag-g7",
                "content_type": "text/plain", "body": "G7:unique"}
    message = {**envelope, "sequence": 1, "attention_intent": {"mode": "none", "agent_ids": []}}
    # Send, join and read retain the native Agent API producer shapes.
    values = {"supervision.json": state, "context.json": context,
              "join.json": {"room_id": "rm-g7", "room_name": "g7-room", "permissions": ["receive", "send"],
                            "history_visibility": "retained",
                            "state": {"room_id": "rm-g7", "room_name": "g7-room",
                                      "origin_instance_id": "sy-instance",
                                      "members": [{"agent_id": "ag-g7", "display_name": "g7",
                                                   "origin_instance_id": "sy-instance"}]}},
              "send.json": {"envelope": envelope, "sequence": 1, "attention_status": "ready",
                            "attention_intent": {"mode": "none"}},
              "read.json": {"messages": [message], "next_cursor": 1, "history_truncated": False,
                            "oldest_available_at": None, "has_more": False}}
    files = {name: json.dumps(value) for name, value in values.items()}
    files.update({"uid": "1000\n", "per-run-started": "1791572062\n", "vm-status": "ready\n",
                  "guest.version": identities["guest"] + "\n", "coord.version": identities["coord"] + "\n",
                  "complete": ""})
    status = {"run_id": "run-current", "runtime_state": "running", "control_state": "ready",
              "agent_state": "running", "launcher": {"kind": "supervisor", "source": "agent"},
              "launch_id": "launch-current", "agent_id": "ag-g7", "error": None}
    return {"status": status, "context": context,
            "current_supervisor": copy.deepcopy(state),
            "current_launch": {"launch_id": "launch-current", "agent_id": "ag-g7",
                               "state": "managed", "launcher": {"kind": "supervisor"}},
            "grant": {"room_id": "rm-g7", "agent_id": "ag-g7"}, "instance_id": "sy-instance",
            "room": "g7-room", "marker": "G7:unique", "host_history": [copy.deepcopy(message)],
            "guest_files": files, "executables": identities, "capture_errors": [],
            "guest_checks": {"observe": {"exit_code": 0, "stdout": "running\n", "stderr": ""},
                             "supervise": {"exit_code": 0, "stdout": json.dumps(state), "stderr": ""}},
            "guest_processes": {"boot_id": "boot\n", "processes": {
                "1": proc_row(1, 0, 0, 1, ["/bin/bash", "/run/safeyolo/guest-init-per-run"]),
                "997": proc_row(997, 1, 0, 183, ["su", "agent", "-s", "/bin/bash", "-c",
                                                "exec '/safeyolo/safeyolo-guest' supervise"]),
                "1000": proc_row(1000, 997, 1000, 184, ["/safeyolo/safeyolo-guest", "supervise"]),
                "1001": proc_row(1001, 1000, 1000, 185, ["sleep", "300"])}},
            "installed_commit": "fixture", "profile": "debug",
            "vz_helper": {"private_control": {"pid": 2345, "helper": {"git_sha": "fixture", "architecture": "arm64"}},
                          "start_token": "darwin:2345:1:0"}}


@pytest.mark.parametrize("helper_path", ["/run/safeyolo/safeyolo-guest", "/safeyolo/safeyolo-guest"])
def test_same_run_observation_accepts_native_shapes_and_hardware_wrapper(observation, helper_path):
    processes = observation["guest_processes"]["processes"]
    processes["1000"]["cmdline"] = f"{helper_path}\0supervise\0"
    processes["997"]["cmdline"] = f"su\0agent\0-s\0/bin/bash\0-c\0exec '{helper_path}' supervise\0"
    observe(observation)
    assert observation["envelope"]["msg_id"] == "msg-marker"
    assert observation["guest_ancestry"]["997"]["start_token"] == "boot:183"


def test_direct_pid1_supervisor_is_also_supported(observation):
    data = json.loads(observation["guest_files"]["supervision.json"])
    data["supervisor_parent_pid"] = 1
    observation["guest_files"]["supervision.json"] = json.dumps(data)
    observation["current_supervisor"]["supervisor_parent_pid"] = 1
    observation["guest_checks"]["supervise"]["stdout"] = json.dumps(data)
    processes = observation["guest_processes"]["processes"]
    processes.pop("997")
    processes["1000"] = proc_row(1000, 1, 1000, 184, ["/safeyolo/safeyolo-guest", "supervise"])
    observe(observation)


@pytest.mark.parametrize("name,field,value", [
    ("context.json", "generation", "stale-run"),
    ("supervision.json", "supervisor_parent_pid", 88),
    ("supervision.json", "supervisor_uid", 0),
    ("supervision.json", "command_start_token", "stale-birth"),
    ("supervision.json", "supervision_id", "other-launch"),
    ("send.json", "origin_instance_id", "other-instance"),
    ("send.json", "sender_agent_id", "ag-other"),
    ("send.json", "msg_id", "other-message"),
    ("send.json", "sequence", 2),
    ("send.json", "sent_at", 1791572062948),
    ("send.json", "body", "other-marker"),
    ("send.json", "sender_kind", "operator"),
    ("join.json", "room_id", "other-room"),
    ("join.json", "room_name", "other-room"),
])
def test_stale_or_unrelated_guest_results_are_refused(observation, name, field, value):
    data = json.loads(observation["guest_files"][name])
    target = data["envelope"] if name == "send.json" and field != "sequence" else data
    target[field] = value
    observation["guest_files"][name] = json.dumps(data)
    with pytest.raises(AssertionError):
        observe(observation)


@pytest.mark.parametrize("name,value", [("uid", "0"), ("vm-status", "booting"),
                                        ("per-run-started", "0"), ("coord.version", "wrong-source")])
def test_initialization_and_executable_failures_are_refused(observation, name, value):
    observation["guest_files"][name] = value
    with pytest.raises(AssertionError):
        observe(observation)


@pytest.mark.parametrize("pid,change", [
    ("1000", {"ticks": 999}), ("1001", {"ticks": 999}),
    ("1000", {"uid": 0}), ("1001", {"uid": 0}),
    ("1000", {"parent": 1}), ("1001", {"parent": 1}),
    ("997", {"parent": 88}), ("997", {"uid": 1000}),
    ("997", {"argv": ["sleep", "300"]}),
    ("997", {"ticks": 999}), ("1", {"parent": 88}),
])
def test_live_birth_uid_and_pid1_ownership_are_required(observation, pid, change):
    row = process_observation(observation["guest_processes"]["processes"][pid], "boot")
    args = {"pid": row["pid"], "parent": row["parent_pid"], "uid": row["uids"][0],
            "ticks": row["start_ticks"], "argv": row["argv"]}
    observation["guest_processes"]["processes"][pid] = proc_row(**(args | change))
    with pytest.raises(AssertionError):
        observe(observation)


@pytest.mark.parametrize("field,value", [("extra", "unaccounted-field"),
                                        ("sent_at", 0), ("sequence", 2),
                                        ("attention_intent", {"mode": "room", "agent_ids": []}),
                                        ("attention_intent", {"mode": "none", "agent_ids": ["ag-other"]})])
def test_matching_reads_do_not_hide_fields_that_differ_from_send(observation, field, value):
    observation["host_history"][0][field] = value
    read = json.loads(observation["guest_files"]["read.json"])
    read["messages"] = copy.deepcopy(observation["host_history"])
    observation["guest_files"]["read.json"] = json.dumps(read)
    with pytest.raises(AssertionError):
        observe(observation)


def test_raw_guest_and_host_records_must_match(observation):
    observation["host_history"][0]["unexpected"] = True
    with pytest.raises(AssertionError, match="independent host history differ"):
        observe(observation)


def test_full_send_envelope_is_compared_without_dropping_extra_fields(observation):
    response = json.loads(observation["guest_files"]["send.json"])
    response["envelope"]["extra"] = {"value": "retained"}
    observation["guest_files"]["send.json"] = json.dumps(response)
    read = json.loads(observation["guest_files"]["read.json"])
    read["messages"][0]["extra"] = {"value": "retained"}
    observation["guest_files"]["read.json"] = json.dumps(read)
    observation["host_history"] = copy.deepcopy(read["messages"])
    observe(observation)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="direct Linux guest proc operands")
def test_live_proc_capture_uses_real_kernel_birth_and_parent(tmp_path):
    pid = os.getpid()
    output = tmp_path / "proc with spaces"
    subprocess.run(["/bin/sh", "-c", proc_command([pid], str(output))], check=True, capture_output=True)
    raw = {name: (output / f"{pid}.{name}").read_text() for name in ("stat", "status", "cmdline")}
    process = process_observation(raw, (output / "boot_id").read_text())
    assert process["pid"] == pid and process["parent_pid"] == os.getppid()
    assert process["uids"][:2] == [os.getuid(), os.geteuid()]
    assert process["start_token"].endswith(":" + Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19])
    # Linux comm can contain spaces and parentheses; native parsing uses the final ')'.
    before, after = raw["stat"].rsplit(")", 1)
    raw["stat"] = before.split("(", 1)[0] + "(comm ) with spaces)" + after
    assert process_observation(raw, (output / "boot_id").read_text()) == process


@pytest.fixture
def installed_fixture(tmp_path_factory, observation, monkeypatch):
    """A staged native-command fixture exercises the driver without starting a guest."""
    tmp_path = tmp_path_factory.mktemp("g7")
    root, workspace = tmp_path / "r", tmp_path / "w"
    (root / "bin").mkdir(parents=True)
    (root / "assets/guest").mkdir(parents=True)
    workspace.mkdir()
    nats = root / "data/coord/nats/bin/2.14.5/nats-server"
    nats.parent.mkdir(parents=True)
    nats.touch()
    for name in ("safeyolo-guest", "safeyolo-coord"):
        binary = root / "assets/guest" / name
        binary.write_bytes(b"controlled-test-artifact")
        binary.with_suffix(".version").write_text(f"{name} 0.1.0 commit=fixture profile=debug\n")
        binary.with_suffix(".sha256").write_text(hashlib.sha256(binary.read_bytes()).hexdigest())
    (root / "assets/docs").mkdir()
    (root / "assets/docs/AGENTS.md").write_text("nonsecret fixture instructions\n")
    (root / "assets/contrib").mkdir()
    (root / "assets/contrib/codex-command.sh").write_text("#!/bin/sh\nexit 0\n")
    data = tmp_path / "producer.json"
    data.write_text(json.dumps(observation))
    script = Path(__file__).with_name("fixtures") / "g7_native_cli.py"
    for name in ("safeyolo", "safeyolo-coord", "safeyolo-proxy"):
        binary = root / "bin" / name
        binary.write_text(f"#!{sys.executable}\n" + script.read_text())
        binary.chmod(0o755)
    monkeypatch.setenv("G7_FIXTURE", str(data))
    monkeypatch.setenv("SAFEYOLO_NATS_TEST_INSTANCE", "owned-fixture")
    monkeypatch.setenv("SAFEYOLO_VZ_TEST_TIMEOUT_SECONDS", "60")
    monkeypatch.setenv("SAFEYOLO_VZ_TEST_RUNNER", str(root / "bin/safeyolo"))
    monkeypatch.setenv("SAFEYOLO_COORD_DATA_DIR", "restored-by-monkeypatch")
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", "restored-by-monkeypatch")
    return Namespace(root=root, workspace=workspace, commit="fixture", profile="debug", data=data,
                     observation=observation)


def test_failed_setup_and_process_inspection_still_attempt_all_owned_stops(installed_fixture, monkeypatch, capsys):
    monkeypatch.setattr(installed_g7_vz.sys, "platform", "darwin")
    monkeypatch.setattr(installed_g7_vz.platform, "machine", lambda: "arm64")
    monkeypatch.setenv("G7_FAIL_SETUP", "1")
    calls = []

    def process_inspection(root):
        calls.append(root)
        if len(calls) > 1:
            raise ValueError("invalid owned PID receipt")
        return []

    monkeypatch.setattr(installed_g7_vz, "owned_processes", process_inspection)
    with pytest.raises(FileNotFoundError) as failed:
        installed_g7_vz.run(installed_fixture)
    result = json.loads(capsys.readouterr().out)
    assert result["failure"]["type"] == "FileNotFoundError"
    assert "invalid owned PID receipt" in result["cleanup"]["failures"][0]
    assert any("invalid owned PID receipt" in note for note in failed.value.__notes__)
    assert list(result["cleanup"]["commands"]) == ["agent stop g7", "stop", "coord stop", "agent cleanup g7"]
    assert all(record["exit_code"] == 0 for record in result["cleanup"]["commands"].values())


@pytest.mark.parametrize("parts", [
    ["agent", "create"], ["coord", "start"], ["coord", "grant"], ["start"], ["agent", "start"],
])
def test_early_checked_command_failure_retains_original_output_before_cleanup(
    installed_fixture, monkeypatch, capsys, parts,
):
    monkeypatch.setattr(installed_g7_vz.sys, "platform", "darwin")
    monkeypatch.setattr(installed_g7_vz.platform, "machine", lambda: "arm64")
    monkeypatch.setenv("G7_FAIL_COMMAND", json.dumps(parts))
    # A second failure must remain separate from the original command output.
    monkeypatch.setenv("G7_FAILURE", "cleanup")
    with pytest.raises(subprocess.CalledProcessError) as failed:
        installed_g7_vz.run(installed_fixture)
    result = json.loads(capsys.readouterr().out)
    saved = result["failure"]
    assert saved["type"] == "CalledProcessError"
    assert saved["command"] == failed.value.cmd
    assert saved["command"][:3] == [str(installed_fixture.root / "bin/safeyolo"),
                                    "--root", str(installed_fixture.root)]
    assert saved["command"][3:3 + len(parts)] == parts
    assert saved["exit_code"] == failed.value.returncode == 23
    assert saved["stdout"] == failed.value.stdout == "original command stdout\nretained ünicode\n"
    assert saved["stderr"] == failed.value.stderr == "original command stderr\nretained refusal\n"
    cleanup = result["cleanup"]
    assert list(cleanup["commands"]) == ["agent stop g7", "stop", "coord stop", "agent cleanup g7"]
    assert cleanup["commands"]["agent stop g7"]["exit_code"] == 9
    assert cleanup["commands"]["agent stop g7"]["stderr"] == "fixture stop refusal\n"
    assert cleanup["failures"] == ["agent stop g7: exit 9"]
    assert not cleanup["survivors"] and not cleanup["remaining_runtime_paths"]
    assert any("G7 owned cleanup also failed" in note for note in failed.value.__notes__)


def test_early_command_timeout_retains_partial_output_and_deadline(installed_fixture, monkeypatch, capsys):
    monkeypatch.setattr(installed_g7_vz.sys, "platform", "darwin")
    monkeypatch.setattr(installed_g7_vz.platform, "machine", lambda: "arm64")
    monkeypatch.setenv("G7_FAIL_COMMAND", json.dumps(["agent", "create"]))
    monkeypatch.setenv("G7_COMMAND_TIMEOUT", "1")
    real_run = subprocess.run

    def short_create_timeout(arguments, **kwargs):
        if arguments[3:5] == ["agent", "create"]:
            kwargs["timeout"] = 0.5
        return real_run(arguments, **kwargs)

    monkeypatch.setattr(installed_g7_vz.subprocess, "run", short_create_timeout)
    with pytest.raises(subprocess.TimeoutExpired) as failed:
        installed_g7_vz.run(installed_fixture)
    result = json.loads(capsys.readouterr().out)
    saved = result["failure"]
    assert saved["type"] == "TimeoutExpired" and saved["exit_code"] is None
    assert saved["command"] == failed.value.cmd
    assert saved["timeout"] == failed.value.timeout == 0.5
    assert saved["stdout"] == failed.value.stdout.decode() == "original command stdout\nretained ünicode\n"
    assert saved["stderr"] == failed.value.stderr.decode() == "original command stderr\nretained refusal\n"
    cleanup = result["cleanup"]
    assert list(cleanup["commands"]) == ["agent stop g7", "stop", "coord stop", "agent cleanup g7"]
    assert all(record["exit_code"] == 0 for record in cleanup["commands"].values())
    assert not cleanup["failures"] and not cleanup["survivors"] and not cleanup["remaining_runtime_paths"]


@pytest.mark.parametrize("failure", ["host-state", "guest-check", "cleanup", "none"])
def test_filtered_driver_retains_operands_and_actual_cleanup_with_failure_exit(installed_fixture, failure):
    fixture = installed_fixture
    if failure == "host-state":
        fixture.observation["status"].update(agent_state="observed", error="fixture host observation error")
    fixture.data.write_text(json.dumps(fixture.observation))
    launcher = fixture.root.parent / "driver.py"
    driver = Path(installed_g7_vz.__file__).resolve()
    launcher.write_text(f"""import runpy, sys
sys.path.insert(0, {str(driver.parent)!r})
module = runpy.run_path({str(driver)!r})
module['sys'].platform = 'darwin'
module['platform'].machine = lambda: 'arm64'
module['run'].__globals__['_process_start_token'] = lambda pid: 'darwin:2345:1:0'
module['main']()
""")
    tools = fixture.root.parent / "tools"
    tools.mkdir()
    (tools / "python3").symlink_to(sys.executable)
    env = {key: value for key, value in os.environ.items()
           if key.startswith(("SAFEYOLO_", "G7_")) or key in (
               "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy",
               "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS")}
    env["PATH"] = str(tools)
    env["G7_FAILURE"] = failure
    completed = subprocess.run([sys.executable, "-I", "-B", str(launcher), "--root", str(fixture.root),
                                "--workspace", str(fixture.workspace), "--commit", "fixture", "--profile", "debug"],
                               env=env, capture_output=True, text=True, timeout=30)
    assert completed.returncode == (0 if failure == "none" else 1), completed.stderr
    result = json.loads(completed.stdout)
    assert result["status"]["run_id"] == result["context"]["generation"] == "run-current"
    assert result["current_launch"]["state"] == "managed"
    assert result["current_supervisor"]["supervisor_parent_pid"] == 997
    assert result["guest_files"]["send.json"] and result["host_history"][0]["sequence"] == 1
    assert result["vz_helper"]["start_token"] == "darwin:2345:1:0"
    assert result["commands"]["status"]["exit_code"] == 0
    assert result["capture_started_at"] <= result["records_captured_at"] <= result["capture_completed_at"]
    assert result["guest_checks"]["observe"]["command"] == [
        "agent", "shell", "g7", "-c", "/safeyolo/safeyolo-guest observe check"]
    assert "1000" in result["guest_processes"]["processes"]
    cleanup = result["cleanup"]
    assert list(cleanup["commands"]) == ["agent stop g7", "stop", "coord stop", "agent cleanup g7"]
    assert not cleanup["survivors"] and not cleanup["remaining_runtime_paths"]
    if failure == "none":
        assert "failure" not in result and not cleanup["failures"]
    else:
        assert result["failure"]["type"] == "AssertionError" and "AssertionError" in completed.stderr
    if failure == "host-state":
        assert result["status"]["agent_state"] == "observed"
        assert result["status"]["error"] == "fixture host observation error"
        assert not result["capture_errors"] and not cleanup["failures"]
    if failure == "guest-check":
        assert result["guest_checks"]["observe"]["exit_code"] == 7
        assert result["guest_checks"]["observe"]["stdout"] == "stopped\n"
        assert result["guest_checks"]["observe"]["stderr"] == "fixture observation refusal\n"
    if failure == "cleanup":
        assert cleanup["commands"]["agent stop g7"]["exit_code"] == 9
        assert cleanup["commands"]["agent stop g7"]["stderr"] == "fixture stop refusal\n"
        assert cleanup["failures"] == ["agent stop g7: exit 9"]
