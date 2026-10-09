"""Challenge same-run native G7 observations before a physical witness is run."""

import copy
import hashlib
import json
from argparse import Namespace

import pytest

from tests.blackbox import installed_g7_vz
from tests.blackbox.installed_g7_vz import observe


@pytest.fixture
def observation(tmp_path):
    home = tmp_path / "home"
    output = home / ".g7"
    output.mkdir(parents=True)
    identities = {"guest": "safeyolo-guest 0.1.0 commit=fixture profile=debug",
                  "coord": "safeyolo-coord 0.1.0 commit=fixture profile=debug"}
    state = {"state": "running", "generation": "run-current", "supervision_id": "launch-current",
             "command_pid": 102, "command_start_token": "linux:boot:102:456",
             "supervisor_pid": 100, "supervisor_start_token": "linux:boot:100:123",
             "supervisor_parent_pid": 1, "supervisor_uid": 1000, "guest_helper_version": identities["guest"]}
    context = {"generation": "run-current"}
    envelope = {"sequence": 1, "msg_id": "msg-marker", "origin_instance_id": "sy-instance",
                "sender_kind": "agent", "sender_agent_name": "g7", "sender_agent_id": "ag-g7",
                "content_type": "text/plain", "body": "G7:unique"}
    values = {"supervision.json": state, "context.json": context, "join.json": {"room_id": "rm-g7"},
              "send.json": {"envelope": envelope}, "read.json": {"messages": [envelope]}}
    for name, value in values.items():
        (output / name).write_text(json.dumps(value))
    (home / ".safeyolo-command-supervisor.json").write_text(json.dumps(state))
    for name, value in {"uid": "1000", "per-run-started": "1791567096", "vm-status": "ready",
                        "guest.version": identities["guest"], "coord.version": identities["coord"], "complete": ""}.items():
        (output / name).write_text(value)
    status = {"run_id": "run-current", "runtime_state": "running", "control_state": "ready",
              "agent_state": "running", "launcher": {"kind": "supervisor"},
              "launch_id": "launch-current", "agent_id": "ag-g7"}
    return {"home": home, "status": status, "context": context,
            "grant": {"room_id": "rm-g7", "agent_id": "ag-g7"}, "instance": "sy-instance",
            "marker": "G7:unique", "history": [copy.deepcopy(envelope)], "identities": identities}


def test_same_run_observation_requires_matching_native_results(observation):
    assert observe(**observation)["envelope"]["msg_id"] == "msg-marker"


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
    ("send.json", "body", "other-marker"),
    ("send.json", "sender_kind", "operator"),
    ("join.json", "room_id", "other-room"),
])
def test_stale_or_unrelated_guest_results_are_refused(observation, name, field, value):
    path = observation["home"] / ".g7" / name
    data = json.loads(path.read_text())
    target = data["envelope"] if name == "send.json" else data
    target[field] = value
    path.write_text(json.dumps(data))
    with pytest.raises(AssertionError):
        observe(**observation)


@pytest.mark.parametrize("name,value", [("uid", "0"), ("vm-status", "booting"),
                                        ("per-run-started", "0"), ("coord.version", "wrong-source")])
def test_initialization_and_executable_failures_are_refused(observation, name, value):
    (observation["home"] / ".g7" / name).write_text(value)
    with pytest.raises(AssertionError):
        observe(**observation)


def test_failed_setup_and_process_inspection_still_attempt_all_owned_stops(tmp_path, monkeypatch):
    # A real executable supplies controlled host output; no guest is started.
    root, workspace = tmp_path / "r", tmp_path / "w"
    (root / "bin").mkdir(parents=True)
    (root / "assets/guest").mkdir(parents=True)
    workspace.mkdir()
    log = tmp_path / "calls"
    for name in ("safeyolo", "safeyolo-coord", "safeyolo-proxy"):
        binary = root / "bin" / name
        binary.write_text('#!/bin/sh\nif [ "$1" = --version ]; then\n'
                          'printf "%s 0.1.0 commit=fixture profile=debug\\n" "${0##*/}"\n'
                          f'else printf "%s\\n" "$*" >> "{log}"; fi\n')
        binary.chmod(0o755)
    for name in ("safeyolo-guest", "safeyolo-coord"):
        binary = root / "assets/guest" / name
        binary.write_bytes(b"controlled-test-artifact")
        binary.with_suffix(".version").write_text(f"{name} 0.1.0 commit=fixture profile=debug\n")
        binary.with_suffix(".sha256").write_text(hashlib.sha256(binary.read_bytes()).hexdigest())
    monkeypatch.setattr(installed_g7_vz.sys, "platform", "darwin")
    monkeypatch.setattr(installed_g7_vz.platform, "machine", lambda: "arm64")
    monkeypatch.setenv("SAFEYOLO_NATS_TEST_INSTANCE", "owned-fixture")
    monkeypatch.setenv("SAFEYOLO_VZ_TEST_TIMEOUT_SECONDS", "60")
    monkeypatch.setenv("SAFEYOLO_VZ_TEST_RUNNER", str(root / "bin/safeyolo"))
    monkeypatch.setenv("SAFEYOLO_COORD_DATA_DIR", "restored-by-monkeypatch")
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", "restored-by-monkeypatch")
    calls = []

    def process_inspection(_root):
        calls.append(_root)
        if len(calls) > 1:
            raise ValueError("invalid owned PID receipt")
        return []

    monkeypatch.setattr(installed_g7_vz, "owned_processes", process_inspection)
    with pytest.raises(FileNotFoundError) as failed:
        installed_g7_vz.run(Namespace(root=root, workspace=workspace, commit="fixture", profile="debug"))
    output = log.read_text()
    for operation in ("agent stop g7", "stop", "coord stop", "agent cleanup g7"):
        assert f"--root {root} {operation}\n" in output
    assert any("invalid owned PID receipt" in note for note in failed.value.__notes__)
