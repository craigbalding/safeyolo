"""Real native policy, attention, source and broker boundaries without a model.

The retained source operands are controlled here. Installed Linux/gVisor and
physical macOS/VZ failure production is proved by installed_operational_events.
"""

from __future__ import annotations

import json
import os
import signal
import sqlite3
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

from tests.proxy_contracts.harness import child_process, wait_ready
from tests.proxy_contracts.native_proposal_fixture import ROOM, proposal_instance

RECIPIENT = "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
TARGET = "ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def support(instance, *arguments, check=True):
    result = instance.cli("support", *arguments)
    if not check:
        return result
    assert result.returncode == 0, (result.stdout, result.stderr)
    return json.loads(result.stdout)


def proposal(instance, notifications, *, rooms=()):
    return {"expected_revision": None, "grant": {
        "instance_id": support(instance, "grants", "--json")["instance_id"],
        "support": {"name": "relay", "agent_id": RECIPIENT},
        "targets": [{"name": "lens", "agent_id": TARGET}],
        "guest_admin": False, "guest_logs": [], "lifecycle": [],
        "notifications": notifications, "signal_rooms": list(rooms),
        "expires_at": None, "acknowledgment": None}}


def apply(instance, value):
    path = instance.root.parent / "support-proposal.json"
    value["grant"]["acknowledgment"] = None
    path.write_text(json.dumps(value))
    preview = support(instance, "preview", "events", "--file", str(path), "--json")
    # Save actual preview operands before assertions or application.
    (instance.root.parent / "support-preview.json").write_text(json.dumps(preview))
    assert preview["notifications"]["recipient"] == value["grant"]["support"]
    assert preview["notifications"]["subjects"] == value["grant"]["targets"]
    assert preview["notifications"]["kinds"] == value["grant"]["notifications"]
    value["grant"] = preview["after"]
    value["grant"]["acknowledgment"] = preview["acknowledgment"]
    path.write_text(json.dumps(value))
    result = support(instance, "apply", "events", "--file", str(path), "--json")
    value["expected_revision"] = result["revision"]
    return result


def database(instance):
    return sqlite3.connect(instance.root / "data/coord/v0.db", timeout=5)


def source_failure(instance, suffix):
    directory = instance.root / "agents/lens"
    (directory / "home").mkdir(parents=True, exist_ok=True)
    value = {"event_id": "evt-" + suffix * 32, "agent_id": TARGET,
             "name": "lens", "run_id": None, "launch_id": None,
             "operation": "sandbox-start", "at": int(time.time()),
             "source": "host_start", "reason": "Synthetic retained failed-start operand"}
    path = directory / "last-start-failure.json"
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value))
    temporary.replace(path)
    return value


def call(instance, tool, arguments, *, check=True):
    return instance.command("call", tool, agent=True, input=json.dumps(arguments), check=check)


def wait_reference(instance, *, since=0, require_local=True):
    # Local fixture observation avoids racing a deliberately unavailable
    # broker before the host has admitted the next reference.
    deadline = time.monotonic() + 11
    while require_local and time.monotonic() < deadline:
        with database(instance) as db:
            ready = db.execute("SELECT count(*) FROM coord_attention_edges WHERE recipient_agent_id=? AND feed_sequence>?", (RECIPIENT, since)).fetchone()[0]
        if ready:
            break
        time.sleep(0.1)
    result = call(instance, "wait_for_coord", {"since_sequence": since, "limit": 100, "timeout_seconds": 10})
    (instance.root.parent / f"attention-{since}.json").write_text(json.dumps(result))
    assert result["objects"], result
    events = [item for item in result["objects"] if item["object"]["kind"] == "operational_event"]
    assert events, result
    return events, result["next_cursor"]


@contextmanager
def restart_observer(instance):
    instance.process.terminate()
    assert instance.process.wait(timeout=15) == 0
    ready = instance.root / "data/ready.json"
    ready.unlink(missing_ok=True)
    proxy = Path(os.environ["SAFEYOLO_NATIVE_ARTIFACTS"]) / "safeyolo-proxy"
    with child_process([str(proxy), "--config", str(instance.root / "config.toml")],
                       instance.root, instance.environment) as process:
        wait_ready(process, [ready, *map(Path, instance.paths.values())], instance.root / "process.log",
                   readiness_file=ready, expected_backend="rust-m2")
        instance.process = process
        instance.port = json.loads(ready.read_text())["admin_port"]
        yield


def test_selected_attention_loss_restart_and_current_observation(tmp_path, _binary_cache):
    with contextmanager(proposal_instance)(tmp_path, nats_binary=_binary_cache) as instance:
        instance.command("revoke", ROOM, "relay")
        source_failure(instance, "1")
        value = proposal(instance, [])
        apply(instance, value)
        time.sleep(5.5)
        with database(instance) as db:
            assert db.execute("SELECT count(*) FROM coord_attention_edges WHERE kind='operational_event'").fetchone() == (0,)
            # Drop the last wake atomically. No later business event will wake
            # this reader; only the ordinary retained-feed recovery can do so.
            db.execute("CREATE TRIGGER lose_final_wake AFTER INSERT ON coord_outbox WHEN NEW.destination='attention-nats' BEGIN UPDATE coord_outbox SET delivered_at=0 WHERE event_id=NEW.event_id; END")
        value["grant"]["notifications"] = ["launch_failed"]
        with ThreadPoolExecutor(max_workers=1) as workers:
            pending = workers.submit(wait_reference, instance, require_local=False)
            time.sleep(0.25)
            apply(instance, value)
            events, cursor = pending.result(timeout=14)
        assert len(events) == 1, events
        edge, event = events[0]["edge"], events[0]["object"]
        assert edge["room_id"] is None and event["reference"]["target"]["agent_id"] == TARGET
        assert event["reference"]["instance_id"] == value["grant"]["instance_id"]
        assert event["reference"]["kind"] == "launch_failed" and event["evidence"]["source_status"] == "retained"
        attention = edge["attention_id"]
        replay = call(instance, "read_attention", {"attention_id": attention})
        assert replay == events[0]
        # A new native recipient process reuses the same canonical identity.
        assert wait_reference(instance)[0] == events
        instance.agent_api("lens", f"/api/coord/attention/{attention}/object", status=404)
        instance.agent_api("relay", f"/api/coord/rooms/{ROOM}/messages", status=404)
        with database(instance) as db:
            assert db.execute("SELECT count(*) FROM coord_work").fetchone() == (0,)
            assert db.execute("SELECT count(*) FROM coord_attention_edges WHERE kind='operational_event'").fetchone() == (1,)
            assert db.execute("SELECT count(*) FROM coord_outbox WHERE destination='attention-nats' AND delivered_at=0").fetchone() == (1,)
            db.execute("DROP TRIGGER lose_final_wake")

        # Broker loss cannot prevent local retained reference discovery. Keep
        # the actual pending wake and its failed attempt for the next owner.
        instance.command("stop")
        (instance.root / "agents/lens/home/.safeyolo-command-supervisor.json").write_text("invalid guest JSON")
        source_failure(instance, "2")
        events2, cursor2 = wait_reference(instance, since=cursor)
        assert events2[0]["object"]["reference"]["event_id"] != event["reference"]["event_id"]
        time.sleep(0.5)
        with database(instance) as db:
            assert db.execute("SELECT count(*) FROM coord_outbox WHERE destination='attention-nats' AND delivered_at IS NULL").fetchone()[0] >= 1
        instance.process.terminate()
        assert instance.process.wait(timeout=15) == 0
        source_failure(instance, "3")
        with restart_observer(instance):
            events3, _ = wait_reference(instance, since=cursor2)
            assert events3[0]["object"]["reference"]["event_id"] not in {
                event["reference"]["event_id"], events2[0]["object"]["reference"]["event_id"]}
            # A replaced source loses old details honestly, but not its
            # already retained identity or observation authorization.
            old = call(instance, "read_attention", {"attention_id": attention})
            assert old["object"]["reference"] == event["reference"]
            assert old["object"]["evidence"]["source_status"] == "details_unavailable"
            value["grant"]["expires_at"] = "2020-01-01T00:00:00Z"
            apply(instance, value)
            denied = call(instance, "read_attention", {"attention_id": attention}, check=False)
            assert denied.returncode != 0 and "observation grant" in denied.stderr
            source_failure(instance, "5")
            time.sleep(5.5)
            with database(instance) as db:
                assert db.execute("SELECT count(*) FROM coord_attention_edges WHERE kind='operational_event'").fetchone() == (3,)
            value["grant"]["expires_at"] = None
            value["grant"]["notifications"] = []
            apply(instance, value)
            assert call(instance, "read_attention", {"attention_id": attention})["object"]["reference"] == event["reference"]
            source_failure(instance, "4")
            time.sleep(5.5)
            with database(instance) as db:
                assert db.execute("SELECT count(*) FROM coord_attention_edges WHERE kind='operational_event'").fetchone() == (3,)
            path = tmp_path / "revoke.json"
            path.write_text(json.dumps({"expected_revision": value["expected_revision"]}))
            support(instance, "revoke", "events", "--file", str(path), "--json")
            denied = call(instance, "read_attention", {"attention_id": attention}, check=False)
            assert denied.returncode != 0 and "observation grant" in denied.stderr
            value["expected_revision"] = None
            apply(instance, value)
            assert call(instance, "read_attention", {"attention_id": attention})["object"]["reference"] == event["reference"]


def test_signal_disclosure_uses_canonical_state_without_room_history(tmp_path, _binary_cache):
    with contextmanager(proposal_instance)(tmp_path, nats_binary=_binary_cache) as instance:
        (instance.root / "agents/lens/home").mkdir(parents=True)
        instance.command("revoke", ROOM, "relay")
        value = proposal(instance, ["needs_operator"], rooms=[ROOM])
        for change, expected in (("instance", "owning instance"), ("target", "durable identity"), ("disclosure", "signal_rooms")):
            invalid = json.loads(json.dumps(value))
            if change == "instance":
                invalid["grant"]["instance_id"] = "sy-" + "0" * 32
            elif change == "target":
                invalid["grant"]["targets"][0]["agent_id"] = "ag-" + "0" * 32
            else:
                invalid["grant"]["signal_rooms"] = []
            path = tmp_path / f"invalid-{change}.json"
            path.write_text(json.dumps(invalid))
            refused = support(instance,"preview","events","--file",str(path),"--json",check=False)
            assert refused.returncode != 0 and expected in refused.stderr, refused.stderr
        apply(instance, value)
        created = instance.agent_api("lens", f"/api/coord/rooms/{ROOM}/signals", method="POST", body={
            "action": "create", "operation_id": "material-source-1", "kind": "blocker", "basis": "observed",
            "summary": "Controlled material signal; attributed peer claim", "refs": ["opaque-source-reference"]})
        (tmp_path / "signal-created.json").write_text(json.dumps(created))
        signal = created["signal"]
        assert signal["needs_operator"] is True
        # Resolve before the observer's next pass. The canonical immutable
        # source revision must still be delivered with its current state.
        instance.command("signal", "resolve", ROOM, signal["signal_id"], "--expected-revision", str(signal["revision"]))
        events, _ = wait_reference(instance)
        item = next(item for item in events if item["object"]["reference"]["kind"] == "needs_operator")
        evidence = item["object"]["evidence"]
        assert evidence["selected_revision"]["signal"] == signal
        assert evidence["current"]["state"] == "resolved" and evidence["current"]["needs_operator"] is False
        assert item["object"]["reference"]["signal_id"] == signal["signal_id"]
        assert item["object"]["reference"]["launch_id"] is None
        assert evidence["current"]["author"] == signal["author"]
        instance.agent_api("relay", f"/api/coord/rooms/{ROOM}/messages", status=404)
        value["grant"]["notifications"] = []
        value["grant"]["signal_rooms"] = []
        apply(instance, value)
        denied = call(instance, "read_attention", {"attention_id": item["edge"]["attention_id"]}, check=False)
        assert denied.returncode != 0 and "signal_rooms" in denied.stderr
        with database(instance) as db:
            assert db.execute("SELECT count(*) FROM coord_work").fetchone() == (0,)


def test_guest_metadata_cannot_spoof_host_or_a_different_generation(tmp_path, _binary_cache):
    with contextmanager(proposal_instance)(tmp_path, nats_binary=_binary_cache) as instance:
        directory = instance.root / "agents/lens"
        home = directory / "home"
        home.mkdir(parents=True)
        generation = "0123456789abcdef0123456789abcdef"
        (directory / "runtime.json").write_text(json.dumps({"name":"lens","agent_id":TARGET,"run_id":generation,"state":"stopped"}))
        (directory / "current-launch.json").write_text(json.dumps({"name":"lens","agent_id":TARGET,"launch_id":"launch-controlled","state":"managed"}))
        source = {"name":"lens","generation":generation,"supervision_id":"launch-controlled","operational_events":[{
            "sequence":1,"kind":"command_exit","source":"host_start","at":time.time(),
            "reason":"private-payload-must-not-leak","state":{"private-payload-must-not-leak":True},
            "exit_signal":{"private-payload-must-not-leak":True},"command":"private-payload-must-not-leak"}]}
        path = home / ".safeyolo-command-supervisor.json"
        path.write_text(json.dumps(source))
        value = proposal(instance,["command_exit","sandbox_availability","control_availability"])
        apply(instance,value)
        events,cursor = wait_reference(instance)
        event = next(item["object"] for item in events if item["object"]["reference"]["kind"] == "command_exit")
        assert "private-payload-must-not-leak" not in json.dumps(event)
        assert event["reference"]["source"] == "guest_command_supervisor"
        assert event["reference"]["state"] == "unknown" and event["evidence"]["event"]["exit_signal"] is None
        source["generation"] = "fedcba9876543210fedcba9876543210"
        source["operational_events"][0]["sequence"] = 2
        path.write_text(json.dumps(source))
        # Invocation-exit telemetry is ordinary room data. It cannot become
        # evidence that a still-running supervisor died.
        instance.send('normal invocation completed: {"event":"exit","exit_code":0}')
        time.sleep(5.5)
        with database(instance) as db:
            assert db.execute("SELECT count(*) FROM coord_attention_edges WHERE kind='operational_event'").fetchone() == (1,)
        path.write_text("invalid guest JSON")
        (directory / "runtime.json").write_text("invalid host runtime JSON")
        changed,_ = wait_reference(instance,since=cursor)
        references = [item["object"]["reference"] for item in changed]
        assert {reference["kind"] for reference in references} == {"sandbox_availability","control_availability"}
        assert all(reference["source"] == "host_runtime" for reference in references)
        assert all(reference["state"]["runtime_state"] == "unknown" for reference in references)


def test_guest_source_survives_abrupt_child_and_owner_exit(tmp_path):
    """Run the Linux guest executable as an owned local process.

    The test calls the PID-1 report entrypoint explicitly. Actual PID-1
    ownership and both sandbox backends require the installed proof.
    """
    binary = Path(os.environ["SAFEYOLO_GUEST_ARTIFACTS"]) / "safeyolo-guest"
    context, state, stop = (tmp_path / name for name in ("context.json", "state.json", "stop.json"))
    context.write_text(json.dumps({"generation": "0123456789abcdef0123456789abcdef"}))
    state.write_text(json.dumps({"schema_version": 1, "name": "controlled-guest",
                                "generation": "0123456789abcdef0123456789abcdef",
                                "supervision_id": "launch-controlled", "command": "exec /bin/sleep 300",
                                "state": "starting", "started_at": time.time(),
                                "restart_count": 0, "consecutive_failures": 0}))
    command = [str(binary), "--context", str(context), "--state", str(state),
               "--stop", str(stop), "--workspace", str(tmp_path), "supervise"]
    binding = subprocess.check_output([*command,"owner-binding"],text=True,timeout=5).strip()

    def wait(predicate):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            value = json.loads(state.read_text())
            if predicate(value):
                return value
            time.sleep(0.02)
        raise AssertionError(f"Source transition did not arrive: {state.read_text()}")

    with (tmp_path / "guest-source.log").open("w") as log:
        owner = subprocess.Popen(command, stdout=log, stderr=log)
        try:
            initial = wait(lambda value: value["state"] == "running")
            (tmp_path / "source-before-kill.json").write_text(json.dumps(initial))
            os.kill(initial["command_pid"], signal.SIGKILL)
            restarted = wait(lambda value: value["state"] == "running" and value["restart_count"] == 1)
            (tmp_path / "source-after-child-kill.json").write_text(json.dumps(restarted))
            events = restarted["operational_events"]
            assert any(event["kind"] == "command_exit" and event["exit_signal"] == 9 for event in events)
            assert any(event["kind"] == "command_restart" for event in events)
            assert not any(event["kind"] == "supervisor_exit" for event in events)
            # A normal heartbeat is not a new event. This includes the period
            # in which an invocation could finish inside its still-live owner.
            sequence = restarted["event_sequence"]
            time.sleep(0.3)
            assert json.loads(state.read_text())["event_sequence"] == sequence
            owner.kill()
            assert owner.wait(timeout=5) == -signal.SIGKILL
            report = subprocess.run([*command, "owner-exit",binding,"137"], capture_output=True, text=True, timeout=5)
            assert report.returncode == 0, report.stderr
            owner = subprocess.Popen(command, stdout=log, stderr=log)
            resumed = wait(lambda value: value["state"] == "running" and value["supervisor_pid"] != restarted["supervisor_pid"])
            (tmp_path / "source-after-owner-kill.json").write_text(json.dumps(resumed))
            events = resumed["operational_events"]
            assert any(event["kind"] == "supervisor_exit" and event["source"] == "guest_pid1" and event["wait_status"] == 137 for event in events)
            assert all(event["state"] == "unknown" for event in events if event["kind"] == "supervisor_exit")
            assert any(event["kind"] == "supervisor_restart" for event in events)
            stop.write_text("{}")
            assert owner.wait(timeout=5) == 0
            terminal = json.loads(state.read_text())
            assert terminal["state"] == "stopped"
            report = subprocess.run([*command, "owner-exit",binding,"0"], capture_output=True, text=True, timeout=5)
            assert report.returncode == 0, report.stderr
            assert json.loads(state.read_text())["event_sequence"] == terminal["event_sequence"]
            replacement = dict(terminal,supervision_id="launch-replacement",state="starting")
            state.write_text(json.dumps(replacement))
            report = subprocess.run([*command,"owner-exit",binding,"137"],capture_output=True,text=True,timeout=5)
            assert report.returncode == 0, report.stderr
            assert json.loads(state.read_text()) == replacement
        finally:
            stop.write_text("{}")
            if owner.poll() is None:
                owner.terminate()
                try:
                    owner.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    owner.kill()
                    owner.wait(timeout=5)
