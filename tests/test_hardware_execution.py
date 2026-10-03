"""Real process, lock, filesystem and harness-protocol controls; no hardware."""

import base64
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from safeyolo.runtime_identity import process_is_alive, process_start_token
from tests import test_hardware_attempt_results
from tests.blackbox.hardware import attempt_results, install_schedule, kvm_host, mac_host, paired

# Local fixture aliases work whether the supplying test module was collected
# before or after this one. Registering it as a plugin depended on that order.
runner_commands = test_hardware_attempt_results.runner_commands
runner_summary = test_hardware_attempt_results.runner_summary
github_fixture = test_hardware_attempt_results.github_fixture


@pytest.fixture
def host_harness(tmp_path, monkeypatch, runner_summary):
    """Execute actual Bash jobs and virsh protocol fixtures in a private pool."""
    _attempt, summary = runner_summary
    jobs = tmp_path / "jobs"
    pool = tmp_path / "pool"
    commands = tmp_path / "commands"
    for path in (jobs, pool, commands):
        path.mkdir()
    state_path = tmp_path / "host-state.json"
    state_path.write_text(json.dumps({"guests": {}, "volumes": [], "calls": [], "exit": 0,
                                     "summary": json.loads(summary.read_text()), "cleanup_failed": False,
                                     "truncated": False, "wrong_sha": False}))
    program = tmp_path / "harness-fixture.py"
    program.write_text("""
import base64,hashlib,json,os,sys
from pathlib import Path
state=Path(os.environ['FIXTURE_HOST_STATE']); pool=Path(os.environ['FIXTURE_HOST_POOL'])
data=json.loads(state.read_text()); operation=sys.argv[1]; args=sys.argv[2:]
data['calls'].append([operation,*args]); result={}
if operation=='list_guests':
    result={'guests':[{'name':name,'state':status} for name,status in data['guests'].items()], 'volumes':data['volumes']}
elif operation=='provision':
    assert '--reuse' in args and '--clean' not in args
    owner=args[args.index('--scenario')+1]; selected=args[args.index('--safeyolo-ref')+1]
    name='sy-'+owner+'-123456789'; data['guests'][name]='running'
    for suffix in ('.qcow2','-seed.iso'):
        file=name+suffix; (pool/file).write_bytes(b'owned fixture disk'); data['volumes'].append(file)
    (pool/'.guest-lease').write_text(name+'\\n')
    result={'guest_name':name,'guest_ip':'192.168.122.100','safeyolo_sha':'f'*40 if data['wrong_sha'] else selected}
elif operation=='ssh_exec':
    script=base64.b64decode(args[1]).decode(); exit_code=data['exit']
    stdout='/home/guest' if script.startswith('printf') else 'private candidate diagnostics'
    if script.startswith('printf'): exit_code=0
    result={'ip':args[0],'exit_code':exit_code,'stdout_b64':base64.b64encode(stdout.encode()).decode(),
            'stderr_b64':'','timed_out':False,'duration_ms':1}
elif operation=='ssh_fetch':
    content=json.dumps(data['summary']).encode()
    result={'path':args[1],'size':len(content),'sha256':hashlib.sha256(content).hexdigest(),
            'content_b64':base64.b64encode(content).decode(),'truncated':data['truncated']}
elif operation=='teardown':
    name=args[0]
    if not data['cleanup_failed']:
        data['guests'].pop(name,None)
        for suffix in ('.qcow2','-seed.iso'):
            file=name+suffix; (pool/file).unlink(missing_ok=True)
            if file in data['volumes']: data['volumes'].remove(file)
        lease=pool/'.guest-lease'
        if lease.exists() and lease.read_text().strip()==name: lease.unlink()
    result={'success':True}  # The real harness also suppresses teardown errors.
elif operation=='virsh':
    if args[:3]==['list','--all','--name']: result='\\n'.join(data['guests'])
    elif args[0]=='domstate': result=data['guests'][args[1]]
    elif args[0]=='dumpxml':
        name=args[1]
        result=f'<domain><name>{name}</name><devices><disk><source file="{pool/name}.qcow2"/></disk><disk><source file="{pool/name}-seed.iso"/></disk></devices></domain>'
    else: raise ValueError(args)
else: raise ValueError(operation)
state.write_text(json.dumps(data))
print(result if isinstance(result,str) else 'HARNESS_JSON='+json.dumps(result))
""")
    for name in ("list_guests", "provision", "ssh_exec", "ssh_fetch", "teardown"):
        (jobs / f"{name}.sh").write_text(f"exec {sys.executable} {program} {name} \"$@\"\n")
    executable = commands / "virsh"
    executable.write_text(f"#!/bin/sh\nexec {sys.executable} {program} virsh \"$@\"\n")
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(commands) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("FIXTURE_HOST_STATE", str(state_path))
    monkeypatch.setenv("FIXTURE_HOST_POOL", str(pool))
    monkeypatch.setattr(kvm_host, "JOBS", jobs)
    monkeypatch.setattr(kvm_host, "POOL", pool)
    # This fixture proves transport/ownership controls, not KVM or capacity.
    monkeypatch.setattr(kvm_host, "preflight", lambda: {"fixture": True})
    return pool, state_path


def change_state(path, **changes):
    row = json.loads(path.read_text())
    row.update(changes)
    path.write_text(json.dumps(row))


def test_host_ignores_successful_wrapper_and_independently_observes_teardown(host_harness):
    pool, state = host_harness
    change_state(state, exit=7)
    result = kvm_host.run_lane("issue889-" + "a" * 32, "b" * 40, "c" * 32, 30)
    assert result["exit"] == 7 and result["summary"] is not None
    assert result["cleanup"] == "verified" and kvm_host.removed(result["guest_name"])
    assert not (pool / ".guest-lease").exists()
    assert not (pool / ".issue889-owner.json").exists()
    calls = json.loads(state.read_text())["calls"]
    assert sum(call[0] == "provision" for call in calls) == 1
    assert any(call[:2] == ["virsh", "list"] for call in calls[calls.index(next(c for c in calls if c[0] == "teardown")) + 1:])


def test_kvm_adapter_keeps_guest_failure_despite_valid_runner_report(host_harness, runner_summary, monkeypatch):
    _pool, state = host_harness
    attempt, _summary = runner_summary
    receipt = attempt.data["lanes"]["kvm"]
    change_state(state, exit=7)
    hardware = paired.PairedHardware({"rundeck_url": "http://rundeck.fixture"}, attempt)

    def host_call(action, extra=()):
        if action == "run":
            return kvm_host.run_lane(attempt.data["owner"], attempt.data["source_revision"], receipt["run_id"], 30)
        assert action == "verify"
        return {"owner": attempt.data["owner"], "removed": kvm_host.removed(extra[1])}

    monkeypatch.setattr(hardware, "rundeck_call", host_call)
    hardware.run_kvm(receipt)
    attempt.finish()
    assert receipt["result"]["complete_success"] is True
    assert receipt["command_exit"] == 7 and receipt["cleanup"] == "verified"
    assert {"stage": "execution", "lane": "kvm"} in attempt.data["failures"]
    assert not attempt.execution_succeeded()


@pytest.mark.parametrize("changes", [{"truncated": True}, {"wrong_sha": True}, {"cleanup_failed": True}])
def test_partial_transfer_wrong_selection_and_suppressed_cleanup_failures_stay_failed(host_harness, changes):
    pool, state = host_harness
    change_state(state, **changes)
    result = kvm_host.run_lane("issue889-" + "a" * 32, "b" * 40, "c" * 32, 30)
    if changes.get("cleanup_failed"):
        assert result["cleanup"] == "failed" and (pool / ".guest-lease").exists()
        assert (pool / ".issue889-owner.json").exists()
    else:
        assert result["exit"] == 2 and result["summary"] is None
        assert result["cleanup"] == "verified"


def test_owned_teardown_preserves_an_unrelated_inactive_domain_and_disk(host_harness):
    pool, state = host_harness
    foreign = "sy-foreign-experiment-22"
    (pool / f"{foreign}.qcow2").write_text("foreign data")
    change_state(state, guests={foreign: "shut off"}, volumes=[f"{foreign}.qcow2"])
    result = kvm_host.run_lane("issue889-" + "a" * 32, "b" * 40, "c" * 32, 30)
    assert result["cleanup"] == "verified"
    assert json.loads(state.read_text())["guests"] == {foreign: "shut off"}
    assert (pool / f"{foreign}.qcow2").read_text() == "foreign data"


def test_defined_owned_domain_without_volume_inventory_is_not_a_fresh_guest(host_harness):
    _pool, state = host_harness
    owner = "issue889-" + "a" * 32
    change_state(state, guests={f"sy-{owner}-123": "shut off"})
    with pytest.raises(ValueError, match="fresh attempt"):
        kvm_host.run_lane(owner, "b" * 40, "c" * 32, 30)
    current = json.loads(state.read_text())
    assert current["guests"] == {f"sy-{owner}-123": "shut off"}
    assert all(call[0] not in {"provision", "teardown"} for call in current["calls"])


def test_stale_recovery_requires_both_owner_and_resource_inactivity(host_harness):
    pool, state = host_harness
    change_state(state, cleanup_failed=True)
    result = kvm_host.run_lane("issue889-" + "a" * 32, "b" * 40, "c" * 32, 30)
    row = json.loads((pool / ".issue889-owner.json").read_text())
    with pytest.raises(ValueError, match="owner is still active"):
        kvm_host.cleanup(row, stale=True)
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    row.update(pid=child.pid, start_token=process_start_token(child.pid))
    child.terminate()
    child.wait(timeout=5)
    with pytest.raises(ValueError, match="resource is still active"):
        kvm_host.cleanup(row, stale=True)
    current = json.loads(state.read_text())
    current["guests"][result["guest_name"]] = "shut off"
    current["cleanup_failed"] = False
    state.write_text(json.dumps(current))
    assert kvm_host.cleanup(row, stale=True)
    assert kvm_host.removed(result["guest_name"])


def test_missing_kvm_journal_still_checks_owned_resource_and_live_owner(host_harness):
    pool, state = host_harness
    owner = "issue889-" + "a" * 32
    assert kvm_host.absent_owner(owner)
    (pool / f"sy-{owner}-123.qcow2").write_bytes(b"owned orphan")
    assert not kvm_host.absent_owner(owner)
    row = {"owner": owner, "pid": os.getpid(), "start_token": process_start_token(os.getpid()), "guest_name": None}
    with pytest.raises(ValueError, match="owner is still active"):
        kvm_host.cleanup(row, stale=True)
    assert (pool / f"sy-{owner}-123.qcow2").read_bytes() == b"owned orphan"


def test_generated_fetch_controls_never_accept_truncated_or_changed_bytes():
    original = b'{"schema_version":1}'
    good = {"path": "/owned/summary.json", "size": len(original), "sha256": hashlib.sha256(original).hexdigest(),
            "content_b64": base64.b64encode(original).decode(), "truncated": False}

    @settings(max_examples=40, deadline=None)
    @given(st.sampled_from(tuple(good)), st.one_of(st.none(), st.booleans(), st.integers(), st.text(), st.lists(st.integers())))
    def check(field, value):
        row = dict(good)
        row[field] = value
        if value == good[field] and type(value) is type(good[field]):
            assert kvm_host.fetched_report(row, good["path"]) == {"schema_version": 1}
        else:
            with pytest.raises((ValueError, TypeError)):
                kvm_host.fetched_report(row, good["path"])

    check()


@pytest.fixture
def owned_child(tmp_path):
    root = tmp_path / "owned"
    root.mkdir()
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", str(root)])
    row = {"pid": process.pid, "start_token": process_start_token(process.pid)}
    try:
        yield root, process, row
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)


def test_real_owned_process_exits_and_reused_foreign_identity_survives(owned_child):
    root, process, row = owned_child
    mac_host.stop_processes([dict(row, start_token="foreign-start-identity")], (root,), timeout=0.1)
    assert process.poll() is None
    mac_host.stop_processes([row], (root,), timeout=0.2)
    process.wait(timeout=5)
    assert not process_is_alive(process.pid)


def test_marker_cannot_signal_a_foreign_tree_or_prefix_neighbor(owned_child):
    root, process, row = owned_child
    for wrong in (root / "elsewhere", Path(str(root)[:-1])):
        with pytest.raises(ValueError, match="no argument in the owned"):
            mac_host.stop_processes([row], (wrong,), timeout=0.1)
        assert process.poll() is None


def test_unknown_identity_and_live_mac_owner_are_preserved(owned_child, tmp_path, monkeypatch):
    root, process, row = owned_child
    journal = tmp_path / "owner.json"
    data = {"pid": process.pid, "start_token": row["start_token"], "processes": [row],
            "run_root": str(root), "state_parent": str(root), "created_trees": [str(root)]}
    mac_host.save_owner(journal, data)
    with pytest.raises(ValueError, match="owner remains active"):
        mac_host.recover(journal)
    monkeypatch.setattr(mac_host, "process_start_token", lambda _: None)
    with pytest.raises(ValueError, match="cannot inspect"):
        mac_host.stop_processes([row], (root,), timeout=0.1)
    assert journal.exists() and process.poll() is None


def test_pair_rejects_public_ref_before_any_hardware_and_publishes_failure(tmp_path, github_fixture, monkeypatch):
    github, store = github_fixture
    monkeypatch.setattr(paired, "checked_controller", lambda *_: None)

    class NoHardware:
        def __init__(self, *_args):
            pytest.fail("unadmitted selection reached hardware")

    config = {"attempts": str(tmp_path / "attempts"), "controller_revision": "b" * 40}
    with pytest.raises(ValueError):
        paired.execute(config, "on-demand", "refs/pull/905/head", github=github, hardware_type=NoHardware)
    records = list((tmp_path / "attempts").glob("*/attempt.json"))
    assert len(records) == 1
    restored = attempt_results.HardwareAttempt.restore(records[0].parent)
    assert restored.data["publication"]["verified"] and not restored.passed()
    assert {"stage": "selection", "lane": None} in restored.data["failures"]
    assert "selection" in json.dumps(json.loads(store.read_text())["comments"])


@pytest.mark.parametrize("trigger", ["overnight", "on-demand"])
def test_one_selected_sha_is_retained_for_both_triggered_lanes(tmp_path, github_fixture, monkeypatch, trigger):
    github, store = github_fixture
    monkeypatch.setattr(paired, "checked_controller", lambda *_: None)
    calls = []

    class HardwareFixture:
        def __init__(self, _config, attempt):
            self.attempt = attempt

        def run_kvm(self, receipt):
            calls.append(("kvm", self.attempt.data["source_revision"]))
            receipt["cleanup"] = "verified"
            self.attempt.fail("preflight", lane="kvm")

        def run_vz(self, receipt):
            calls.append(("vz", self.attempt.data["source_revision"]))
            receipt["cleanup"] = "verified"
            self.attempt.fail("execution", lane="vz")

    config = {"attempts": str(tmp_path / "attempts"), "controller_revision": "b" * 40}
    result = paired.execute(config, trigger, "a" * 40 if trigger == "on-demand" else None,
                            github=github, hardware_type=HardwareFixture)
    assert calls == [("kvm", "a" * 40), ("vz", "a" * 40)]
    assert result.data["publication"]["verified"] and not result.passed()
    assert "preflight (kvm)" in json.loads(store.read_text())["comments"]["1"]["body"]


def test_cleanup_failure_stops_paired_continuation_even_after_transport_exception(tmp_path, github_fixture, monkeypatch):
    github, _store = github_fixture
    monkeypatch.setattr(paired, "checked_controller", lambda *_: None)

    class HardwareFixture:
        def __init__(self, _config, attempt):
            self.attempt = attempt

        def run_kvm(self, receipt):
            receipt["cleanup"] = "failed"
            self.attempt.fail("cleanup", lane="kvm")
            raise TimeoutError("lost fixture transport")

        def run_vz(self, _receipt):
            pytest.fail("cleanup failure allowed another hardware invocation")

    config = {"attempts": str(tmp_path / "attempts"), "controller_revision": "b" * 40}
    result = paired.execute(config, "overnight", github=github, hardware_type=HardwareFixture)
    assert set(result.data["lanes"]) == {"kvm"} and not result.passed()
    assert result.data["publication"]["verified"]


@pytest.mark.parametrize("caller_timeout", [False, True])
def test_mac_outer_deadline_stops_real_caller_and_owned_helper(tmp_path, monkeypatch, caller_timeout):
    """Linux substitutes Mac capability only; launch, signals and teardown run."""
    owner = "issue889-" + "a" * 32
    run = tmp_path / "runs" / "aaaaaaaa"
    state = tmp_path / "states" / "aaaaaaaa"
    run.parent.mkdir()
    state.parent.mkdir()
    staging = tmp_path / "staging"
    script = staging / "source/tests/blackbox/run-installed.sh"
    helper = staging / "payload/bin/safeyolo-vm"
    script.parent.mkdir(parents=True)
    helper.parent.mkdir(parents=True)
    helper.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n")
    helper.chmod(0o755)
    script.write_text(f"#!{sys.executable}\n" + f"""
import json,subprocess,sys,time
from pathlib import Path
from safeyolo.runtime_identity import process_start_token
state=Path({str(state)!r}); root=Path({str(run)!r})
marker=state/'sy-vz-fixture/isolation/agents/bbtest/vm-supervisor.json'
marker.parent.mkdir(parents=True)
child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)',str(root)])
marker.write_text(json.dumps({{'pid':child.pid,'start_token':process_start_token(child.pid),'helper_pid':None}}))
(root/'arguments.json').write_text(json.dumps(sys.argv[1:]))
if {caller_timeout!r}: time.sleep(30)
""")
    script.chmod(0o755)
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as bundle:
        bundle.add(staging / "source", arcname="source")
        bundle.add(staging / "payload", arcname="payload")
    data = archive.getvalue()
    monkeypatch.setattr(mac_host, "preflight", lambda *_: {"fixture": True})
    journal = tmp_path / "host-owner.json"
    result = mac_host.run_lane(owner, run, state, Path(sys.executable), "b" * 40, "c" * 32, "d" * 64,
                               0.4 if caller_timeout else 10, 120, journal,
                               hashlib.sha256(data).hexdigest(), archive_input=io.BytesIO(data))
    assert result["exit"] == (2 if caller_timeout else 0)
    assert result["cleanup"] == "verified"
    row = json.loads(journal.read_text())
    assert all(not process_is_alive(item["pid"]) for item in row["processes"])
    arguments = json.loads((run / "arguments.json").read_text())
    assert "--section" not in arguments and "--staged-inputs" in arguments and "--run-id" in arguments
    assert arguments[arguments.index("--vz-test-runner") + 1] == "/Users/sy-agent/bin/run-vz-test"
    assert mac_host.release(row)
    assert not state.exists() and not (run / "payload").exists() and not (run / "source").exists()


def test_malformed_transfer_cannot_start_candidate_and_owned_inputs_are_released(tmp_path, monkeypatch):
    run = tmp_path / "runs" / "aaaaaaaa"
    state = tmp_path / "states" / "aaaaaaaa"
    run.parent.mkdir()
    state.parent.mkdir()
    journal = tmp_path / "owner.json"
    monkeypatch.setattr(mac_host, "preflight", lambda *_: {"fixture": True})
    result = mac_host.run_lane("issue889-" + "a" * 32, run, state, Path(sys.executable), "b" * 40,
                               "c" * 32, "d" * 64, 10, 120, journal, "e" * 64,
                               archive_input=io.BytesIO(b"wrong transferred bytes"))
    assert result["stage"] == "transfer" and result["exit"] == 2 and result["cleanup"] == "verified"
    row = json.loads(journal.read_text())
    assert not row["processes"] and mac_host.release(row)


def test_cron_installation_preserves_foreign_entries_and_reads_back_actual_entry(tmp_path, monkeypatch):
    executable = tmp_path / "crontab"
    store = tmp_path / "crontab-state"
    store.write_text("42 4 * * * /operator/foreign-experiment\n")
    executable.write_text(f"#!{sys.executable}\n" + """
import os,sys
from pathlib import Path
p=Path(os.environ['FIXTURE_CRONTAB'])
if sys.argv[1:] == ['-l']: print(p.read_text(),end='')
elif sys.argv[1:] == ['-']: p.write_text(sys.stdin.read())
else: raise SystemExit(2)
""")
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("FIXTURE_CRONTAB", str(store))
    monkeypatch.setattr(paired, "checked_controller", lambda *_: None)
    config = tmp_path / "private config.json"
    config.write_text(json.dumps({"controller_revision": "b" * 40, "attempts": str(tmp_path / "attempts")}))
    entry = tmp_path / "deployed.cron"
    result = install_schedule.install(config, entry, 2, 17)
    assert result["entry"] in store.read_text()
    assert store.read_text().startswith("42 4 * * * /operator/foreign-experiment\n")
    assert "17 2 * * *" in entry.read_text() and "paired.py overnight --config" in entry.read_text()
    install_schedule.install(config, entry, 2, 17)
    assert store.read_text().count(install_schedule.START) == 1
    assert install_schedule.current_crontab() == store.read_text()


def test_ambiguous_cron_markers_cannot_replace_operator_work():
    for previous in (install_schedule.START, install_schedule.END + "\n" + install_schedule.START,
                     (install_schedule.START + install_schedule.END) * 2):
        with pytest.raises(ValueError):
            install_schedule.replace_entry(previous, "fixture new entry\n")


def test_colliding_run_directory_survives_failed_transfer_and_release(tmp_path, monkeypatch):
    root = tmp_path / "runs/aaaaaaaa"
    state = tmp_path / "states/aaaaaaaa"
    root.mkdir(parents=True)
    state.parent.mkdir()
    foreign = root / "source/operator-data"
    foreign.parent.mkdir()
    foreign.write_text("keep the previous unrelated owner")
    monkeypatch.setattr(mac_host, "preflight", lambda *_: {"fixture": True})
    journal = tmp_path / "host-owner.json"
    result = mac_host.run_lane("issue889-" + "a" * 32, root, state, Path(sys.executable), "b" * 40,
                               "c" * 32, "d" * 64, 10, 120, journal, "e" * 64, archive_input=io.BytesIO(b"unused"))
    row = json.loads(journal.read_text())
    assert result["exit"] == 2 and row["created_trees"] == [] and row["processes"] == []
    assert mac_host.release(row)
    assert foreign.read_text() == "keep the previous unrelated owner"


def test_failed_builder_is_never_reported_clean_or_removed(tmp_path, github_fixture):
    github, _store = github_fixture
    attempt = attempt_results.HardwareAttempt(tmp_path, "b" * 40, "on-demand")
    attempt.data["tart_build"] = {"root": "/operator/tart/" + attempt.data["run_id"], "complete": False, "removed": False}
    hardware = paired.PairedHardware({"rundeck_url": "http://rundeck.fixture"}, attempt)
    assert hardware.release_build() is False
    assert attempt.data["tart_build"]["removed"] is False


def test_recovery_preserves_failure_and_does_not_rerun_candidate(tmp_path, github_fixture, monkeypatch):
    github, store = github_fixture
    attempt = attempt_results.HardwareAttempt(tmp_path, "b" * 40, "on-demand")
    attempt.select("c" * 40)
    attempt.start_lane("kvm")
    attempt.fail("execution", lane="kvm")
    attempt.finish()
    monkeypatch.setattr(paired, "checked_controller", lambda *_: None)

    class Recovery:
        def __init__(self, config, active):
            self.active = active

        def rundeck_call(self, action):
            assert action == "cleanup"
            return {"owner": self.active.data["owner"], "removed": True}

    recovered = paired.recover_attempt({"attempts": str(tmp_path), "controller_revision": "b" * 40},
                                      attempt.directory, github=github, hardware_type=Recovery)
    assert recovered.data["lanes"]["kvm"]["cleanup"] == "verified"
    assert recovered.data["failures"] == [{"stage": "execution", "lane": "kvm"}]
    assert recovered.data["publication"]["verified"] is True and not recovered.passed()
    assert "failed or incomplete" in store.read_text()
