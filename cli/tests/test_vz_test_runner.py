"""Disposable VZ deadline supervision keeps the helper and runner distinct."""

import json
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from safeyolo import vm
from safeyolo.runtime_identity import process_is_alive, process_start_token


@pytest.fixture
def supervised_vm(tmp_path, monkeypatch, tmp_config_dir):
    """Run real finite child processes, replacing only macOS observation/boot."""
    monkeypatch.setattr(vm.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(vm, "probe_vm_helper", lambda helper: helper)
    share = tmp_config_dir / "share"
    share.mkdir()
    for filename in ("Image", "initramfs.cpio.gz", "rootfs-base.ext4"):
        (share / filename).write_bytes(b"fixture")
    agent = tmp_config_dir / "agents/probe"
    (agent / "config-share").mkdir(parents=True)
    binaries = tmp_config_dir / "bin"
    binaries.mkdir()
    helper = binaries / "safeyolo-vm"
    helper.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(60)\n")
    helper.chmod(0o755)
    runner = tmp_path / "run-vz-test"
    runner.write_text(f"#!{sys.executable}\n" + """
import signal
import subprocess
import sys
child = subprocess.Popen(sys.argv[sys.argv.index('--') + 1:])
def stop(signum, frame):
    child.terminate()
    child.wait(timeout=3)
    raise SystemExit(128 + signum)
signal.signal(signal.SIGTERM, stop)
try:
    raise SystemExit(child.wait(timeout=int(sys.argv[2])))
except subprocess.TimeoutExpired:
    child.terminate()
    child.wait(timeout=3)
    raise SystemExit(124)
""")
    runner.chmod(0o755)
    monkeypatch.setenv("SAFEYOLO_VZ_TEST_RUNNER", str(runner))
    monkeypatch.setenv("SAFEYOLO_VZ_TEST_TIMEOUT_SECONDS", "30")
    def observe(runner_pid, _helper):
        # Linux's real parent-child observation substitutes for libproc only.
        children = Path(f"/proc/{runner_pid}/task/{runner_pid}/children").read_text().split()
        if not children:
            return None
        pid = int(children[0])
        return pid, process_start_token(pid)

    monkeypatch.setattr(vm, "_vz_runner_helper_pid", observe)
    yield agent
    # The fixture owns only the PIDs it observed. Preserve any reused PID.
    if (agent / "vm-supervisor.json").exists():
        vm.stop_vm("probe")


def test_real_runner_and_helper_have_separate_pid_files_and_owned_stop(supervised_vm):
    process = vm.start_vm("probe", "/workspace", background=True, ephemeral=True)
    receipt = json.loads((supervised_vm / "vm-supervisor.json").read_text())
    helper_pid = int((supervised_vm / "vm.pid").read_text())
    assert receipt["pid"] == process.pid
    assert receipt["helper_pid"] == helper_pid != process.pid
    assert receipt["start_token"] == process_start_token(process.pid)
    assert (supervised_vm / "vm.token").read_text() == process_start_token(helper_pid)
    vm.stop_vm("probe")
    assert process.wait(timeout=3) == 128 + signal.SIGTERM
    assert not process_is_alive(helper_pid)
    assert not (supervised_vm / "vm-supervisor.json").exists()
    assert not (supervised_vm / "vm.pid").exists()


def test_real_deadline_stops_and_reaps_helper(supervised_vm, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_VZ_TEST_TIMEOUT_SECONDS", "1")
    process = vm.start_vm("probe", "/workspace", background=True, ephemeral=True)
    helper_pid = int((supervised_vm / "vm.pid").read_text())
    assert process.wait(timeout=4) == 124
    assert not process_is_alive(helper_pid)
    vm.stop_vm("probe")
    assert not (supervised_vm / "vm-supervisor.json").exists()


@pytest.mark.parametrize("exit_mode", ("deadline", "helper_exit", "missing_helper_pid"))
def test_public_stop_reclaims_supervision_after_helper_exit(supervised_vm, monkeypatch, exit_mode):
    from safeyolo import agent_lifecycle, platform
    from safeyolo.platform.darwin import DarwinPlatform

    monkeypatch.setattr(platform, "get_platform", lambda: DarwinPlatform())
    if exit_mode == "deadline":
        monkeypatch.setenv("SAFEYOLO_VZ_TEST_TIMEOUT_SECONDS", "1")
    process = vm.start_vm("probe", "/workspace", background=True, ephemeral=True)
    helper_pid = int((supervised_vm / "vm.pid").read_text())
    if exit_mode != "deadline":
        os.kill(helper_pid, signal.SIGTERM)
    assert process.wait(timeout=4) == (124 if exit_mode == "deadline" else 256 - signal.SIGTERM)
    assert not process_is_alive(helper_pid)
    if exit_mode == "missing_helper_pid":
        (supervised_vm / "vm.pid").unlink()
    result = agent_lifecycle.stop_agent_by_name("probe")
    assert result.sandbox_state == "stopped" and result.error is None
    assert not (supervised_vm / "vm-supervisor.json").exists()
    assert not (supervised_vm / "vm.pid").exists()
    assert not (supervised_vm / "vm.token").exists()


def test_relaunch_preserves_existing_real_runner_and_helper(supervised_vm):
    process = vm.start_vm("probe", "/workspace", background=True, ephemeral=True)
    receipt = supervised_vm / "vm-supervisor.json"
    original = receipt.read_bytes()
    with pytest.raises(vm.VMError, match="still active"):
        vm.start_vm("probe", "/workspace", background=True, ephemeral=True)
    assert process.poll() is None
    assert receipt.read_bytes() == original
    helper_pid = int((supervised_vm / "vm.pid").read_text())
    assert process_is_alive(helper_pid)
    vm.stop_vm("probe")
    process.wait(timeout=3)


def test_darwin_snapshot_caller_receives_real_helper_pid(supervised_vm, monkeypatch):
    from safeyolo import sockets
    from safeyolo.platform import darwin

    launches = []

    def launch(**kwargs):
        process = vm.start_vm(**kwargs)
        launches.append(process)
        return process

    monkeypatch.setattr(darwin, "start_vm", launch)
    # This process-identity fixture has no real bridges. Keep pytest's long
    # temporary path out of the unrelated Unix socket pathname check.
    monkeypatch.setattr(sockets, "path_for", lambda name, ip: Path("/short/proxy.sock"))
    helper_pid = darwin.DarwinPlatform().start_sandbox(
        "probe", "/workspace", supervised_vm / "config-share", {"attribution_ip": "10.200.0.1"},
        1, 512, None, True, ephemeral=True,
    )
    assert helper_pid == int((supervised_vm / "vm.pid").read_text())
    assert helper_pid != launches[0].pid
    assert process_is_alive(helper_pid)
    vm.stop_vm("probe")
    launches[0].wait(timeout=3)


def test_pid_file_failure_stops_both_real_processes(supervised_vm, monkeypatch):
    original = Path.write_text

    def write(path, *args, **kwargs):
        if path == supervised_vm / "vm.pid":
            raise OSError("fixture disk failure")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", write)
    observed = []
    discover = vm._vz_runner_helper_pid

    def record(pid, helper):
        result = discover(pid, helper)
        if result:
            observed.extend((pid, result[0]))
        return result

    monkeypatch.setattr(vm, "_vz_runner_helper_pid", record)
    with pytest.raises(OSError, match="disk failure"):
        vm.start_vm("probe", "/workspace", background=True, ephemeral=True)
    assert observed and all(not process_is_alive(pid) for pid in observed)
    assert not (supervised_vm / "vm-supervisor.json").exists()


def test_cancellation_during_registration_stops_real_runner(supervised_vm, monkeypatch):
    runner = []

    def interrupt(pid, helper):
        runner.append(pid)
        raise KeyboardInterrupt

    monkeypatch.setattr(vm, "_vz_runner_helper_pid", interrupt)
    with pytest.raises(KeyboardInterrupt):
        vm.start_vm("probe", "/workspace", background=True, ephemeral=True)
    assert runner and not process_is_alive(runner[0])


@pytest.mark.parametrize("public_stop", (False, True))
def test_reused_foreign_process_is_never_signalled(tmp_config_dir, monkeypatch, public_stop):
    foreign = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        directory = tmp_config_dir / "agents/probe"
        directory.mkdir(parents=True)
        (directory / "vm-supervisor.json").write_text(json.dumps({
            "pid": foreign.pid, "start_token": "older-runner",
            "helper_pid": foreign.pid, "helper_start_token": "older-helper",
        }))
        if public_stop:
            from safeyolo import agent_lifecycle, platform
            from safeyolo.platform.darwin import DarwinPlatform

            monkeypatch.setattr(platform, "get_platform", lambda: DarwinPlatform())
            assert agent_lifecycle.stop_agent_by_name("probe").sandbox_state == "stopped"
        else:
            vm.stop_vm("probe")
        assert foreign.poll() is None
        assert not (directory / "vm-supervisor.json").exists()
    finally:
        foreign.terminate()
        foreign.wait(timeout=3)


@pytest.mark.parametrize("public_stop", (False, True))
def test_unknown_live_process_identity_keeps_cleanup_failure(tmp_config_dir, monkeypatch, public_stop):
    directory = tmp_config_dir / "agents/probe"
    directory.mkdir(parents=True)
    receipt = directory / "vm-supervisor.json"
    receipt.write_text(json.dumps({"pid": 100, "start_token": "known",
                                   "helper_pid": 101, "helper_start_token": "helper"}))
    monkeypatch.setattr(vm, "process_is_alive", lambda pid: True)
    monkeypatch.setattr(vm, "process_start_token", lambda pid: None)
    with pytest.raises(vm.VMError, match="Cannot establish"):
        if public_stop:
            from safeyolo import agent_lifecycle, platform
            from safeyolo.platform.darwin import DarwinPlatform

            monkeypatch.setattr(platform, "get_platform", lambda: DarwinPlatform())
            agent_lifecycle.stop_agent_by_name("probe")
        else:
            vm.stop_vm("probe")
    assert receipt.exists()


def test_public_stop_retains_receipt_for_live_owned_helper_without_runner(tmp_config_dir, monkeypatch):
    from safeyolo import agent_lifecycle, platform
    from safeyolo.platform.darwin import DarwinPlatform

    monkeypatch.setattr(platform, "get_platform", lambda: DarwinPlatform())
    exited = subprocess.Popen([sys.executable, "-c", "pass"])
    exited.wait(timeout=3)
    helper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    directory = tmp_config_dir / "agents/probe"
    directory.mkdir(parents=True)
    receipt = directory / "vm-supervisor.json"
    receipt.write_text(json.dumps({"pid": exited.pid, "start_token": "earlier-runner",
                                   "helper_pid": helper.pid, "helper_start_token": process_start_token(helper.pid)}))
    try:
        with pytest.raises(vm.VMError, match="owned helper did not stop"):
            agent_lifecycle.stop_agent_by_name("probe")
        assert helper.poll() is None
        assert receipt.exists(), "failed owned cleanup must remain visible"
    finally:
        helper.terminate()
        helper.wait(timeout=3)
        vm.stop_vm("probe")


@given(
    st.sampled_from(("absent", "valid", "relative", "missing", "not_executable")),
    st.one_of(st.none(), st.text(st.characters(exclude_categories=("Cs",), exclude_characters="\0"), max_size=12),
              st.integers(-3, 10000).map(str)),
)
def test_generated_runner_timeout_inputs_never_silently_select_direct_launch(kind, timeout):
    # Use a fresh environment per generated pair; no shell interprets the values.
    from unittest.mock import patch

    with tempfile.TemporaryDirectory() as directory:
        runner = Path(directory) / "runner"
        runner.write_text("#!/bin/sh\nexit 0\n")
        runner.chmod(0o644 if kind == "not_executable" else 0o755)
        paths = {"valid": str(runner), "relative": "runner", "missing": str(runner.parent / "missing"),
                 "not_executable": str(runner)}
        environment = {}
        if kind != "absent":
            environment["SAFEYOLO_VZ_TEST_RUNNER"] = paths[kind]
        if timeout is not None:
            environment["SAFEYOLO_VZ_TEST_TIMEOUT_SECONDS"] = timeout
        with patch.dict(os.environ, environment, clear=True):
            if kind == "absent" and timeout is None:
                assert vm._vz_test_command(["helper", "run"]) == ["helper", "run"]
            elif kind == "valid" and timeout and all(char in "0123456789" for char in timeout) and int(timeout) > 0:
                assert vm._vz_test_command(["helper", "run"])[-3:] == ["--", "helper", "run"]
            else:
                with pytest.raises(vm.VMError):
                    vm._vz_test_command(["helper", "run"])


def test_direct_command_uses_literal_runner_and_helper_paths(tmp_path, monkeypatch):
    runner = tmp_path / "runner with spaces"
    runner.write_text("#!/bin/sh\nexit 0\n")
    runner.chmod(0o755)
    monkeypatch.setenv("SAFEYOLO_VZ_TEST_RUNNER", str(runner))
    monkeypatch.setenv("SAFEYOLO_VZ_TEST_TIMEOUT_SECONDS", "003")
    assert vm._vz_test_command(["/selected path/safeyolo-vm", "run", "--overlay", "owned path"]) == [
        str(runner), "--timeout-seconds", "3", "--",
        "/selected path/safeyolo-vm", "run", "--overlay", "owned path",
    ]


@pytest.mark.parametrize("difference", ("none", "parent", "executable", "start_token", "zombie"))
def test_kernel_child_discovery_requires_parent_executable_and_stable_start(tmp_path, monkeypatch, difference):
    from safeyolo import runtime_identity

    helper = tmp_path / "safeyolo-vm"
    helper.touch()
    foreign = tmp_path / "foreign"
    foreign.touch()

    def children(pid, pids, size):
        assert pid == 40
        pids[0] = 41
        return 1  # libproc returns a PID count, not a byte count.

    def path(pid, buffer, size):
        buffer.value = os.fsencode(foreign if difference == "executable" else helper)
        return len(buffer.value)

    monkeypatch.setattr(vm.ctypes, "CDLL", lambda *args, **kwargs:
                        SimpleNamespace(proc_listchildpids=children, proc_pidpath=path))
    monkeypatch.setattr(runtime_identity, "_darwin_process_info", lambda pid: SimpleNamespace(
        pbi_ppid=99 if difference == "parent" else 40, pbi_status=5 if difference == "zombie" else 2,
        pbi_start_tvsec=1000, pbi_start_tvusec=2000,
    ))
    token = "darwin:41:1000:2000"
    monkeypatch.setattr(vm, "process_start_token", lambda pid: "reused" if difference == "start_token" else token)
    assert vm._vz_runner_helper_pid(40, helper) == ((41, token) if difference == "none" else None)


def test_kernel_child_discovery_rejects_ambiguous_helpers(tmp_path, monkeypatch):
    from safeyolo import runtime_identity

    helper = tmp_path / "safeyolo-vm"
    helper.touch()

    def children(pid, pids, size):
        pids[0], pids[1] = 41, 42
        return 2

    def path(pid, buffer, size):
        buffer.value = os.fsencode(helper)
        return len(buffer.value)

    monkeypatch.setattr(vm.ctypes, "CDLL", lambda *args, **kwargs:
                        SimpleNamespace(proc_listchildpids=children, proc_pidpath=path))
    monkeypatch.setattr(runtime_identity, "_darwin_process_info", lambda pid: SimpleNamespace(
        pbi_ppid=40, pbi_status=2, pbi_start_tvsec=1000, pbi_start_tvusec=2000,
    ))
    monkeypatch.setattr(vm, "process_start_token", lambda pid: f"darwin:{pid}:1000:2000")
    with pytest.raises(vm.VMError, match="more than one"):
        vm._vz_runner_helper_pid(40, helper)
