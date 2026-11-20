"""Run authority-controller capture and teardown with real local children."""

import json
import os
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from tests.blackbox import installed_authority as authority


@pytest.mark.parametrize("section", ["peer-support", "shared-approvals"])
@pytest.mark.parametrize("outcome", ["success", "failure", "timeout", "capture-failure"])
def test_authority_driver_keeps_parent_owned_logs_and_stops_on_failure(tmp_path, monkeypatch, section, outcome):
    root, output = tmp_path / "owned", tmp_path / "output"
    calls, children = [], []

    def prepare(_base, root, _native):
        root.mkdir()
        (root / ".safeyolo-platform-smoke").touch()
        (root / "services").mkdir()
        for name in authority.NAMES:
            (root / "agents" / name).mkdir(parents=True)

    def native(command, **_options):
        arguments = command[3:]
        calls.append(arguments)
        return "{}" if arguments[:2] == ["agent", "status"] else ""

    monkeypatch.setattr(authority, "prepare_authority_guests", prepare)
    monkeypatch.setattr(authority, "inputs", lambda *_args: {"guest": {"sha256": "controlled"}})
    monkeypatch.setattr(authority, "checked", native)
    monkeypatch.setattr(authority, "running_guest", lambda _root, name, _status:
        {"backend_pid": os.getpid(), "backend_token": "controlled", "agent_id": name, "run_id": "controlled"})
    monkeypatch.setattr(authority, "_sha256", lambda _path: "controlled")
    monkeypatch.setattr(authority, "owned_processes", lambda _root: [])
    monkeypatch.setattr(authority, "surviving_processes", lambda _processes: [])
    capture = authority.capture_guest_command

    def run_child(command, env, log, failures):
        assert command[:3] == [sys.executable, "-m", "tests.blackbox.installed_" +
                               ("peer_support" if section == "peer-support" else "shared_approvals")]
        assert env["SAFEYOLO_CONFIG_DIR"] == str(root)
        if outcome == "capture-failure":
            log.write_text("existing-log-must-survive")
        program = f'''
import os, stat, sys, time
assert stat.S_ISFIFO(os.fstat(1).st_mode)
assert stat.S_ISFIFO(os.fstat(2).st_mode)
sys.stdout.buffer.write(b'o' * 131072)
sys.stdout.buffer.flush()
sys.stderr.buffer.write(b'e' * 131072)
sys.stderr.buffer.flush()
if {outcome!r} == 'timeout':
    time.sleep(60)
sys.exit(7 if {outcome!r} == 'failure' else 0)
'''
        child, reader, finished = capture([sys.executable, "-c", program], env, log, failures)
        children.append((child, reader))
        if outcome == "timeout":
            wait = child.wait
            monkeypatch.setattr(child, "wait", lambda timeout=None: wait(timeout=1 if timeout == 900 else timeout))
        return child, reader, finished

    monkeypatch.setattr(authority, "capture_guest_command", run_child)
    args = SimpleNamespace(root=root, prepared_config=tmp_path / "prepared", output=output,
                           revision="controlled", section=section)
    if outcome == "success":
        authority.run(args)
    else:
        error = subprocess.TimeoutExpired if outcome == "timeout" else AssertionError
        with pytest.raises(error):
            authority.run(args)
    report = json.loads((output / "result.json").read_text())
    assert report["status"] == ("passed" if outcome == "success" else "incomplete")
    assert report["cleanup"] == ("failed" if outcome == "capture-failure" else "stopped")
    assert calls[-3:] == [["agent", "stop", "bbtest"], ["agent", "stop", "bbpeer"], ["stop"]]
    assert len(children) == 1
    child, reader = children[0]
    assert child.poll() is not None and not reader.is_alive()
    log = output / "driver.log"
    if outcome == "capture-failure":
        assert log.read_text() == "existing-log-must-survive"
        assert any("guest output capture failed" in failure for failure in report["cleanup_failures"])
    else:
        assert log.read_bytes() == b'o' * 131072 + b'e' * 131072
        assert log.stat().st_uid == os.getuid() and log.stat().st_gid == os.getgid()
        assert stat.S_IMODE(log.stat().st_mode) == 0o600
        assert report["cleanup_failures"] == []
        if outcome != "timeout":
            assert report["exit"] == (7 if outcome == "failure" else 0)
