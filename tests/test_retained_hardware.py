"""Exercise the reused hardware ownership boundary with retained input callers."""

from __future__ import annotations

import copy
import errno
import fcntl
import hashlib
import json
import os
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.blackbox.hardware import publish_results as hardware
from tests.blackbox.harness import macos_process_argv as macos

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def hardware_reports(tmp_path):
    reports = tmp_path / "reports"
    (reports / "guest").mkdir(parents=True)
    files = dict.fromkeys(("bin/safeyolo", "bin/safeyolo-proxy", "bin/safeyolo-coord", "assets/guest/safeyolo-guest", "assets/guest/safeyolo-coord"), "a" * 64)
    descriptor = {"digest": "sha256:" + "b" * 64, "size": 10}
    selection = {"platform": "linux-amd64", "controller_revision": "d" * 40, "selected_at": "2026-10-17T08:00:00+00:00",
                 "host": {"source_revision": "c" * 40, "executables_sha256": files},
                 "guest": dict.fromkeys(("index", "child", "archive"), descriptor)}
    run = {"lane": "kvm", "started_at": "2026-10-17T09:00:00+00:00", "finished_at": "2026-10-17T10:00:00+00:00", "exit": 0,
           "controller_revision": "d" * 40, "controller_dirty": False,
           "host_system": "Linux", "host_architecture": "x86_64"}
    installed = {"host_source_revision": "c" * 40, "profile": "production", "platform": "linux-amd64",
                 "guest": dict.fromkeys(("index", "manifest", "archive"), descriptor), "installed_files_sha256": copy.deepcopy(files)}
    sections = {"lane": "kvm", "source_revision": "c" * 40, "preparation": {"exit": 0},
                "sections": [{"section": name, "exit": 0, "result": "passed", "cleanup": "stopped"}
                             for name in hardware.SECTIONS["kvm"]]}
    data = {"selection.json": selection, "retained-run.json": run, "installed-inputs.json": installed,
            "guest/installed-sections.json": sections}

    def save():
        for name, value in data.items():
            (reports / name).write_text(json.dumps(value))

    save()
    return reports, copy.deepcopy(selection), data, save


@pytest.mark.parametrize("defect", [None, "partial", "cleanup", "failed", "source", "selection", "helper", "private"])
def test_public_projection_preserves_failures_and_artifact_attribution(hardware_reports, defect):
    reports, selection, data, save = hardware_reports
    if defect == "partial":
        data["guest/installed-sections.json"]["sections"].pop()
    elif defect in {"cleanup", "failed"}:
        row = data["guest/installed-sections.json"]["sections"][0]
        row.update(exit=2, result="cleanup_failure" if defect == "cleanup" else "preparation_failure",
                   cleanup="failed" if defect == "cleanup" else "stopped")
    elif defect == "source":
        data["installed-inputs.json"]["host_source_revision"] = "d" * 40
    elif defect == "selection":
        data["selection.json"]["host"]["source_revision"] = "d" * 40
    elif defect == "helper":
        data["installed-inputs.json"]["installed_files_sha256"]["assets/guest/safeyolo-guest"] = "e" * 64
    elif defect == "private":
        data["installed-inputs.json"]["installed_files_sha256"]["private-marker"] = "e" * 64
        data["guest/installed-sections.json"]["sections"][0]["private"] = "private-marker"
    save()
    if defect in {"source", "selection", "helper"}:
        with pytest.raises(ValueError):
            hardware.installed_result(reports, "kvm", selection)
    else:
        result = hardware.installed_result(reports, "kvm", selection)
        assert result["complete"] == (defect in {None, "private"})
        assert "private-marker" not in json.dumps(result)


@pytest.mark.parametrize("kind", ["symlink", "fifo", "oversized"])
def test_untrusted_report_reader_does_not_follow_or_block(tmp_path, kind):
    path = tmp_path / "report"
    if kind == "symlink":
        (tmp_path / "actual").write_text("{}")
        path.symlink_to(tmp_path / "actual")
    elif kind == "fifo":
        os.mkfifo(path)
    else:
        with path.open("wb") as output:
            output.truncate(hardware.MAX_REPORT_BYTES + 1)
    with pytest.raises((OSError, ValueError)):
        hardware.read_json(path)


def test_uncertain_initial_publication_is_not_replayed(tmp_path):
    class LostReply:
        calls = 0

        def comment(self, *_args):
            self.calls += 1
            raise OSError("controlled lost reply")

    attempt = dict.fromkeys(("controller_revision", "started_at", "finished_at", "exit", "cleanup", "stage", "inputs", "result"))
    attempt.update(run_id="a" * 32, lane="kvm", trigger="overnight", publication=None)
    client = LostReply()
    with pytest.raises(OSError):
        hardware.publish(tmp_path, attempt, client)
    assert json.loads((tmp_path / "attempt.json").read_bytes())["publication_uncertain"]
    with pytest.raises(ValueError, match="uncertain"):
        hardware.publish(tmp_path, attempt, client)
    assert client.calls == 1


def test_hardware_entry_filters_credentials_and_uses_retained_inputs(tmp_path):
    checkout = tmp_path / "controller"
    (checkout / "tests/blackbox").mkdir(parents=True)
    (checkout / ".gitignore").write_text("/.venv\n")
    (checkout / ".venv").symlink_to(sys.prefix, target_is_directory=True)
    consumer = checkout / "tests/blackbox/retained_inputs.py"
    consumer.write_text('''import json, os, pathlib, sys
assert 'GH_TOKEN' not in os.environ and 'GITHUB_TOKEN' not in os.environ
assert os.environ['SSL_CERT_FILE'] == 'public-ca-marker'
assert os.environ['BASH_ENV'] == '/dev/null'
assert '--guest-archive' in sys.argv and '--selection' in sys.argv
pathlib.Path(sys.argv[sys.argv.index('--artifacts')+1]).write_text(json.dumps(sys.argv[1:]))
''')
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
    subprocess.run(["git", "-C", str(checkout), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "controller"], check=True)
    revision = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "selection.json").write_bytes(b'{"frozen":"bytes"}')
    digest = hashlib.sha256((inputs / "selection.json").read_bytes()).hexdigest()
    command = ["bash", str(ROOT / "tests/blackbox/hardware/run-hardware-lane.sh"), str(checkout), revision,
               "kvm", str(inputs), digest, str(tmp_path / "handoff.json")]
    environment = dict(os.environ, GH_TOKEN="private-test-marker", GITHUB_TOKEN="private-test-marker", SSL_CERT_FILE="public-ca-marker")
    run = subprocess.run(command, env=environment, capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "private-test-marker" not in run.stdout + run.stderr + (tmp_path / "handoff.json").read_text()
    # A transferred selection with changed bytes cannot reach the consumer.
    (inputs / "selection.json").write_bytes(b"changed")
    (tmp_path / "handoff.json").unlink()
    assert subprocess.run(command, env=environment, capture_output=True, check=False).returncode != 0
    assert not (tmp_path / "handoff.json").exists()


@pytest.mark.parametrize("member", [False, True])
@pytest.mark.parametrize("device_result", ["available", "unreadable", "wrong-api"])
def test_kvm_remote_prerequisites_refresh_only_runner_groups(tmp_path, member, device_result):
    if os.geteuid() == 0:
        pytest.skip("The permission control needs an ordinary test user")
    tools = tmp_path / "tools"
    (tools / ".venv/bin").mkdir(parents=True)
    fixture = tmp_path / "device"
    fixture.touch(mode=0o600)
    if device_result == "unreadable":
        fixture.chmod(0)
    membership = tmp_path / "membership-added"
    record = tmp_path / "sudo-calls.jsonl"
    identity = tools / "id"
    identity.write_text(f'#!{sys.executable}\nimport sys\n'
                        'assert sys.argv[1:] == ["-nG", "agent"]\n'
                        f'print("agent sudo" + (" kvm" if {member!r} else ""))\n')
    sudo = tools / "sudo"
    sudo.write_text(f'''#!{sys.executable}
import json, os, pathlib, sys
args = sys.argv[1:]
with open({str(record)!r}, "a") as stream: stream.write(json.dumps(args) + "\\n")
if args == ["-n", "usermod", "-aG", "kvm", "agent"]:
    pathlib.Path({str(membership)!r}).touch()
else:
    assert args[:5] == ["-n", "-E", "-u", "agent", "--"], args
    assert {member!r} or pathlib.Path({str(membership)!r}).exists()
    os.execvp(args[5], args[5:])
''')
    python = tools / ".venv/bin/python"
    python.write_text(f'''#!{sys.executable}
import fcntl, os, sys
real_open = os.open
def open_device(path, flags):
    assert path == "/dev/kvm" and flags == os.O_RDWR
    return real_open({str(fixture)!r}, flags)
os.open = open_device
fcntl.ioctl = lambda fd, request, value: {11 if device_result == "wrong-api" else 12}
assert sys.argv[1] == "-c"
exec(sys.argv[2])
''')
    lane = tools / "tests/blackbox/hardware/run-hardware-lane.sh"
    lane.parent.mkdir(parents=True)
    lane.write_text(f'''#!/bin/bash
set -eu
test "$(umask)" = 0022
test "$SSL_CERT_FILE" = public-ca-marker
touch {shlex.quote(str(tmp_path / "lane-reached"))}
''')
    for executable in (identity, sudo, python, lane):
        executable.chmod(0o755)
    wrapper = (ROOT / "tests/blackbox/hardware/run-kvm.sh").read_text()
    start = wrapper.index("printf -v command 'set -euo pipefail\n")
    format_block = wrapper[start:wrapper.index("stage=execution\n", start)]
    formatted = subprocess.check_output(["bash", "-c", 'controller=a; input_digest=b\n' + format_block + '\nprintf "%s" "$command"'], text=True)
    prerequisite = formatted[formatted.index("test -c /dev/kvm\n"):]
    # Use a permission-controlled file in place of the absent hardware node.
    prerequisite = prerequisite.replace("test -c /dev/kvm", "test -f " + shlex.quote(str(fixture)))
    result = subprocess.run(["bash", "-c", "set -euo pipefail; umask 077\n" + prerequisite], cwd=tools,
                            env=dict(os.environ, PATH=f"{tools}:{os.environ['PATH']}", SSL_CERT_FILE="public-ca-marker"),
                            capture_output=True, text=True, timeout=10, check=False)
    assert (result.returncode == 0) == (device_result == "available"), result.stdout + result.stderr
    assert (tmp_path / "lane-reached").exists() == (device_result == "available")
    assert membership.exists() == (not member)
    calls = [json.loads(line) for line in record.read_text().splitlines()]
    assert len(calls) == (1 if member else 2)
    assert fixture.stat().st_mode & 0o777 == (0 if device_result == "unreadable" else 0o600)


@pytest.mark.parametrize("missing", [False, True])
def test_vz_transfer_copies_guest_readable_offline_files(tmp_path, missing):
    producer = tmp_path / "controller"
    producer.mkdir()
    (producer / "tracked").touch()
    subprocess.run(["git", "init", "-q", str(producer)], check=True)
    subprocess.run(["git", "-C", str(producer), "add", "."], check=True)
    subprocess.run(["git", "-C", str(producer), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "controller"], check=True)
    work = tmp_path / "work $literal"
    for name in ("source", "inputs"):
        (work / name).mkdir(parents=True)
    subprocess.run(["git", "-C", str(producer), "bundle", "create", str(work / "controller.bundle"), "HEAD"], check=True)
    archive = tmp_path / "inputs.tar"
    subprocess.run(["tar", "-cf", str(archive), "-C", str(producer), "tracked"], check=True)
    supplier = tmp_path / "supplier"
    supplier.mkdir(mode=0o755)
    expected = {"debs/python.deb": b"verified Debian bytes", "wheels/pytest.whl": b"locked wheel bytes",
                "mise-node/installs/node/22/bin/node": b"verified executable bytes"}
    for name, content in expected.items():
        path = supplier / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(0o755 if name.endswith("/node") else 0o644)
    for path in supplier.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)
    node = supplier / "mise-node/installs/node/22/bin/node"
    node.rename(tmp_path / "node-input")
    node.symlink_to(tmp_path / "node-input")
    inputs = tmp_path / "offline inputs $literal"
    if not missing:
        inputs.symlink_to(supplier, target_is_directory=True)
    # Execute the actual SSH transfer block locally; no product or VM runs.
    wrapper = (ROOT / "tests/blackbox/hardware/run-vz.sh").read_text()
    transfer = wrapper[wrapper.index("    printf -v command 'set -euo pipefail; tar"):wrapper.index("    env_options=(")]
    setup = 'umask 077; work=$1; VZ_TEST_ENV=$2; VZ_OFFLINE_TEST_INPUTS=$3; attempt=$4; ssh_command=(bash -c)\n'
    result = subprocess.run(["bash", "-c", setup + transfer, "transfer", str(work), sys.prefix, str(inputs), str(tmp_path)],
                            capture_output=True, text=True, timeout=10, check=False)
    if missing:
        assert result.returncode != 0
        return
    assert result.returncode == 0, result.stdout + result.stderr
    staged = work / "source/offline"
    assert staged.is_dir() and not staged.is_symlink()
    assert not any(path.is_symlink() for path in staged.rglob("*"))
    # Removing the supplier paths must not break the guest-visible copy.
    inputs.unlink()
    node.unlink()
    (tmp_path / "node-input").unlink()
    for name, content in expected.items():
        copied = staged / name
        assert hashlib.sha256(copied.read_bytes()).digest() == hashlib.sha256(content).digest()
        assert copied.stat().st_mode & 0o777 == (0o755 if name.endswith("/node") else 0o644)
        assert all(parent.stat().st_mode & 0o005 == 0o005 for parent in copied.parents if parent.is_relative_to(staged))
    clean = subprocess.check_output(["git", "-C", str(work / "source"), "status", "--porcelain"], text=True)
    assert clean == ""


def test_vz_lock_contender_does_not_execute_or_signal_current_owner(tmp_path):
    lock = tmp_path / "host.lock"
    work = tmp_path / "work"
    work.mkdir()
    with lock.open("wb") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        command = ["bash", str(ROOT / "tests/blackbox/hardware/run-vz.sh"), "__execute", sys.executable,
                   str(lock), str(work), "a" * 40, "b" * 64]
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=10)
        assert result.returncode == 2, result.stdout + result.stderr
        assert (work / "exit").read_text() == "2\n"
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)  # the original owner still holds the lock


def test_vz_cancellation_reaps_the_retained_input_consumer_and_releases_lock(tmp_path):
    work = tmp_path / "work"
    source = work / "source"
    (source / "tests/blackbox").mkdir(parents=True)
    (source / ".gitignore").write_text("/.venv\n")
    (source / ".venv").symlink_to(sys.prefix, target_is_directory=True)
    (source / "tests/blackbox/retained_inputs.py").write_text('''import pathlib, sys, time
pathlib.Path(sys.argv[sys.argv.index('--artifacts')+1]).write_text('consumer started')
time.sleep(60)
''')
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(["git", "-C", str(source), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "controller"], check=True)
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    (work / "inputs").mkdir()
    (work / "inputs/selection.json").write_bytes(b"frozen selection")
    digest = hashlib.sha256((work / "inputs/selection.json").read_bytes()).hexdigest()
    lock = tmp_path / "host.lock"
    lock.touch()
    command = ["bash", str(ROOT / "tests/blackbox/hardware/run-vz.sh"), "__execute", sys.executable,
               str(lock), str(work), revision, digest]
    with subprocess.Popen(command, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as child:
        try:
            deadline = time.monotonic() + 10
            while not (work / "reports").exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            assert (work / "reports").is_file(), "retained consumer did not start"
            child.send_signal(signal.SIGTERM)
            assert child.wait(timeout=10) == 143
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
    assert (work / "exit").read_text() == "143\n"
    with lock.open("rb") as released:
        fcntl.flock(released, fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_account_inspection_preserves_foreign_processes_and_reports_unknowns(monkeypatch):
    monkeypatch.setattr(macos, "account_pids", lambda _uid: [100, 101, 102])
    monkeypatch.setattr(macos.os, "getpid", lambda: 999)
    monkeypatch.setattr(macos, "process_argv", lambda pid: {100: [b"/owned/run/bin/product"], 101: [b"/foreign/run"], 102: [b"/owned/run-sibling"]}[pid])
    assert macos.owned_account_processes(502, ["/owned/run"]) == [100]

    def exited(_pid):
        raise OSError(errno.ESRCH, "controlled exit")

    monkeypatch.setattr(macos, "process_argv", exited)
    assert macos.owned_account_processes(502, ["/owned/run"]) == []
    monkeypatch.setattr(macos, "process_argv", lambda _pid: (_ for _ in ()).throw(PermissionError("controlled denial")))
    with pytest.raises(PermissionError):
        macos.owned_account_processes(502, ["/owned/run"])


@pytest.mark.parametrize("ownership", ["owned-inactive", "owned-active", "foreign"])
def test_kvm_reconciliation_requires_inactive_exact_ownership(tmp_path, ownership):
    run_id = "a" * 32
    root, pool, jobs, tools = (tmp_path / name for name in ("attempts", "pool", "jobs", "tools"))
    for path in (root, pool, jobs, tools):
        path.mkdir()
    attempt = root / run_id
    attempt.mkdir()
    (attempt / "attempt.json").write_text(json.dumps({"run_id": run_id}))
    guest = f"sy-issue889-{run_id}-fixture" if ownership != "foreign" else "sy-foreign-fixture"
    (attempt / "guest-name").write_text(guest)
    (pool / "domain").write_text(guest)
    (pool / "lease").write_text(guest + "\n")
    (pool / f"{guest}.qcow2").touch()
    (pool / f"{guest}-seed.iso").touch()
    common = f'''POOL_DIR={shlex.quote(str(pool))}
acquire_provision_lock() {{ exec 8>"$POOL_DIR/provision.lock"; flock -n 8; }}
guest_lease_path() {{ printf '%s' "$POOL_DIR/lease"; }}
'''
    (jobs / "_common.sh").write_text(common)
    virsh = tools / "virsh"
    virsh.write_text(f'''#!/bin/bash
set -eu
case "$3" in
list) cat {shlex.quote(str(pool / 'domain'))};;
domblklist) printf 'file disk vda %s\\n' {shlex.quote(str(pool / (guest + '.qcow2')))};;
domstate) printf '%s\\n' {'running' if ownership == 'owned-active' else "'shut off'"};;
*) exit 99;;
esac
''')
    virsh.chmod(0o755)
    teardown = jobs / "teardown.sh"
    teardown.write_text(f'''#!/bin/bash
set -eu
test "$1" = {shlex.quote(guest)}
rm -- {shlex.quote(str(pool / (guest + '.qcow2')))} {shlex.quote(str(pool / (guest + '-seed.iso')))}
: > {shlex.quote(str(pool / 'domain'))}
rm -- {shlex.quote(str(pool / 'lease'))}
touch {shlex.quote(str(pool / 'teardown-called'))}
''')
    config = tmp_path / "kvm.env"
    config.write_text(f"KVM_ATTEMPTS={shlex.quote(str(root))}\nHARNESS_JOBS={shlex.quote(str(jobs))}\n")
    result = subprocess.run(["bash", str(ROOT / "tests/blackbox/hardware/run-kvm.sh"), "reconcile", str(attempt)],
                            env=dict(os.environ, KVM_DEPLOYMENT_ENV=str(config), PATH=f"{tools}:{os.environ['PATH']}"),
                            capture_output=True, text=True, timeout=10, check=False)
    assert (result.returncode == 0) == (ownership == "owned-inactive"), result.stdout + result.stderr
    assert (pool / "teardown-called").exists() == (ownership == "owned-inactive")
