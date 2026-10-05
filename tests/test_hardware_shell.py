"""Independent shell controls with real locks, files and existing runner reports."""

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

from safeyolo.runtime_identity import process_start_token
from tests import test_hardware_attempt_results
from tests.blackbox.hardware.attempt_results import HardwareAttempt
from tests.blackbox.harness import macos_process_argv

ROOT = Path(__file__).resolve().parents[1]
github_fixture = test_hardware_attempt_results.github_fixture
runner_summary = test_hardware_attempt_results.runner_summary
runner_commands = test_hardware_attempt_results.runner_commands


@pytest.fixture
def kvm_host(tmp_path, runner_summary, monkeypatch):
    """Model the deployed helper receipts; do not model a hardware pass."""
    attempt, summary = runner_summary
    attempt.data["required_lanes"] = ["kvm"]
    attempt.save()
    commands = tmp_path / "commands"
    jobs = tmp_path / "jobs"
    pool = tmp_path / "pool"
    for directory in (commands, jobs, pool):
        directory.mkdir()
    state = tmp_path / "domain"
    teardown_calls = tmp_path / "teardown-calls"
    consumer = tmp_path / "guest-command"
    virsh = commands / "virsh"
    virsh.write_text(f"#!{sys.executable}\n" + """
import os, sys
from pathlib import Path
domain = Path(os.environ['FIXTURE_DOMAIN'])
pool = Path(os.environ['POOL_DIR'])
name = domain.read_text().strip() if domain.exists() else ''
arguments = sys.argv[1:]
if 'list' in arguments:
    if name: print(name)
elif 'domblklist' in arguments:
    print('Type Device Target Source\\n---- ------ ------ ------')
    disk = '/foreign/disk' if os.environ.get('FIXTURE_FAILURE') == 'foreign-disk' else str(pool / (name + '.qcow2'))
    print('file disk vda ' + disk)
    print('file cdrom sda ' + str(pool / (name + '-seed.iso')))
elif 'dumpxml' in arguments: print("<domain type='kvm'>")
elif 'domcapabilities' in arguments: print('<domain>kvm</domain>')
elif 'domstate' in arguments: print('running' if os.environ.get('FIXTURE_FAILURE') == 'active-guest' else 'shut off')
else: raise SystemExit(7)
""")
    virsh.chmod(0o755)
    for name, output in (("nproc", "8"), ("df", "Filesystem 1K-blocks Used Available Use% Mounted\\nfixture 200000000 0 200000000 0% /"), ("uname", "Linux")):
        path = commands / name
        path.write_text(f"#!/bin/bash\nprintf '%b\\n' {shlex.quote(output)}\n")
        path.chmod(0o755)
    awk = commands / "awk"
    awk.write_text("#!/bin/bash\nif [[ $* = *MemAvailable* ]]; then echo 20000000; else exec /usr/bin/awk \"$@\"; fi\n")
    awk.chmod(0o755)
    (jobs / "_common.sh").write_text("""
set -euo pipefail
acquire_provision_lock() {
    exec {PROVISION_LOCK_FD}>"$POOL_DIR/.provision.lock"
    flock -n "$PROVISION_LOCK_FD"
}
guest_lease_path() { printf '%s\\n' "$POOL_DIR/.guest-lease"; }
""")
    (jobs / "list_guests.sh").write_text("#!/bin/bash\nvirsh list --all --name\n")
    console = tmp_path / "console"
    console.write_text(f"#!{sys.executable}\n" + """
import os, time
from pathlib import Path
Path(os.environ['FIXTURE_CONSOLE_PID']).write_text(str(os.getpid()))
while not Path(os.environ['FIXTURE_CONSOLE_RELEASE']).exists(): time.sleep(0.01)
""")
    console.chmod(0o755)
    (jobs / "provision.sh").write_text("""#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/_common.sh"
acquire_provision_lock
test "$1" = --scenario
guest=sy-$2-fixture
printf '%s\\n' "$guest" > "$POOL_DIR/.guest-lease"
touch "$POOL_DIR/$guest.qcow2" "$POOL_DIR/$guest-seed.iso"
printf '%s\\n' "$guest" > "$FIXTURE_DOMAIN"
if [[ ${FIXTURE_FAILURE:-} = detached-console ]]; then
    # Model the corrected maintained console: close the provisioner's lock,
    # then retain every other inherited descriptor in a detached child.
    (exec {PROVISION_LOCK_FD}>&-; exec "$FIXTURE_CONSOLE") </dev/null >/dev/null 2>&1 &
    disown
fi
if [[ ${FIXTURE_FAILURE:-} = wait-provision ]]; then
    touch "$FIXTURE_PROVISION_READY"
    while [[ ! -f $FIXTURE_PROVISION_RELEASE ]]; do sleep 0.01; done
fi
# Hold the real lifetime lock across a child. Cleanup cannot race this work.
sleep 0.1
if [[ ${FIXTURE_FAILURE:-} = provision-failure ]]; then exit 7; fi
printf 'HARNESS_JSON:{"guest_name":"%s","guest_ip":"192.168.122.100"}\\n' "$guest"
""")
    (jobs / "teardown.sh").write_text("""#!/bin/bash
set -euo pipefail
printf '%s\\n' "$1" >> "$FIXTURE_TEARDOWN"
if [[ ${FIXTURE_FAILURE:-} != cleanup-lie ]]; then
    rm "$FIXTURE_DOMAIN" "$POOL_DIR/$1.qcow2" "$POOL_DIR/$1-seed.iso" "$POOL_DIR/.guest-lease"
fi
echo 'HARNESS_JSON:{"destroyed":true,"undefined":true}'
""")
    (jobs / "ssh_exec.sh").write_text("""#!/bin/bash
set -euo pipefail
printf '%s' "$2" | base64 -d > "$FIXTURE_CONSUMER"
echo 'HARNESS_JSON:{"exit_code":0,"timed_out":false,"stdout_b64":"","stderr_b64":""}'
""")
    (jobs / "ssh_fetch.sh").write_text(f"#!/bin/bash\n{shlex.quote(sys.executable)} - \"$@\" <<'PY'\n" + """
import base64, hashlib, json, os, sys
from pathlib import Path
if os.environ.get('FIXTURE_FAILURE') == 'missing-report': raise SystemExit(7)
source = Path(os.environ['FIXTURE_SUMMARY']).with_name(Path(sys.argv[2]).name)
content = source.read_bytes()
print('HARNESS_JSON:' + json.dumps({'content_b64':base64.b64encode(content).decode(),
    'sha256':hashlib.sha256(content).hexdigest(), 'truncated':False}))
PY
""")
    environment = {"KVM_ATTEMPTS": str(attempt.directory.parent), "HARNESS_JOBS": str(jobs), "POOL_DIR": str(pool),
                   "HARDWARE_PYTHON": sys.executable, "FIXTURE_DOMAIN": str(state), "FIXTURE_TEARDOWN": str(teardown_calls),
                   "FIXTURE_SUMMARY": str(summary), "FIXTURE_CONSUMER": str(consumer),
                   "FIXTURE_CONSOLE": str(console), "FIXTURE_CONSOLE_PID": str(tmp_path / "console-pid"),
                   "FIXTURE_CONSOLE_RELEASE": str(tmp_path / "console-release"),
                   "FIXTURE_PROVISION_READY": str(tmp_path / "provision-ready"),
                   "FIXTURE_PROVISION_RELEASE": str(tmp_path / "provision-release")}
    config = tmp_path / "kvm.env"
    config.write_text("".join(f"export {name}={shlex.quote(value)}\n" for name, value in environment.items()))
    monkeypatch.setenv("KVM_DEPLOYMENT_ENV", str(config))
    monkeypatch.setenv("PATH", str(commands) + os.pathsep + os.environ["PATH"])
    return attempt, pool, state, teardown_calls, consumer


@pytest.mark.parametrize("failure", (None, "provision-failure", "cleanup-lie", "foreign-disk", "missing-report"))
def test_kvm_shell_retains_early_identity_and_observes_actual_teardown(kvm_host, github_fixture, monkeypatch, failure):
    attempt, pool, domain, calls, consumer = kvm_host
    _github, store = github_fixture
    if failure:
        monkeypatch.setenv("FIXTURE_FAILURE", failure)
    result = subprocess.run(["bash", str(ROOT / "tests/blackbox/hardware/run-kvm.sh"), "host", str(attempt.directory)],
                            capture_output=True, text=True, timeout=10, check=False)
    restored = HardwareAttempt.restore(attempt.directory)
    assert result.returncode == (0 if failure is None else 2), result.stderr
    assert restored.passed() is (failure is None)
    assert restored.data["publication"]["verified"]
    assert restored.data["finished_at"]
    remains = failure in {"cleanup-lie", "foreign-disk"}
    assert domain.exists() is remains
    assert (pool / ".guest-lease").exists() is remains
    if failure == "foreign-disk":
        assert not calls.exists(), "uncorrelated storage must survive"
    else:
        assert calls.read_text().strip().startswith("sy-" + restored.data["owner"] + "-")
    if failure == "provision-failure":
        assert not consumer.exists(), "a missing receipt must stop candidate execution but preserve early cleanup identity"
    else:
        assert consumer.read_text().count('kvm /home/agent/issue889-results') == 1
    publication = json.dumps(json.loads(store.read_text())["comments"])
    assert str(pool) not in publication and "fixture-principal" not in publication


def test_kvm_detached_console_cannot_retain_the_attempt_lock(kvm_host, github_fixture, monkeypatch):
    import fcntl

    attempt, pool, _domain, _calls, _consumer = kvm_host
    monkeypatch.setenv("FIXTURE_FAILURE", "detached-console")
    console_pid = pool.parent / "console-pid"
    try:
        result = subprocess.run(["bash", str(ROOT / "tests/blackbox/hardware/run-kvm.sh"), "host", str(attempt.directory)],
                                capture_output=True, text=True, timeout=10, check=False)
        assert result.returncode == 0, result.stderr
        pid = int(console_pid.read_text())
        assert process_start_token(pid), "the console must still be alive when its provisioner and attempt end"
        for path in (pool / ".provision.lock", attempt.directory.parent / ".kvm.lock"):
            with path.open() as contender:
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        (pool.parent / "console-release").touch()


@pytest.mark.parametrize("signum", (signal.SIGHUP, signal.SIGINT, signal.SIGTERM))
def test_kvm_cancellation_waits_and_reaps_before_early_lease_teardown(kvm_host, github_fixture, monkeypatch, signum):
    import fcntl

    attempt, pool, _domain, calls, consumer = kvm_host
    monkeypatch.setenv("FIXTURE_FAILURE", "wait-provision")
    process = subprocess.Popen(["bash", str(ROOT / "tests/blackbox/hardware/run-kvm.sh"), "host", str(attempt.directory)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    release = pool.parent / "provision-release"
    try:
        deadline = time.monotonic() + 5
        while not (pool.parent / "provision-ready").exists():
            assert process.poll() is None, process.communicate()
            assert time.monotonic() < deadline
            time.sleep(0.01)
        process.send_signal(signum)
        time.sleep(0.05)
        assert process.poll() is None and not calls.exists(), "cancellation must wait before teardown"
        for path in (pool / ".provision.lock", attempt.directory.parent / ".kvm.lock"):
            with path.open() as contender, pytest.raises(BlockingIOError):
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        release.touch()
        _stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 2, stderr
        restored = HardwareAttempt.restore(attempt.directory)
        assert restored.data["lanes"]["kvm"]["command_exit"] == 128 + signum
        assert restored.data["lanes"]["kvm"]["cleanup"] == "verified"
        assert {"stage": "cancelled", "lane": "kvm"} in restored.data["failures"]
        assert restored.data["publication"]["verified"] and not restored.passed()
        assert calls.exists() and not consumer.exists()
    finally:
        release.touch()
        if process.poll() is None:
            process.communicate(timeout=10)


@pytest.mark.parametrize("ownership", ("inactive-owned", "active-owned", "foreign"))
def test_kvm_reconcile_requires_inactive_exact_ownership(kvm_host, monkeypatch, ownership):
    attempt, pool, domain, calls, _consumer = kvm_host
    owner = attempt.data["owner"] if ownership != "foreign" else "another-owner"
    guest = f"sy-{owner}-fixture"
    domain.write_text(guest)
    (pool / ".guest-lease").write_text(guest + "\n")
    for name in (guest + ".qcow2", guest + "-seed.iso"):
        (pool / name).touch()
    if ownership == "active-owned":
        monkeypatch.setenv("FIXTURE_FAILURE", "active-guest")
    original = (attempt.directory / "attempt.json").read_bytes()
    result = subprocess.run(["bash", str(ROOT / "tests/blackbox/hardware/run-kvm.sh"), "reconcile", str(attempt.directory)],
                            capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == (2 if ownership == "active-owned" else 0), result.stderr
    assert calls.exists() is (ownership == "inactive-owned")
    assert domain.exists() is (ownership != "inactive-owned")
    assert (pool / ".guest-lease").exists() is (ownership != "inactive-owned")
    assert (pool / (guest + ".qcow2")).exists() is (ownership != "inactive-owned")
    assert (attempt.directory / "attempt.json").read_bytes() == original, "reconciliation must preserve the failed original"


def test_single_lane_publication_does_not_need_or_start_its_sibling(runner_summary, github_fixture):
    attempt, summary = runner_summary
    github, _store = github_fixture
    attempt.data["required_lanes"] = ["kvm"]
    attempt.data["lanes"]["kvm"]["cleanup"] = "verified"
    attempt.retain_lane("kvm", summary)
    attempt.finish()
    assert attempt.execution_succeeded()
    with pytest.raises(ValueError):
        attempt.start_lane("vz")
    from tests.blackbox.hardware.publish_results import publish_attempt
    publish_attempt(attempt, github)
    assert HardwareAttempt.restore(attempt.directory).passed()


def test_publication_cli_rejects_untrusted_selection_before_any_candidate(tmp_path, github_fixture):
    _github, store = github_fixture
    publisher = ROOT / "tests/blackbox/hardware/publish_results.py"
    result = subprocess.run([sys.executable, "-I", "-B", str(publisher), "--begin", "vz", "--root", str(tmp_path / "attempts"),
                             "--trigger", "on-demand", "--authorized-commit", "refs/pull/905/head"],
                            capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 2
    attempt = HardwareAttempt.restore(Path(result.stdout.strip()))
    assert attempt.data["source_revision"] is None and not attempt.data["lanes"]
    assert {"stage": "selection", "lane": None} in attempt.data["failures"]
    assert attempt.data["publication"]["verified"]
    assert not any('/commits/' in route for route, _method in json.loads(store.read_text())["calls"])


@pytest.mark.parametrize("signum", (None, signal.SIGHUP, signal.SIGINT, signal.SIGTERM))
def test_vz_local_lock_and_filtered_runner_retain_exit_after_cancellation(tmp_path, signum):
    """Run the Unix shell/lock boundary; this command fixture boots no guest."""
    import fcntl

    work = tmp_path / "work"
    source = work / "source"
    blackbox = source / "tests/blackbox"
    blackbox.mkdir(parents=True)
    states = tmp_path / "states"
    states.mkdir()
    runner = blackbox / "run-installed.sh"
    runner.write_text(f"#!{sys.executable}\n" + """
import json, os, signal, sys, time
from pathlib import Path
assert sys.argv[1] == 'vz'
assert all(name not in os.environ for name in ('GH_TOKEN','RUNDECK_TOKEN','SSH_AUTH_SOCK','PYTHONPATH'))
assert os.environ['SSL_CERT_FILE'] == '/public-ca'
output = Path(sys.argv[sys.argv.index('--artifacts')+1])
output.mkdir()
for number in (signal.SIGHUP,signal.SIGINT,signal.SIGTERM):
    signal.signal(number, lambda received, _frame: sys.exit(128+received))
(output/'ready').write_text(json.dumps({'pid':os.getpid()}))
if '--wait' in os.environ.get('FIXTURE_MODE', ''): raise SystemExit('control must have been filtered')
time.sleep(1)
raise SystemExit(7)
""")
    runner.chmod(0o755)
    for command in (("init",), ("add", "."), ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "runner fixture")):
        subprocess.run(["git", "-C", str(source), *command], check=True, capture_output=True)
    selected = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    lock = tmp_path / "protected-lock"
    lock.touch(mode=0o444)
    command = ["bash", str(ROOT / "tests/blackbox/hardware/run-vz.sh"), "__execute", sys.executable, str(lock),
               str(work), str(states), selected, "e" * 64, sys.executable, "120", "a" * 32]
    environment = dict(os.environ, GH_TOKEN="fixture-principal", RUNDECK_TOKEN="fixture-rundeck", SSH_AUTH_SOCK="/private/agent",
                       PYTHONPATH="/private/source", SSL_CERT_FILE="/public-ca")
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
    try:
        deadline = time.monotonic() + 5
        while not (work / "results/ready").exists():
            assert process.poll() is None, process.communicate()
            assert time.monotonic() < deadline
            time.sleep(0.01)
        with lock.open() as contender, pytest.raises(BlockingIOError):
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if signum is not None:
            process.send_signal(signum)
        _stdout, stderr = process.communicate(timeout=5)
        expected = 7 if signum is None else 128 + signum
        assert process.returncode == expected, stderr
        assert int((work / "exit").read_text()) == expected
        with lock.open() as contender:
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def test_vz_lock_contender_leaves_existing_owner_alive(tmp_path):
    import fcntl

    lock = tmp_path / "protected-lock"
    lock.touch(mode=0o444)
    work = tmp_path / "new-attempt"
    work.mkdir()
    with lock.open() as owner:
        fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = subprocess.run(["bash", str(ROOT / "tests/blackbox/hardware/run-vz.sh"), "__execute", sys.executable, str(lock), str(work)],
                                capture_output=True, text=True, timeout=5, check=False)
        assert result.returncode == 2
        assert (work / "exit").read_text() == "2\n"
        fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert list(work.iterdir()) == [work / "exit"]


@pytest.mark.parametrize("escape", (False, True))
def test_vz_transfer_uses_index_and_collect_survives_observer_loss(tmp_path, github_fixture, monkeypatch, escape):
    """Exercise the whole shell recipe through a local SSH command fixture."""
    commands = tmp_path / "commands"
    commands.mkdir()
    for name, body in {
        "uname": "case $1 in -s) echo Darwin;; -m) echo arm64;; esac",
        "sysctl": "case $2 in hw.model) echo Mac16,1;; hw.optional.hypervisor) echo 1;; esac",
    }.items():
        script = commands / name
        script.write_text("#!/bin/bash\n" + body + "\n")
        script.chmod(0o755)
    ssh = commands / "ssh"
    ssh.write_text(f"#!{sys.executable}\n" + """
import subprocess, sys
command = sys.argv[-1]
if '--owned-roots' in command: print('{"owned_processes":[]}'); raise SystemExit(0)
if 'check_vz_ports' in command: raise SystemExit(0)
raise SystemExit(subprocess.run(command,shell=True,executable='/bin/bash',stdin=sys.stdin).returncode)
""")
    ssh.chmod(0o755)
    source = tmp_path / "prepared-source"
    blackbox = source / "tests/blackbox"
    blackbox.mkdir(parents=True)
    runner = blackbox / "run-installed.sh"
    runner.write_text(f"#!{sys.executable}\n" + """
import os, sys, time
from pathlib import Path
assert 'GH_TOKEN' not in os.environ and 'FIXTURE_GITHUB_STORE' not in os.environ
results = Path(sys.argv[sys.argv.index('--artifacts')+1])
results.mkdir()
(results/'ready').touch()
time.sleep(2)
for name in ('installed-summary.json','installed-sections.json'): (results/name).write_text('{}')
raise SystemExit(7)
""")
    runner.chmod(0o755)
    for command in (("init",), ("add", "."), ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "runner fixture")):
        subprocess.run(["git", "-C", str(source), *command], check=True, capture_output=True)
    selected = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    inputs = tmp_path / "inputs"
    prepared = inputs / selected
    prepared.mkdir(parents=True)
    source.rename(prepared / "source")
    payload = prepared / "payload"
    payload.mkdir()
    (payload / "allowed").write_bytes(b'indexed input')
    os.mkfifo(payload / "unindexed-private-fifo")
    index = json.dumps({"files": {"../../foreign" if escape else "allowed": hashlib.sha256(b'indexed input').hexdigest()}})
    (payload / "staged-inputs.json").write_text(index)
    (prepared / "staged-sha256").write_text(hashlib.sha256(index.encode()).hexdigest())
    _github, store = github_fixture
    data = json.loads(store.read_text())
    data['selected'] = selected
    store.write_text(json.dumps(data))
    environment = {"VZ_ATTEMPTS": str(tmp_path / "attempts"), "VZ_SSH_CONFIG": str(tmp_path / "existing-ssh"),
                   "VZ_TART_INPUTS": str(inputs), "VZ_PYTHON": sys.executable,
                   "VZ_RUNTIME_PATH": os.environ['PATH'], "HARDWARE_PYTHON": sys.executable,
                   "VZ_RUNS": str(tmp_path / "runs"), "VZ_STATES": str(tmp_path / "states"),
                   "VZ_LOCK": str(tmp_path / "lock"), "VZ_CA_BUNDLE": "/public-ca", "VZ_OBSERVER_TIMEOUT": "0"}
    Path(environment['VZ_LOCK']).touch(mode=0o444)
    config = tmp_path / "vz.env"
    config.write_text("".join(f"export {name}={shlex.quote(value)}\n" for name, value in environment.items()))
    monkeypatch.setenv("VZ_DEPLOYMENT_ENV", str(config))
    monkeypatch.setenv("PATH", str(commands) + os.pathsep + os.environ['PATH'])
    monkeypatch.setenv("GH_TOKEN", "fixture-private-principal")
    script = ROOT / "tests/blackbox/hardware/run-vz.sh"
    started = subprocess.run(["/bin/bash", str(script), "on-demand", selected], capture_output=True, text=True, timeout=10, check=False)
    assert started.returncode == 2, started.stderr
    directories = list((tmp_path / "attempts").iterdir())
    assert len(directories) == 1
    attempt = HardwareAttempt.restore(directories[0])
    work = tmp_path / "runs" / attempt.data['run_id'][:8]
    if escape:
        assert not work.exists(), "escaping indexed input must fail before remote filesystem changes"
        assert {"stage": "transfer", "lane": "vz"} in attempt.data['failures']
        assert attempt.data['finished_at'] and attempt.data['publication']['verified']
        return
    assert attempt.data['finished_at'] is None, "observer timeout must preserve the running local attempt"
    assert not (work / "payload/unindexed-private-fifo").exists()
    deadline = time.monotonic() + 5
    while not (work / "results/ready").exists():
        assert time.monotonic() < deadline
        time.sleep(0.01)
    assert not (work / "exit").exists(), "observer loss must not cancel a healthy local command"
    config.write_text(config.read_text().replace("VZ_OBSERVER_TIMEOUT=0", "VZ_OBSERVER_TIMEOUT=5"))
    collected = subprocess.run(["/bin/bash", str(script), "collect", str(attempt.directory)],
                               capture_output=True, text=True, timeout=10, check=False)
    assert collected.returncode == 2, collected.stderr
    restored = HardwareAttempt.restore(attempt.directory)
    assert restored.data['lanes']['vz']['command_exit'] == 7
    assert restored.data['publication']['verified'] and not restored.passed()
    assert {"stage": "report", "lane": "vz"} in restored.data['failures']
    assert json.loads((work / "local.json").read_text())['start_token']


def test_account_inspection_preserves_foreign_argv_and_reports_unknowns(monkeypatch):
    monkeypatch.setattr(macos_process_argv, "account_pids", lambda _uid: [11, 12, 13])
    def arguments(pid):
        if pid == 13:
            raise ProcessLookupError(3, 'exited')
        return [b'python', b'/owned/state/config.yaml' if pid == 11 else b'/foreign/state/config.yaml']
    monkeypatch.setattr(macos_process_argv, "process_argv", arguments)
    assert macos_process_argv.owned_account_processes(502, ['/owned/state']) == [11]
    def unavailable(_pid):
        raise PermissionError(1, 'inspection denied')
    monkeypatch.setattr(macos_process_argv, "process_argv", unavailable)
    with pytest.raises(PermissionError):
        macos_process_argv.owned_account_processes(502, ['/owned/state'])
