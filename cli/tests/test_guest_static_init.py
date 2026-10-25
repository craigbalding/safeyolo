"""Run static init with real Bash/keygen and gated network/filesystem commands."""

import os
import re
import select
import shutil
import signal
import stat
import subprocess
from contextlib import ExitStack, contextmanager
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
KEYGEN = shutil.which("ssh-keygen")


@pytest.fixture
def guest(tmp_path):
    assert KEYGEN, "Static-init controls require OpenSSH ssh-keygen"
    for directory in ("bin", "dev", "etc/ssh", "safeyolo", "safeyolo-status", "var/log"):
        (tmp_path / directory).mkdir(parents=True)
    (tmp_path / "safeyolo/authorized_keys").write_text("operator-public-key\n")
    (tmp_path / "pid1-limits").write_text("Max open files 65536 65536 files\n")
    for name in ("guest-init", "guest-init-static"):
        source = (REPO_ROOT / f"cli/src/safeyolo/{name}.sh").read_text()
        # Keep both complete shell programs and the real static-init-done
        # boundary. Redirect paths; no host mounts, network or accounts change.
        source = re.sub(
            r"/(?:dev|etc|home/agent|root|run|safeyolo(?:-status)?|var/log|workspace)\b",
            lambda match: str(tmp_path) + match[0], source,
        ).replace("/usr/sbin/sshd", str(tmp_path / "bin/sshd"))
        source = source.replace("/proc/1/limits", str(tmp_path / "pid1-limits"))
        path = tmp_path / "safeyolo" / name
        path.write_text(source)
        path.chmod(0o755)
    per_run = tmp_path / "safeyolo/guest-init-per-run"
    per_run.write_text('#!/bin/bash\ntouch "$TEST_ROOT/per-run-started"\n')
    per_run.chmod(0o755)
    (tmp_path / "safeyolo/per-run-go").touch()
    commands = {
        "hostname": "echo fixture-guest\n",
        "mountpoint": "exit 0\n",
        "mount": "exit 0\n",
        "chown": "exit 0\n",
        "sysctl": "exit 0\n",
        "prlimit": "exit 0\n",
        "usermod": 'printf "authorized-keys-ready\\n" >&"$TEST_EVENTS_FD"\n',
        "sshd": (
            'touch "$TEST_ROOT/sshd-started"\n'
            'printf "sshd-started\\n" >&"$TEST_EVENTS_FD"\n'
        ),
        "ip": (
            'if [ "$*" = "link set lo up" ]; then\n'
            '    printf "network-started\\n" >&"$TEST_EVENTS_FD"\n'
            '    read -r release <&"$TEST_NETWORK_GATE"\n'
            '    exit "$TEST_NETWORK_STATUS"\n'
            'fi\n'
            'exit 1\n'
        ),
        "ssh-keygen": (
            '[ "$*" = -A ] || exit 90\n'
            'echo "$$" > "$TEST_ROOT/keygen-pid"\n'
            'printf "keygen-started\\n" >&"$TEST_EVENTS_FD"\n'
            'read -r release <&"$TEST_KEYGEN_GATE"\n'
            '[ "$TEST_KEYGEN_FAIL" = 0 ] || exit 1\n'
            '"$TEST_KEYGEN" -A -f "$TEST_ROOT" || exit $?\n'
            'printf "keygen-finished\\n" >&"$TEST_EVENTS_FD"\n'
        ),
    }
    for name, command in commands.items():
        path = tmp_path / "bin" / name
        path.write_text("#!/bin/bash\nset -e\n" + command)
        path.chmod(0o755)
    return tmp_path


@contextmanager
def _boot(root, *, fail_keygen=False, network_status=0):
    for marker in ("sshd-started", "safeyolo-status/static-init-done", "per-run-started"):
        (root / marker).unlink(missing_ok=True)
    with ExitStack() as stack:
        pipes = [os.pipe() for _ in range(3)]
        for pipe in pipes:
            for descriptor in pipe:
                stack.callback(os.close, descriptor)
        (events, events_write), (keygen, keygen_release), (network, network_release) = pipes
        environment = os.environ | {
            "PATH": f"{root / 'bin'}:{os.environ['PATH']}",
            "TEST_ROOT": str(root), "TEST_KEYGEN": KEYGEN,
            "TEST_EVENTS_FD": str(events_write),
            "TEST_KEYGEN_GATE": str(keygen), "TEST_NETWORK_GATE": str(network),
            "TEST_KEYGEN_FAIL": str(int(fail_keygen)),
            "TEST_NETWORK_STATUS": str(network_status),
        }
        process = subprocess.Popen(
            ["/bin/bash", str(root / "safeyolo/guest-init")], env=environment,
            pass_fds=(events_write, keygen, network),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True,
        )
        try:
            yield process, events, keygen_release, network_release
        finally:
            # Also clean up descendants if an assertion exposes a broken join
            # or cancellation path in the candidate being tested.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # The entire fixture process group has already exited.
            process.communicate(timeout=10)


def _wait_events(descriptor, *expected):
    received = set()
    while set(expected) - received:
        assert select.select([descriptor], [], [], 10)[0], (
            f"Missing static-init events: {set(expected) - received}"
        )
        received.update(os.read(descriptor, 4096).decode().splitlines())


def _finish(process, expected_status=0):
    stdout, stderr = process.communicate(timeout=20)
    assert process.returncode == expected_status, stdout + stderr


def test_keygen_overlaps_setup_but_sshd_and_static_completion_wait(guest):
    # An old image's shared keys must be replaced, even when work is parallel.
    old_key = guest / "etc/ssh/ssh_host_ed25519_key"
    subprocess.run(
        [KEYGEN, "-q", "-t", "ed25519", "-N", "", "-f", str(old_key)],
        check=True, capture_output=True, timeout=10,
    )
    old_public = old_key.with_suffix(".pub").read_bytes()
    with _boot(guest) as (process, events, keygen, network):
        _wait_events(events, "keygen-started", "network-started")
        assert not old_key.exists()
        os.write(network, b"continue\n")
        _wait_events(events, "authorized-keys-ready")
        assert not (guest / "sshd-started").exists()
        assert not (guest / "safeyolo-status/static-init-done").exists()
        assert not (guest / "per-run-started").exists()
        assert not (guest / "etc/ssh/.safeyolo-host-keys-generated").exists()
        for home in ("home/agent", "root"):
            ssh = guest / home / ".ssh"
            assert (ssh / "authorized_keys").read_text() == "operator-public-key\n"
            assert stat.S_IMODE(ssh.stat().st_mode) == 0o700
            assert stat.S_IMODE((ssh / "authorized_keys").stat().st_mode) == 0o600
        os.write(keygen, b"continue\n")
        _wait_events(events, "keygen-finished", "sshd-started")
        _finish(process)

    assert (guest / "safeyolo-status/static-init-done").read_text() == "ready\n"
    assert (guest / "per-run-started").is_file()
    assert (guest / "etc/ssh/.safeyolo-host-keys-generated").is_file()
    assert old_key.with_suffix(".pub").read_bytes() != old_public
    keys = list((guest / "etc/ssh").glob("ssh_host_*_key"))
    assert keys
    for key in keys:
        assert stat.S_IMODE(key.stat().st_mode) == 0o600
        subprocess.run(
            [KEYGEN, "-l", "-f", str(key)], check=True, capture_output=True, timeout=10,
        )

    # A retained overlay keeps its identity and does not generate keys again.
    public_keys = {path.name: path.read_bytes() for path in old_key.parent.glob("*.pub")}
    with _boot(guest) as (process, events, _keygen, network):
        _wait_events(events, "network-started")
        os.write(network, b"continue\n")
        _wait_events(events, "authorized-keys-ready", "sshd-started")
        _finish(process)
    assert {path.name: path.read_bytes() for path in old_key.parent.glob("*.pub")} == public_keys


def test_completed_keygen_does_not_skip_remaining_static_setup(guest):
    with _boot(guest) as (process, events, keygen, network):
        _wait_events(events, "keygen-started", "network-started")
        os.write(keygen, b"continue\n")
        _wait_events(events, "keygen-finished")
        assert not (guest / "safeyolo-status/static-init-done").exists()
        assert not (guest / "per-run-started").exists()
        assert not (guest / "sshd-started").exists()
        os.write(network, b"continue\n")
        _wait_events(events, "authorized-keys-ready", "sshd-started")
        _finish(process)


def test_failed_static_setup_cancels_and_reaps_keygen(guest):
    with _boot(guest, network_status=23) as (process, events, _keygen, network):
        _wait_events(events, "keygen-started", "network-started")
        keygen_pid = int((guest / "keygen-pid").read_text())
        os.write(network, b"fail\n")
        _finish(process, expected_status=23)
        with pytest.raises(ProcessLookupError):
            os.kill(keygen_pid, 0)
    assert not (guest / "sshd-started").exists()
    assert not (guest / "safeyolo-status/static-init-done").exists()
    assert not (guest / "per-run-started").exists()
    assert not (guest / "etc/ssh/.safeyolo-host-keys-generated").exists()


def test_keygen_failure_remains_retryable(guest):
    with _boot(guest, fail_keygen=True) as (process, events, keygen, network):
        _wait_events(events, "keygen-started", "network-started")
        os.write(network, b"continue\n")
        _wait_events(events, "authorized-keys-ready")
        os.write(keygen, b"fail\n")
        _wait_events(events, "sshd-started")
        _finish(process)
    # Keep the existing best-effort keygen failure behavior, including retry.
    assert not (guest / "etc/ssh/.safeyolo-host-keys-generated").exists()
    with _boot(guest) as (process, events, keygen, network):
        _wait_events(events, "keygen-started", "network-started")
        os.write(keygen, b"continue\n")
        os.write(network, b"continue\n")
        _wait_events(events, "keygen-finished", "authorized-keys-ready", "sshd-started")
        _finish(process)
    assert (guest / "etc/ssh/.safeyolo-host-keys-generated").is_file()
