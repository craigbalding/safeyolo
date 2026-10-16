"""Exercise the real static terminal child, with only its vsock transport replaced.

Run as guest root on Linux with a C compiler and static libc. A socket
pair replaces the unavailable host vsock connection. PTY setup, libc group
lookup, identity changes and command execution run in the executable itself.
Set SAFEYOLO_VSOCK_TERM to test an unmodified native-architecture build through
strace syscall injection on a native Linux kernel. The default linker fixture
also works under gVisor, whose ARM64 ptrace cannot inject syscalls.
"""

from __future__ import annotations

import grp
import os
import select
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def terminal(tmp_path_factory):
    if sys.platform != "linux" or os.geteuid() != 0:
        pytest.skip("the terminal child needs Linux guest root")
    supplied = os.environ.get("SAFEYOLO_VSOCK_TERM")
    if supplied:
        assert shutil.which("strace"), "the unmodified executable needs strace"
        return Path(supplied).resolve(), "strace"
    output = tmp_path_factory.mktemp("vsock-build") / "vsock-term"
    subprocess.run(
        ["cc", "-static", "-O2", "-o", str(output),
         str(REPOSITORY / "guest/vsock-term.c"),
         str(REPOSITORY / "tests/fixtures/vsock-term-syscalls.c"), "-lutil",
         *[f"-Wl,--wrap={name}" for name in (
             "socket", "bind", "listen", "accept", "chdir", "setgid", "initgroups", "setuid")]],
        check=True, timeout=30,
    )
    return output, "linker"


def run_terminal(terminal, workspace, trace, *, failure=None, command=None, typed=b""):
    """Replace only socket setup; inject the selected real setup syscall failure."""
    peer, listener = socket.socketpair()
    executable, backend = terminal
    with peer, listener:
        accepted = os.dup(listener.fileno())
        try:
            # Both listen calls use the inherited descriptor. After data accept
            # closes it, the optional control poll sees a closed descriptor.
            injections = [
                f"socket:retval={listener.fileno()}:when=1..2",
                "bind:retval=0:when=1..2",
                "listen:retval=0:when=1..2",
                f"accept:retval={accepted}:when=1",
            ]
            if failure:
                injections.append(f"{failure}:error=EACCES")
            arguments = ["strace", "-f", "-qq", "-o", str(trace)]
            for injection in injections:
                arguments += ["-e", "inject=" + injection]
            environment = os.environ.copy()
            if backend == "linker":
                arguments = []
                environment["TEST_TERMINAL_SOCKET"] = str(listener.fileno())
                if failure:
                    environment["TEST_TERMINAL_FAILURE"] = "initgroups" if failure == "setgroups" else failure
            arguments += [str(executable), "--uid", "1000", "--gid", "1000",
                          "--cwd", str(workspace), *(command or [
                              "/bin/sh", "-c", "echo COMMAND_EXECUTED; echo EXECUTED > marker"])]
            with subprocess.Popen(
                arguments, pass_fds=(listener.fileno(), accepted),
                env=environment, cwd=workspace.parent,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ) as process:
                listener.close()
                os.close(accepted)
                accepted = -1
                if typed:
                    peer.sendall(typed)
                output = bytearray()
                deadline = time.monotonic() + 15
                try:
                    while time.monotonic() < deadline:
                        if select.select([peer], [], [], 0.1)[0]:
                            chunk = peer.recv(65536)
                            if not chunk:
                                break
                            output.extend(chunk)
                        elif process.poll() is not None:
                            break
                    stdout, stderr = process.communicate(timeout=2)
                except BaseException:
                    # Popen's context waits; kill a failed probe before that wait.
                    process.kill()
                    process.wait(timeout=5)
                    raise
            return process.returncode, output.decode(), stdout.decode(), stderr.decode()
        finally:
            if accepted >= 0:
                os.close(accepted)


@pytest.mark.parametrize("syscall,stage", [
    ("chdir", "chdir"), ("setgid", "setgid"),
    ("setgroups", "initgroups"), ("setuid", "setuid"),
])
def test_setup_failure_never_executes_command(terminal, tmp_path, syscall, stage):
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o777)
    workspace.chmod(0o777)
    trace = tmp_path / "trace"
    code, output, stdout, stderr = run_terminal(terminal, workspace, trace, failure=syscall)

    assert code == 1, (output, stdout, stderr)
    assert f"vsock-term: {stage}: Permission denied" in output, (output, stdout, stderr)
    assert not (workspace / "marker").exists()
    assert "COMMAND_EXECUTED" not in output
    # The tracer must reach the selected setup call, not an earlier failure.
    if terminal[1] == "strace":
        assert f"{syscall}(" in trace.read_text()
        assert not any('execve("/bin/sh"' in line for line in trace.read_text().splitlines())


def test_identity_groups_directory_and_terminal(terminal, tmp_path):
    memberships = {group.gr_gid for group in grp.getgrall() if "agent" in group.gr_mem}
    memberships.discard(1000)
    if not memberships:
        pytest.skip("success proof needs an agent supplementary group in the guest")
    group = min(memberships)
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o777)
    workspace.chmod(0o777)
    protected = workspace / "group-only"
    protected.write_text("GROUP_ACCESS\n")
    os.chown(protected, 0, group)
    protected.chmod(0o640)
    trace = tmp_path / "trace"
    command = ["/usr/bin/timeout", "5", "/bin/sh", "-ec",
               'printf "uid="; id -u; printf "gid="; id -g; '
               'printf "groups="; id -G; pwd; test -t 0 && test -t 1 && test -t 2; '
               'stty size; cat group-only; read -r reply; printf "read:%s\\n" "$reply"; '
               'echo EXECUTED > marker; exit 7']
    code, output, stdout, stderr = run_terminal(terminal, workspace, trace, command=command, typed=b"hello\n")

    assert code == 7, (output, stdout, stderr)
    assert "uid=1000\r\n" in output and "gid=1000\r\n" in output
    groups = next(line for line in output.splitlines() if line.startswith("groups="))
    assert set(map(int, groups.removeprefix("groups=").split())) == memberships | {1000}
    assert str(workspace) in output
    assert "24 80\r\n" in output and "read:hello\r\n" in output
    assert "GROUP_ACCESS\r\n" in output
    assert (workspace / "marker").read_text() == "EXECUTED\n"
    if terminal[1] == "strace":
        before_command = trace.read_text().split('execve("/usr/bin/timeout"', 1)[0]
        assert '"/etc/nsswitch.conf"' in before_command
        assert '"/etc/group"' in before_command
        assert "libnss_" not in before_command
