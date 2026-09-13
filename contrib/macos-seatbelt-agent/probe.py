#!/usr/bin/env python3
"""Run inside the configured entry; all paths belong to disposable test fixtures.

The operator supplies a readable canary outside the account home, a listening
loopback port, and optionally an outside UDS and same-UID unsandboxed process.
No external service is contacted. A failed assertion is a failed acceptance.
"""

import argparse
import ctypes
import errno
import json
import os
import pty
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path


def denied(operation):
    try:
        operation()
    except OSError as exc:
        assert exc.errno in (errno.EPERM, errno.EACCES), exc
        return
    raise AssertionError("operation unexpectedly succeeded")


def run(command, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, timeout=45, **kwargs)
    assert result.returncode == 0, (command, result.stdout, result.stderr)
    return result.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--outside-file", required=True, type=Path)
    parser.add_argument("--loopback-port", required=True, type=int)
    parser.add_argument("--outside-socket")
    parser.add_argument("--outside-pid", type=int)
    parser.add_argument("--tmux", default="tmux")
    args = parser.parse_args()
    results = []
    observations = {}
    home = Path.home()
    assert os.getuid() != 0
    assert Path(os.environ["TMPDIR"]).is_relative_to(home)
    with tempfile.TemporaryDirectory(prefix="seatbelt-probe-", dir=home) as directory:
        root = Path(directory)
        sample = root / "sample"
        sample.write_text("home-rw")
        assert sample.read_text() == "home-rw"
        denied(args.outside_file.read_text)
        denied(lambda: args.outside_file.open("a"))
        alias = root / "outside-alias"
        alias.symlink_to(args.outside_file)
        denied(alias.read_text)
        results.append("home read/write; outside file and symlink denied")

        master, slave = pty.openpty()
        try:
            os.write(slave, b"pty-ok\n")
            assert b"pty-ok" in os.read(master, 100)
        finally:
            os.close(master)
            os.close(slave)
        results.append("PTY")

        with socket.socket(socket.AF_UNIX) as server:
            address = str(root / "test.sock")
            server.bind(address)
            server.listen(1)
            with socket.socket(socket.AF_UNIX) as client:
                client.connect(address)
                peer, _ = server.accept()
                with peer:
                    client.sendall(b"uds-ok")
                    assert peer.recv(100) == b"uds-ok"
        results.append("home UDS bind/connect/exchange")
        if args.outside_socket:
            with socket.socket(socket.AF_UNIX) as client:
                denied(lambda: client.connect(args.outside_socket))
            alias = root / "socket-alias"
            alias.symlink_to(args.outside_socket)
            with socket.socket(socket.AF_UNIX) as client:
                denied(lambda: client.connect(str(alias)))
            with socket.socket(socket.AF_UNIX) as client:
                client.bind(str(root / "bound-client.sock"))
                denied(lambda: client.connect(args.outside_socket))
            results.append("outside UDS, symlink and home-bound client denied")
        with socket.socket() as client:
            client.settimeout(2)
            denied(lambda: client.connect(("127.0.0.1", args.loopback_port)))
        results.append("direct IP connect denied")

        child = subprocess.Popen(["/bin/sleep", "30"])
        try:
            os.kill(child.pid, 0)
            libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            libproc.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
            libproc.proc_pidinfo.restype = ctypes.c_int
            buffer = ctypes.create_string_buffer(4096)
            # PROC_PIDTASKINFO from the macOS SDK's sys/proc_info.h.
            assert libproc.proc_pidinfo(child.pid, 4, 0, buffer, len(buffer)) > 0
            if args.outside_pid:
                denied(lambda: os.kill(args.outside_pid, 0))
                # Some libproc metadata remains visible on tested macOS even
                # with no process-info allowance. Record this limitation rather
                # than reporting it as a successfully enforced boundary.
                observations["outside_taskinfo_bytes"] = libproc.proc_pidinfo(
                    args.outside_pid, 4, 0, buffer, len(buffer)
                )
            child.send_signal(signal.SIGTERM)
            child.wait(timeout=5)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
        results.append("child signalling/info; outside same-UID signal denied")

        source = root / "hello.c"
        source.write_text('#include <stdio.h>\nint main(void) { puts("c-ok"); }\n')
        run(["/usr/bin/cc", str(source), "-o", str(root / "hello")])
        assert run([str(root / "hello")]).strip() == "c-ok"
        swift = root / "hello.swift"
        swift.write_text('print("swift-ok")\n')
        run(["/usr/bin/swiftc", "-module-cache-path", str(root / "modules"), str(swift), "-o", str(root / "swift")])
        assert run([str(root / "swift")]).strip() == "swift-ok"
        results.append("C and Swift compile/execute")

        tmux = [args.tmux, "-S", str(root / "tmux.sock"), "-f", "/dev/null"]
        try:
            run([*tmux, "new-session", "-d", "-s", "probe", "/bin/sh -c 'echo tmux-ok; sleep 30'"])
            deadline = time.monotonic() + 5
            while True:
                pane = run([*tmux, "capture-pane", "-p", "-t", "probe"])
                if "tmux-ok" in pane:
                    break
                assert time.monotonic() < deadline, "tmux pane never became ready"
                time.sleep(0.05)
        finally:
            subprocess.run([*tmux, "kill-server"], capture_output=True, timeout=5)
        results.append("tmux server/pane over home socket")
    print(json.dumps({"status": "pass", "checks": results, "observations": observations}))


if __name__ == "__main__":
    main()
