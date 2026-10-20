"""Probe native proxy control on an unchanged macOS Seatbelt SSH route.

Normal and failed launches use the native CLI. The held-start fixture uses
only the native proxy's setsid/log redirection while it holds the real policy
lock. It does not publish a native process record on the proxy's behalf.
"""

from __future__ import annotations

import argparse
import ctypes
import fcntl
import json
import signal
import subprocess
import sys
import time
from pathlib import Path


class ProcessInfo(ctypes.Structure):
    _fields_ = [
        ("first", ctypes.c_uint32 * 12),
        ("command", ctypes.c_char * 16),
        ("name", ctypes.c_char * 32),
        ("other", ctypes.c_uint32 * 5),
        ("seconds", ctypes.c_uint64),
        ("microseconds", ctypes.c_uint64),
    ]


def birth(pid):
    """Use the same kernel birth fields as host_platform::macos_process_token."""
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    info = ProcessInfo()
    assert ctypes.sizeof(info) == 136
    count = library.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
    if count != ctypes.sizeof(info):
        return None
    assert info.first[3] == pid and info.seconds and info.microseconds < 1_000_000
    return f"darwin:{pid}:{info.seconds}:{info.microseconds}"


def save(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value) + "\n")
    temporary.replace(path)


def native(root, operation):
    result = subprocess.run([str(root / "bin/safeyolo"), "--root", str(root), operation],
                            capture_output=True, text=True, timeout=12)
    return {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def prepare(root, inputs, port, invalid):
    root.mkdir(mode=0o700)  # Refuse to reuse any existing instance.
    (root / "bin").mkdir()
    for binary in ("safeyolo", "safeyolo-proxy"):
        (root / "bin" / binary).symlink_to((inputs / binary).resolve(strict=True))
    initialized = native(root, "init")
    assert initialized["returncode"] == 0, initialized
    (root / "config.toml").write_text(f"admin_port={port}\nflow_store_enabled=false\n")
    (root / "policy.toml").write_text('[hosts\n' if invalid else '[hosts]\n"*"={egress="deny"}\n')
    # Coord is outside this proxy-only probe. Make its automatic acquisition
    # fail locally, before any IP request or listener, in this owned instance.
    (root / "data/coord").mkdir()
    (root / "data/coord/nats").write_text("proxy-only fixture: no NATS runtime\n")


def hold_start(root):
    """Block real policy loading, with a bounded original-parent cleanup path."""
    with (root / ".policy.toml.lock").open("w") as lock, (root / "logs/proxy.log").open("ab") as log:
        fcntl.flock(lock, fcntl.LOCK_EX)
        child = subprocess.Popen(
            [str(root / "bin/safeyolo-proxy"), "--config", str(root / "config.toml")],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True,
        )
        identity = {"pid": child.pid, "token": birth(child.pid)}
        forced = False
        try:
            assert identity["token"], "child birth unavailable"
            save(root / "probe-process.json", identity)
            deadline = time.monotonic() + 60
            while not (root / "release").exists() and child.poll() is None:
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.02)
        finally:
            # The child cannot consume SIGTERM until policy loading completes.
            # This cleanup is fixture work, never a passing native stop result.
            if child.poll() is None:
                assert birth(child.pid) == identity["token"], "child birth changed; refusing cleanup"
                child.send_signal(signal.SIGTERM)
            fcntl.flock(lock, fcntl.LOCK_UN)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                assert birth(child.pid) == identity["token"], "child birth changed; refusing cleanup"
                child.kill()
                child.wait(timeout=5)
                forced = True
            save(root / "exit.json", {"exit_status": child.returncode, "forced": forced})


def launch(root, inputs, port, hold, invalid):
    prepare(root, inputs, port, invalid)
    if not hold:
        observed = native(root, "start")
        save(root / "native-start.json", observed)
        if observed["returncode"] == 0:
            identity = json.loads((root / "data/proxy-process.json").read_text())
            save(root / "probe-process.json", identity)
        return observed
    # This owner only holds the policy lock and reaps the fixture child. Fresh
    # control connections still run the unchanged native stop command.
    with (root / "logs/owner.log").open("ab") as log:
        subprocess.Popen([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "hold", str(root)],
                         stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
    wait_file(root / "probe-process.json")
    return json.loads((root / "probe-process.json").read_text())


def wait_file(path):
    deadline = time.monotonic() + 8
    while not path.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError(f"missing {path}; inspect retained logs")
        time.sleep(0.02)


def status(root):
    identity = json.loads((root / "probe-process.json").read_text())
    return {"identity": identity, "alive": birth(identity["pid"]) == identity["token"],
            "ready": (root / "data/ready.json").exists(),
            "native_record": (root / "data/proxy-process.json").exists()}


def native_stop(root, stale):
    record = root / "data/proxy-process.json"
    saved = record.read_bytes() if record.exists() else None
    try:
        if stale:
            save(record, json.loads(stale.read_text()))
        observed = native(root, "stop")
        save(root / ("native-stale-stop.json" if stale else "native-stop.json"), observed)
        return observed
    finally:
        if stale:
            if saved is None:
                record.unlink(missing_ok=True)
            else:
                record.write_bytes(saved)


def cleanup(root):
    if (root / "logs/owner.log").exists():
        (root / "release").touch()
        wait_file(root / "exit.json")
        observed = json.loads((root / "exit.json").read_text())
        assert observed["exit_status"] == 0 and not observed["forced"], observed
    elif (root / "probe-process.json").exists() and status(root)["alive"]:
        observed = native_stop(root, None)
        assert observed["returncode"] == 0, observed
    if (root / "probe-process.json").exists():
        assert not status(root)["alive"], "original process remains"
    assert not (root / "data/ready.json").exists(), "readiness remains"
    return {"clean": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["launch", "hold", "status", "native-stop", "clean"])
    parser.add_argument("root", type=Path)
    parser.add_argument("--inputs", type=Path)
    parser.add_argument("--port", type=int, default=46375)
    parser.add_argument("--hold", action="store_true")
    parser.add_argument("--invalid", action="store_true")
    parser.add_argument("--identity", type=Path, help="stale native process record")
    args = parser.parse_args()
    root = args.root.resolve()
    if args.operation == "launch":
        result = launch(root, args.inputs, args.port, args.hold, args.invalid)
    elif args.operation == "hold":
        hold_start(root)
        return
    elif args.operation == "native-stop":
        result = native_stop(root, args.identity)
    elif args.operation == "clean":
        result = cleanup(root)
    else:
        result = status(root)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
