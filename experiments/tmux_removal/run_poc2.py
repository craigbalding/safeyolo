"""Drive the deterministic PTY/screen boundary before any real harness run."""

import argparse
import json
import socket
import subprocess
import sys
import time
from pathlib import Path


def rpc(path, operation, **fields):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(5)
        client.connect(str(path))
        client.sendall(json.dumps({"op": operation, **fields}).encode() + b"\n")
        return json.loads(client.makefile("rb").readline())


def wait_for(observe, predicate, description):
    deadline = time.monotonic() + 10
    while True:
        value = observe()
        if predicate(value):
            return value
        assert time.monotonic() < deadline, (description, value)
        time.sleep(0.02)


def attach(path):
    client = socket.socket(socket.AF_UNIX)
    client.settimeout(5)
    client.connect(str(path))
    client.sendall(b'{"op":"attach"}\n')
    stream = client.makefile("rb")
    frame = json.loads(stream.readline())
    return client, stream, frame


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True, help="new disk-backed fixture directory")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    root = args.root.resolve()
    root.mkdir(mode=0o700)
    path = root / "terminal.sock"
    fixture = Path(__file__).with_name("fixture.py").resolve()
    with (root / "keeper.log").open("wb") as log:
        process = subprocess.Popen([str(binary), str(path), "24", "80", sys.executable, "-I", "-B", str(fixture), str(root)],
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
    try:
        wait_for(path.exists, bool, "keeper socket")
        wait_for(lambda: (root / "initial").exists(), bool, "initial output")
        client, stream, initial = attach(path)
        assert "INITIAL-ATTACHED" in initial["contents"]
        stream.close()
        client.close()
        wait_for(lambda: rpc(path, "state"), lambda state: state["viewers"] == 0, "viewer detached")
        (root / "produce-detached").touch()
        wait_for(lambda: (root / "idle-alt").exists(), bool, "detached fixture query and alternate screen")
        idle = wait_for(lambda: rpc(path, "state"), lambda state: "ALT-DETACHED-IDLE" in state["contents"], "alternate screen parsed")
        assert idle["alternate"] and idle["viewers"] == 0 and idle["queries_answered"] == 1
        assert json.loads((root / "query.json").read_text())["reply"] == b"\x1b[6;9R".hex()
        client, stream, frame = attach(path)
        replay = subprocess.run([str(binary), "--replay"], input=json.dumps(frame), capture_output=True, text=True, check=True)
        assert json.loads(replay.stdout)["contents"] == "ALT-DETACHED-IDLE"
        assert frame["bytes"] == idle["bytes"], "reattach caused or required child output"
        rpc(path, "resize", rows=18, cols=64)
        wait_for(lambda: (root / "resized.json").exists(), bool, "child observed resize")
        assert json.loads((root / "resized.json").read_text()) == [64, 18]
        resized = rpc(path, "state")
        assert (resized["rows"], resized["cols"], resized["bytes"]) == (18, 64, idle["bytes"])
        stream.close()
        client.close()
        wait_for(lambda: rpc(path, "state"), lambda state: state["viewers"] == 0, "viewer detached again")
        (root / "leave-alt").touch()
        wait_for(lambda: (root / "idle-normal").exists(), bool, "normal screen idle")
        idle = wait_for(lambda: rpc(path, "state"), lambda state: "AFTER-ALT-IDLE" in state["contents"], "normal screen parsed")
        client, stream, frame = attach(path)
        assert not frame["alternate"] and frame["bytes"] == idle["bytes"]
        replay = subprocess.run([str(binary), "--replay"], input=json.dumps(frame), capture_output=True, text=True, check=True)
        assert json.loads(replay.stdout)["contents"] == frame["contents"]
        history = rpc(path, "history")
        assert len(history["history"]) <= history["history_bound"] == 200
        assert any("DETACHED-NORMAL-100" in row for row in history["history"]), history
        assert not any("DETACHED-NORMAL-000" in row for row in history["history"]), history
        input_text = "\x1b[A\x1b[200~paste-✓\x1b[201~\x03"
        rpc(path, "input", text=input_text)
        final = wait_for(lambda: rpc(path, "state"), lambda state: state["exit"] is not None, "original child exit")
        assert final["exit"] == 7 and final["pid"] == initial["pid"] and final["session"] == initial["session"]
        assert json.loads((root / "input.json").read_text())["input"] == input_text.encode().hex()
        stream.close()
        client.close()
        print(json.dumps({"fixture": "PASS", "pid": final["pid"], "session": final["session"],
                          "history_rows": len(history["history"]), "queries_answered": final["queries_answered"],
                          "exit_status": final["exit"], "unhandled": final["unhandled"]}))
    finally:
        if process.poll() is None:
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(2)
                client.connect(str(path))
                client.sendall(b'{"op":"quit"}\n')
            process.wait(timeout=5)
        assert process.returncode == 0, (root / "keeper.log").read_text()
        assert not path.exists(), "keeper socket remains"


if __name__ == "__main__":
    main()
