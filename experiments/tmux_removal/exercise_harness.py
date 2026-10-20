"""Exercise an authenticated, detached real harness through the actual viewer.

Start the prototype in a private directory first. This probe does not change
credentials, start another harness, or use the harness to execute tools.
"""

import argparse
import fcntl
import json
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

from run_poc2 import rpc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--name", choices=["codex", "claude"], required=True)
    parser.add_argument("--ready", required=True, help="text from the authenticated harness's input prompt")
    args = parser.parse_args()
    original = rpc(args.socket, "state")
    assert original["viewers"] == 0 and original["exit"] is None
    # The display is an ordinary test PTY. The prototype's child PTY is still
    # created exclusively by pty-process.
    display = bytearray()
    master = None
    viewer = None

    def drain():
        if master is not None:
            while select.select([master], [], [], 0)[0]:
                data = os.read(master, 65536)
                if not data:
                    break
                display.extend(data)

    def wait(predicate, description):
        deadline = time.monotonic() + 45
        while True:
            drain()
            state = rpc(args.socket, "state")
            if predicate(state):
                return state
            assert time.monotonic() < deadline, (description, state["contents"], state["unhandled"])
            time.sleep(0.05)

    def open_viewer(rows, cols):
        nonlocal master, viewer
        master, slave = pty.openpty()
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        viewer = subprocess.Popen([sys.executable, "-B", str(Path(__file__).with_name("attach.py")), str(args.socket)],
                                  stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        wait(lambda state: state["viewers"] == 1, "viewer attach")

    def close_viewer():
        nonlocal master, viewer
        os.write(master, b"\x1d")
        viewer.wait(timeout=5)
        assert viewer.returncode == 0
        os.close(master)
        master, viewer = None, None
        return wait(lambda state: state["viewers"] == 0, "viewer detach")

    wait(lambda state: args.ready in state["contents"], "authenticated prompt after detached startup")
    try:
        open_viewer(24, 80)
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 28, 100, 0, 0))
        os.kill(viewer.pid, signal.SIGWINCH)
        wait(lambda state: (state["rows"], state["cols"]) == (28, 100), "resize through viewer")
        name = "POC-" + args.name.upper()
        prompt = f"Reply exactly with two words {name} and OK. Do not use tools."
        # Left, insertion, right, backspace must produce this exact prompt.
        os.write(master, prompt[:-1].encode() + b"X\x1b[D.\x1b[C\x7f")
        wait(lambda state: prompt in state["contents"], "arrow/input editing")
        os.write(master, b"\r")
        response = name + " OK"
        wait(lambda state: response in state["contents"], "real model response")
        detached = close_viewer()
        assert detached["pid"] == original["pid"] and detached["session"] == original["session"]
        open_viewer(28, 100)
        wait(lambda state: response in state["contents"], "reattach to original harness")
        os.write(master, "\x1b[200~paste-✓\x1b[201~".encode())
        wait(lambda state: "paste-✓" in state["contents"], "bracketed paste")
        os.write(master, b"\x03")
        final = wait(lambda state: "paste-✓" not in state["contents"], "Ctrl-C clears the draft")
        drain()
        replay = subprocess.run([str(args.binary.resolve()), "--replay"],
                                input=json.dumps({"rows":28,"cols":100,"screen":display.decode("utf-8")}),
                                capture_output=True, text=True, check=True)
        assert response in json.loads(replay.stdout)["contents"], "actual viewer display did not retain the response"
        assert final["pid"] == original["pid"] and final["session"] == original["session"]
        print(json.dumps({"harness":args.name,"result":"PASS","pid":final["pid"],"session":final["session"],
                          "unhandled":sorted(set(final["unhandled"]))}))
    finally:
        if viewer is not None:
            close_viewer()


if __name__ == "__main__":
    main()
