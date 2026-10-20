"""Exercise the existing terminal prototype around one real SafeYolo guest.

Run on an approved disposable host with prepared native assets. This probe
starts and stops its own proxy, Coord instance and guest. It changes no policy.
"""

import argparse
import fcntl
import importlib
import json
import os
import pty
import re
import select
import socket
import struct
import subprocess
import sys
import termios
from pathlib import Path

import tomlkit
from run_poc2 import rpc, wait_for


class Viewer:
    def __init__(self, path):
        self.master, slave = pty.openpty()
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        self.display = bytearray()
        self.process = subprocess.Popen(
            [sys.executable, "-B", str(Path(__file__).with_name("attach.py")), str(path)],
            stdin=slave,
            stdout=slave,
            stderr=slave,
        )
        os.close(slave)

    def sees(self, marker):
        while select.select([self.master], [], [], 0)[0]:
            try:
                data = os.read(self.master, 65536)
            except OSError as error:
                if error.errno != 5:  # A closed Linux display PTY returns EIO.
                    raise
                break
            if not data:
                break
            self.display.extend(data)
        return marker.encode() in self.display

    def send(self, text):
        os.write(self.master, text.encode())

    def poll_exit(self):
        # Drain the display while waiting. A full test PTY can block the
        # viewer's final screen write before it reports the child's exit.
        self.sees("")
        return self.process.poll()

    def close(self):
        if self.process.poll() is None:
            self.process.kill()  # Deliberate abrupt viewer loss, without detach.
        self.process.wait(timeout=5)
        os.close(self.master)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--native-binaries", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--base", type=Path, required=True, help="new, short disk-backed directory")
    args = parser.parse_args()
    base = args.base.resolve()
    base.mkdir(mode=0o700)
    root, workspace, path = base / "i", base / "w", base / "session.sock"
    workspace.mkdir()
    sys.path.insert(0, str(args.repository.resolve() / "tests/blackbox"))
    installed = importlib.import_module("installed_sections")
    smoke = importlib.import_module("installed_host_smoke")
    cli = args.native_binaries.resolve() / "safeyolo"
    env = dict(
        os.environ,
        SAFEYOLO_CONFIG_DIR=str(root),
        SAFEYOLO_LOGS_DIR=str(root / "logs"),
        SAFEYOLO_COORD_DATA_DIR=str(root / "data/coord"),
        SAFEYOLO_SUBNET_BASE="75",
        SAFEYOLO_NATS_TEST_INSTANCE=os.urandom(16).hex(),
    )
    env.pop("TMUX", None)
    env.pop("TMUX_PANE", None)
    if sys.platform == "darwin":
        env.update(
            SAFEYOLO_NATS_TEST_PORTS="46370,46372",
            SAFEYOLO_VZ_TEST_RUNNER="/Users/sy-agent/bin/run-vz-test",
            SAFEYOLO_VZ_TEST_TIMEOUT_SECONDS="180",
        )
    os.environ.update(env)  # Maintained cleanup uses this same test-instance identity.

    def native(*words):
        result = subprocess.run(
            [str(cli), "--root", str(root), *words], env=env, capture_output=True, text=True, timeout=150
        )
        with (base / "operations.log").open("a") as log:
            log.write(json.dumps(list(words)) + f" => {result.returncode}\n" + result.stdout + result.stderr)
        result.check_returncode()
        return result.stdout

    def record():
        return json.loads((root / "agents/bbtest/current-launch.json").read_text())

    report = {"result": "UNVERIFIED", "platform": sys.platform, "base": str(base)}
    viewers = []
    keeper = None
    try:
        installed.prepare_native_instance(args.prepared.resolve(), root)
        installed.copy_prepared_nats(args.prepared.resolve(), root)
        (root / "bin").unlink()
        (root / "bin").mkdir()
        for source in (args.prepared / "bin").iterdir():
            if source.name != "tmux":
                replacement = args.native_binaries / source.name
                (root / "bin" / source.name).symlink_to(replacement if replacement.exists() else source)
        assert not (root / "bin/tmux").exists()
        if sys.platform == "darwin":
            (root / "share").unlink()
            (root / "share").mkdir()
            for source in (args.prepared / "share").iterdir():
                subprocess.run(["cp", "-c", str(source), str(root / "share" / source.name)], check=True)
        config = root / "config.toml"
        document = tomlkit.parse(config.read_text())
        document.update(admin_port=46375 if sys.platform == "darwin" else 19175, listeners=[])
        config.write_text(tomlkit.dumps(document))
        # The command stays alive with no viewer and returns a known exit code.
        (workspace / "agent.sh").write_text(
            'printf "GUEST-READY pid=%s birth=" "$$"; cut -d" " -f22 /proc/$$/stat\n'
            "while IFS= read -r word; do\n"
            '  printf "GUEST-REPLY %s pid=%s\\n" "$word" "$$"\n'
            '  if [ "$word" = exit-23 ]; then exit 23; fi\n'
            "done\nexit 24\n"
        )
        native(
            "agent",
            "create",
            "bbtest",
            "--workspace",
            str(workspace),
            "--command",
            "exec /bin/bash /workspace/agent.sh",
        )
        report["native_version"] = subprocess.check_output([str(cli), "--version"], text=True).strip()
        report["guest_selection"] = json.loads((root / "share/guest-selection.json").read_text())
        if sys.platform == "darwin":
            native("coord", "start", "--client-port", "46370", "--monitor-port", "46372")
        native("start")
        native("agent", "start", "bbtest", "--sandbox-only")
        report["runtime"] = json.loads(native("agent", "status", "bbtest"))
        proxy_before = json.loads((root / "data/proxy-process.json").read_text())
        with (base / "keeper.log").open("w") as log:
            keeper = subprocess.Popen(
                [
                    str(args.binary.resolve()),
                    str(path),
                    "24",
                    "80",
                    str(cli),
                    "--root",
                    str(root),
                    "agent",
                    "start",
                    "bbtest",
                    "--foreground",
                ],
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
                start_new_session=True,
            )
        wait_for(path.exists, bool, "keeper socket")
        guest_pattern = re.compile(r"GUEST-READY pid=(\d+) birth=(\d+)")
        original = wait_for(
            lambda: rpc(path, "state"),
            lambda s: guest_pattern.search(s["contents"]) is not None,
            "trusted guest entrypoint and complete process identity",
        )
        report["original"] = {k: original[k] for k in ("pid", "session", "contents", "exit")}
        guest = guest_pattern.search(original["contents"])
        assert guest is not None, original["contents"]
        guest_pid, guest_birth = guest.groups()
        report["guest_identity"] = {"pid": int(guest_pid), "birth": guest_birth}
        launch = record()
        report["launch_before"] = launch
        for count in (1, 2):
            viewer = Viewer(path)
            viewers.append(viewer)
            wait_for(lambda: rpc(path, "state"), lambda s, count=count: s["viewers"] == count, "viewer attach")
            wait_for(lambda viewer=viewer: viewer.sees("GUEST-READY"), bool, "original screen in actual viewer")
        viewers[0].send("first\n")
        for viewer in viewers:
            wait_for(lambda viewer=viewer: viewer.sees(f"GUEST-REPLY first pid={guest_pid}"), bool, "shared output")
        viewers.pop(0).close()
        wait_for(lambda: rpc(path, "state"), lambda s: s["viewers"] == 1, "abrupt initiating-viewer disconnect")
        viewers[0].send("after-disconnect\n")
        wait_for(
            lambda: viewers[0].sees(f"GUEST-REPLY after-disconnect pid={guest_pid}"), bool, "surviving child input"
        )
        viewers.append(Viewer(path))
        reconnected = wait_for(lambda: rpc(path, "state"), lambda s: s["viewers"] == 2, "viewer reconnect")
        assert (reconnected["pid"], reconnected["session"]) == (original["pid"], original["session"])
        report["reconnected"] = {k: reconnected[k] for k in ("pid", "session", "viewers", "rows", "cols")}
        viewers.pop(0).close()  # Also lose the other original viewer while the child is live.
        wait_for(lambda: rpc(path, "state"), lambda s: s["viewers"] == 1, "other viewer disconnect")
        viewers[0].send("after-other-disconnect\n")
        wait_for(
            lambda: viewers[0].sees(f"GUEST-REPLY after-other-disconnect pid={guest_pid}"),
            bool,
            "child input after either viewer disconnects",
        )
        viewers.append(Viewer(path))
        wait_for(lambda: rpc(path, "state"), lambda s: s["viewers"] == 2, "second viewer reconnect")
        native("stop")  # Deliberately restart only the proxy, leaving the guest/keeper live.
        wait_for(lambda: smoke._pid_alive(proxy_before["pid"]), lambda alive: not alive, "old proxy exited")
        stopped = rpc(path, "state")
        assert stopped["exit"] is None and keeper.poll() is None
        native("start")
        proxy_after = json.loads((root / "data/proxy-process.json").read_text())
        assert proxy_before != proxy_after
        report["proxy_before"], report["proxy_after"] = proxy_before, proxy_after
        viewers[0].send("after-proxy-restart\n")
        for viewer in viewers:
            wait_for(
                lambda viewer=viewer: viewer.sees(f"GUEST-REPLY after-proxy-restart pid={guest_pid}"),
                bool,
                "proxy-independent original child",
            )
        observed = json.loads(native("agent", "status", "bbtest"))
        assert observed["run_id"] == report["runtime"]["run_id"]
        assert observed["launch_id"] == launch["launch_id"]
        report["runtime_after_restart"] = observed
        viewers[0].send("exit-23\n")
        final = wait_for(lambda: rpc(path, "state"), lambda s: s["exit"] is not None, "original exit status")
        assert final["exit"] == 23
        for viewer in viewers:
            assert wait_for(viewer.poll_exit, lambda code: code is not None, "viewer exit") == 23
            viewer.close()
        viewers.clear()
        late = Viewer(path)
        viewers.append(late)
        assert wait_for(late.poll_exit, lambda code: code is not None, "later attach exit") == 23
        final = rpc(path, "state")
        assert (final["pid"], final["session"]) == (original["pid"], original["session"])
        assert record()["launch_id"] == launch["launch_id"]
        assert record()["exit_code"] == 23 and record()["state"] == "exited"
        duplicate = subprocess.run(
            [str(cli), "--root", str(root), "agent", "entrypoint", "bbtest", launch["launch_id"]],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert duplicate.returncode != 0 and "No matching unclaimed" in duplicate.stderr
        assert record()["exit_code"] == 23 and record()["state"] == "exited"
        report["duplicate_entrypoint"] = {"exit": duplicate.returncode, "stderr": duplicate.stderr}
        report.update(result="PASS", final={k: final[k] for k in ("pid", "session", "exit")}, launch_after=record())
    finally:
        for viewer in viewers:
            viewer.close()
        if keeper is not None and keeper.poll() is None:
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(2)
                client.connect(str(path))
                client.sendall(b'{"op":"quit"}\n')
            keeper.wait(timeout=10)
        report["keeper_exit"] = keeper.returncode if keeper else None
        report["socket_absent"] = not path.exists()
        report["cleanup_failures"] = installed.cleanup_instance(cli, root)
        (base / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        assert not report["cleanup_failures"], report["cleanup_failures"]
        assert report["socket_absent"]
    print(json.dumps(report))


if __name__ == "__main__":
    main()
