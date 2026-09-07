"""Prove a real nested agent survives its launch client's and API process's exit.

Uses the production Admin handler with a dummy credential on a test-owned
loopback port. The existing nested proxy is not restarted. The only stopped
agent and tmux server are created by this script. Run with the candidate Python
and an already configured, running disposable SafeYolo instance.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from safeyolo.agent_launchers import observe_launch, read_launch
from safeyolo.agents_store import load_agent
from safeyolo.vm import get_agent_home_dir


def serve(root: Path) -> None:
    # Mirror the proxy's source-root path for the package-external pdp module.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from safeyolo.mitm_addons.admin_api import AdminRequestHandler, LoopbackHTTPServer

    class Handler(AdminRequestHandler):
        def do_POST(self):
            try:
                super().do_POST()
            finally:
                (root / "request-finished").touch()

    Handler.admin_token = "disposable-launcher-probe"
    server = LoopbackHTTPServer(("127.0.0.1", 0), Handler)
    (root / "api.json").write_text(json.dumps({"port": server.server_port, "pid": os.getpid()}))
    server.serve_forever()


def main() -> None:
    from safeyolo.proxy import is_proxy_running

    assert is_proxy_running(), "Start the disposable nested proxy first"
    root = Path(tempfile.mkdtemp(prefix="sy-launch-client-loss-"))
    workspace = root / "workspace"
    workspace.mkdir()
    name = "client-loss-" + uuid.uuid4().hex[:8]
    command = [sys.executable, "-m", "safeyolo.cli"]
    tmux = ["tmux", "-S", str(root / "tmux.sock")]
    api = None
    client = None
    added = False

    def cli(*args):
        result = subprocess.run([*command, *args], capture_output=True, text=True)
        with (root / "commands.jsonl").open("a") as log:
            log.write(json.dumps({"argv": args, "code": result.returncode,
                                  "stdout": result.stdout, "stderr": result.stderr}) + "\n")
        assert result.returncode == 0, result.stdout + result.stderr

    def until(predicate, description):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if api is not None and api.poll() is not None:
                raise AssertionError(f"Test API exited {api.returncode}; inspect {root / 'api.log'}")
            if value := predicate():
                return value
            time.sleep(0.05)
        raise AssertionError(f"Timed out: {description}; evidence={root}")

    def running():
        record = read_launch(name)
        return record if record and record["state"] == "running" else None

    print(f"agent={name} evidence={root}", flush=True)
    try:
        subprocess.run([*tmux, "new-session", "-d", "-s", "api-launch-context"], check=True)
        tmux_pid = subprocess.check_output([*tmux, "display-message", "-p", "#{pid}"], text=True).strip()
        environment = {**os.environ, "TMUX": f"{root / 'tmux.sock'},{tmux_pid},0"}
        environment.pop("TMUX_PANE", None)
        cli("agent", "add", name, str(workspace), "--no-run")
        added = True
        cli("agent", "config", name, "--memory", "1024")
        entrypoint = get_agent_home_dir(name) / ".safeyolo-command"
        entrypoint.write_text("""#!/bin/bash
set -eu
test -t 0 && test -t 1
echo "$BASHPID" >> /workspace/starts
while IFS= read -r line; do echo "$line" >> /workspace/received; done
""")
        entrypoint.chmod(0o755)
        launcher = root / "launcher.sh"
        launcher.write_text("""#!/bin/bash
set -eu
root=$(dirname "$0")
if [ "$1" = launch ]; then
    "$SAFEYOLO_LAUNCHER_PRESETS/tmux-window.sh" "$@"
    touch "$root/launch-created"
    while [ ! -e "$root/release-response" ]; do sleep 0.05; done
else
    exec "$SAFEYOLO_LAUNCHER_PRESETS/tmux-window.sh" "$@"
fi
""")
        launcher.chmod(0o755)
        cli("agent", "config", name, "--launcher", str(launcher))
        agent_id = load_agent(name)["agent_id"]
        with (root / "api.log").open("a") as log:
            api = subprocess.Popen([sys.executable, __file__, "--serve", str(root)],
                                   env=environment, stdout=log, stderr=log)
        until(lambda: (root / "api.json").exists(), "test API ready")
        port = json.loads((root / "api.json").read_text())["port"]
        client = socket.create_connection(("127.0.0.1", port), timeout=30)
        client.sendall((f"POST /admin/agents/{agent_id}/start HTTP/1.1\r\n"
                        "Host: 127.0.0.1\r\nAuthorization: Bearer disposable-launcher-probe\r\n"
                        "Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}").encode())
        until(lambda: (root / "launch-created").exists(), "launch created before response")
        original = until(running, "guest command running")
        until(lambda: (workspace / "starts").exists(), "real guest startup")
        client.shutdown(socket.SHUT_RDWR)
        client.close()
        client = None
        (root / "release-response").touch()
        until(lambda: (root / "request-finished").exists(), "disconnected request finished")
        assert api.poll() is None
        assert running()["launch_id"] == original["launch_id"]
        print("PASS launch client disconnected before receiving the response; same launch remains", flush=True)

        api.terminate()
        api.wait(timeout=10)
        api = None
        subprocess.run([*tmux, "send-keys", "-t", original["pane_id"], "-l", "after-api-exit"], check=True)
        subprocess.run([*tmux, "send-keys", "-t", original["pane_id"], "Enter"], check=True)
        until(lambda: (workspace / "received").exists()
              and (workspace / "received").read_text() == "after-api-exit\n",
              "complete guest input after API exit")
        assert len((workspace / "starts").read_text().splitlines()) == 1
        assert observe_launch(name, sandbox_ready=True)["agent_state"] == "running"
        assert read_launch(name)["launch_id"] == original["launch_id"]
        print("PASS API process exited; same real guest command accepts terminal input", flush=True)
    finally:
        (root / "release-response").touch()
        if client is not None:
            client.close()
        if api is not None:
            api.terminate()
            api.wait(timeout=10)
        if added:
            cli("agent", "stop", name)
        subprocess.run([*tmux, "kill-server"], check=False)
        print(f"Stopped disposable agent and private tmux server; retained {root}", flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--serve":
        serve(Path(sys.argv[2]))
    else:
        main()
