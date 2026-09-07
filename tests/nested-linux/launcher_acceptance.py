"""Real launcher acceptance against an already configured disposable SafeYolo.

Run with the candidate's Python and test-owned SAFEYOLO_CONFIG_DIR. This adds
one uniquely named agent, uses the installed platform/runtime, and leaves its
stopped state plus evidence for inspection. It never selects an existing agent.
Also runnable on macOS/VZ in an operator-approved existing installation. It
changes only the newly created agent; no proxy restart or install is needed.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import pty
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from safeyolo.agent_launchers import observe_launch, read_launch
from safeyolo.agents_store import load_agent
from safeyolo.platform import get_platform
from safeyolo.vm import get_agent_home_dir


def main() -> None:
    from safeyolo.proxy import is_proxy_running

    if not shutil.which("tmux"):
        raise SystemExit("Install tmux on this SafeYolo host before running the launcher acceptance.")
    if not is_proxy_running():
        raise SystemExit("Start this host's SafeYolo proxy before running the launcher acceptance.")
    name = "launcher-probe-" + uuid.uuid4().hex[:8]
    evidence = Path(tempfile.mkdtemp(prefix="safeyolo-launcher-acceptance-"))
    workspace = evidence / "workspace"
    workspace.mkdir()
    transcript = evidence / "commands.jsonl"
    command = [sys.executable, "-m", "safeyolo.cli"]

    def cli(*args: str) -> subprocess.CompletedProcess:
        result = subprocess.run([*command, *args], capture_output=True, text=True, check=False)
        with transcript.open("a") as output:
            output.write(json.dumps({"argv": args, "code": result.returncode,
                                     "stdout": result.stdout, "stderr": result.stderr}) + "\n")
        if result.returncode:
            raise AssertionError(f"{args}: {result.stdout}\n{result.stderr}")
        return result

    def until(predicate, description: str):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if value := predicate():
                return value
            time.sleep(0.05)
        raise AssertionError(f"Timed out: {description}; evidence={evidence}")

    def active():
        record = read_launch(name)
        return record if record and record["state"] == "running" else None

    def send(pane: str, value: str) -> None:
        subprocess.run(["tmux", "send-keys", "-t", pane, "-l", value], check=True)
        subprocess.run(["tmux", "send-keys", "-t", pane, "Enter"], check=True)

    print(f"agent={name} evidence={evidence}", flush=True)
    cli("agent", "add", name, str(workspace), "--no-run")
    cli("agent", "config", name, "--memory", "1024")
    entrypoint = get_agent_home_dir(name) / ".safeyolo-command"
    entrypoint.write_text("""#!/bin/bash
set -eu
test -t 0 && test -t 1 && test -t 2 || exit 91
printf '%s\\n' "$$" >> /workspace/starts
printf 'TTY ready\\n'
while IFS= read -r line; do
    printf '%s\\n' "$line" >> /workspace/input
    printf 'received:%s\\n' "$line"
    if [ "$line" = quit ]; then exit 7; fi
    if [ "$line" = quit0 ]; then exit 0; fi
done
""")
    entrypoint.chmod(0o755)
    hooks = evidence / "hooks"
    script = evidence / "launcher.sh"
    script.write_text("""#!/bin/bash
set -eu
case "$1" in
    pre_launch|post_launch|on_exit)
        printf '%s:%s\\n' "$1" "$SAFEYOLO_AGENT_EXIT_CODE" >> "$(dirname "$0")/hooks"
        ;;
    *) exec "$SAFEYOLO_LAUNCHER_PRESETS/tmux-pane.sh" "$1" ;;
esac
""")
    script.chmod(0o755)
    try:
        cli("agent", "run", name, "--sandbox-only")
        assert get_platform().is_sandbox_running(name)
        assert not (workspace / "starts").exists(), "sandbox-only launched the entrypoint"
        absent = subprocess.run([*command, "agent", "attach", name], capture_output=True, text=True)
        assert absent.returncode != 0 and "no live session" in absent.stdout.lower()

        cli("agent", "config", name, "--launcher", str(script))
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
            list(workers.map(lambda _: cli("agent", "run", name, "--detach"), range(2)))
        original = until(active, "agent process to start")
        until(lambda: (workspace / "starts").exists(), "terminal probe startup")
        assert len((workspace / "starts").read_text().splitlines()) == 1
        until(lambda: hooks.exists() and len(hooks.read_text().splitlines()) == 2, "launch hooks")

        # The session is selected by the recorded launch, even after settings
        # change. No second command or hook runs when a viewer attaches.
        cli("agent", "config", name, "--launcher", "tmux-window")
        assert read_launch(name)["launcher"] == original["launcher"]
        master, slave = pty.openpty()
        viewer_env = {**os.environ, "TERM": "xterm-256color"}
        viewer_env.pop("TMUX", None)
        viewer_env.pop("TMUX_PANE", None)
        viewer = subprocess.Popen([*command, "agent", "attach", name], stdin=slave,
                                  stdout=slave, stderr=slave, env=viewer_env, start_new_session=True)
        os.close(slave)
        try:
            screen = bytearray()

            def viewer_ready():
                if select.select([master], [], [], 0.05)[0]:
                    screen.extend(os.read(master, 65536))
                return b"TTY ready" in screen

            until(viewer_ready, "attached viewer screen")
            (evidence / "viewer.raw").write_bytes(screen)
            os.write(master, b"from-viewer\n")
            until(lambda: (workspace / "input").exists() and "from-viewer" in (workspace / "input").read_text(), "viewer input")
        finally:
            os.close(master)
            if viewer.poll() is None:
                os.killpg(viewer.pid, signal.SIGHUP)
            viewer.wait(timeout=10)
        assert active()["launch_id"] == original["launch_id"]
        assert observe_launch(name, sandbox_ready=True)["agent_state"] == "running"
        assert len(hooks.read_text().splitlines()) == 2
        send(original["pane_id"], "quit")

        def exited():
            current = read_launch(name)
            return current if current and current["state"] == "exited" else None

        ended = until(exited, "command exit")
        assert ended["exit_code"] == 7
        assert hooks.read_text().splitlines() == ["pre_launch:", "post_launch:", "on_exit:7"]
        assert get_platform().is_sandbox_running(name), "background command exit stopped its sandbox"

        cli("agent", "run", name, "--detach")
        restarted = until(active, "second launch in ready sandbox")
        assert restarted["launch_id"] != original["launch_id"]
        assert restarted["launcher"]["kind"] == "tmux-window"
        before = subprocess.run(["tmux", "list-panes", "-a", "-F", "#{pane_id}"], capture_output=True, text=True, check=True).stdout.splitlines()
        cli("agent", "stop", name)
        assert not get_platform().is_sandbox_running(name)
        until(lambda: read_launch(name)["state"] in {"exited", "failed"}, "exit wrapper after explicit stop")
        after = subprocess.run(["tmux", "list-panes", "-a", "-F", "#{pane_id}"], capture_output=True, text=True).stdout.splitlines()
        assert set(before) - {restarted["pane_id"]} <= set(after), "stop removed an unrelated pane"
        print("PASS real terminal I/O, concurrent reuse, pinned attach, viewer disconnect, hooks, ready-sandbox relaunch, narrow stop", flush=True)

        interactive_entry = entrypoint.with_name(".safeyolo-interactive-command")
        interactive_entry.write_bytes(entrypoint.read_bytes())
        interactive_entry.chmod(0o755)
        retained = entrypoint.with_name("launcher-acceptance-checkpoint")
        retained.write_text("retain this agent-local configuration across debug mode\n")
        entrypoint.write_text("""#!/bin/bash
set -eu
printf '%s\\n' "$$" >> /workspace/managed-starts
printf '%s\\n' "$$" > /workspace/managed.pid
while true; do sleep 1; done
""")
        cli("agent", "config", name, "--launcher", "supervisor")
        cli("agent", "run", name, "--detach")

        def managed_running():
            return observe_launch(name, sandbox_ready=True)["agent_state"] == "running"

        until(managed_running, "guest PID-1-owned supervisor")
        until(lambda: (workspace / "managed-starts").exists(), "managed command start")
        cli("agent", "shell", name, "-c", 'kill -KILL "$(cat /workspace/managed.pid)"')
        until(lambda: len((workspace / "managed-starts").read_text().splitlines()) >= 2, "supervisor restart after command crash")
        cli("agent", "stop", name)
        assert not get_platform().is_sandbox_running(name)

        cli("agent", "run", name, "--interactive", "--detach")
        debug = until(active, "interactive managed-agent override")
        assert debug["launcher"]["kind"] == "tmux-window"
        assert load_agent(name)["launcher"] == "supervisor"
        assert retained.read_text() == "retain this agent-local configuration across debug mode\n"
        assert debug["command"] == "/home/agent/.safeyolo-interactive-command"
        cli("agent", "stop", name)
        until(lambda: read_launch(name)["state"] in {"exited", "failed"}, "debug exit")
        previous_starts = len((workspace / "managed-starts").read_text().splitlines())
        cli("agent", "run", name, "--detach")
        until(managed_running, "managed mode restored")
        until(lambda: len((workspace / "managed-starts").read_text().splitlines()) > previous_starts, "restored managed command")
        assert read_launch(name)["launcher"]["kind"] == "supervisor"
        print("PASS real supervisor restart, intentional stop, interactive override, retained config, managed-mode restoration", flush=True)

        cli("agent", "stop", name)
        before = subprocess.run(["tmux", "list-panes", "-a", "-F", "#{pane_id}"], capture_output=True, text=True).stdout
        master, slave = pty.openpty()
        local_env = dict(viewer_env)
        local_env.pop("SSH_CONNECTION", None)
        foreground = subprocess.Popen([*command, "agent", "run", name, "--interactive"],
                                      stdin=slave, stdout=slave, stderr=slave, env=local_env, start_new_session=True)
        os.close(slave)
        screen = bytearray()
        try:
            def foreground_ready():
                if select.select([master], [], [], 0.05)[0]:
                    screen.extend(os.read(master, 65536))
                return b"TTY ready" in screen

            until(foreground_ready, "local foreground terminal")
            assert read_launch(name)["launcher"]["kind"] == "interactive"
            os.write(master, b"quit0\n")
            assert foreground.wait(timeout=30) == 0
        finally:
            os.close(master)
            if foreground.poll() is None:
                os.killpg(foreground.pid, signal.SIGHUP)
                foreground.wait(timeout=10)
        after = subprocess.run(["tmux", "list-panes", "-a", "-F", "#{pane_id}"], capture_output=True, text=True).stdout
        assert before == after, "foreground run created a tmux pane"
        assert not get_platform().is_sandbox_running(name)
        print("PASS local foreground PTY, no forced tmux, existing clean-exit sandbox behavior", flush=True)
    finally:
        cli("agent", "stop", name)


if __name__ == "__main__":
    main()
